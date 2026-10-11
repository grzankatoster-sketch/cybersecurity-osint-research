"""Atomic exports, checksum-validated local snapshots and durable result journal."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sqlite3
import tempfile
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from ultimate_username.domain.codec import from_json, to_json
from ultimate_username.domain.json_types import parse_json
from ultimate_username.domain.models import SearchResult
from ultimate_username.registry import SiteRegistry


def atomic_write(path: Path, chunks: Iterable[str]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(
        prefix="." + path.name + ".", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
            for chunk in chunks:
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def json_chunks(results: Iterable[SearchResult]) -> Iterator[str]:
    yield "[\n"
    first = True
    for result in results:
        if not first:
            yield ",\n"
        yield to_json(result)
        first = False
    yield "\n]\n"


def csv_chunks(results: Iterable[SearchResult]) -> Iterator[str]:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(
        ["job_id", "site_id", "username", "verdict", "state", "profile_url", "error_codes"]
    )
    yield stream.getvalue()
    for result in results:
        stream.seek(0)
        stream.truncate()
        cells = [
            result.job_id,
            result.site_id,
            result.username.raw,
            result.detection.verdict.value,
            result.detection.state.value,
            result.profile_url,
            "|".join(e.code.value for e in result.detection.errors),
        ]
        # Spreadsheet-safe representation; canonical JSON keeps the exact value.
        writer.writerow(
            ["'" + v if v.startswith(("=", "+", "-", "@", "\t", "\r")) else v for v in cells]
        )
        yield stream.getvalue()


def export_results(path: Path, results: Iterable[SearchResult], format: str = "json") -> None:
    encoders: dict[str, Callable[[Iterable[SearchResult]], Iterable[str]]] = {
        "json": json_chunks,
        "ndjson": lambda items: (to_json(r) + "\n" for r in items),
        "csv": csv_chunks,
    }
    if format not in encoders:
        raise ValueError("Unsupported output format")
    atomic_write(path, encoders[format](results))


class SnapshotStore:
    def __init__(self, path: Path) -> None:
        self.path = path.resolve()

    def load(self) -> tuple[str, SiteRegistry]:
        envelope = parse_json(self.path.read_text(encoding="utf-8"))
        if not isinstance(envelope, dict) or set(envelope) != {"sha256", "registry_json"}:
            raise ValueError("Invalid snapshot envelope")
        text, digest = envelope["registry_json"], envelope["sha256"]
        if not isinstance(text, str) or not isinstance(digest, str):
            raise ValueError("Invalid snapshot types")
        if hashlib.sha256(text.encode()).hexdigest() != digest:
            raise ValueError("Snapshot checksum mismatch")
        registry = SiteRegistry.from_json(text)
        if any(e.issues for e in registry.entries):
            raise ValueError("Snapshot contains invalid definitions")
        return digest, registry

    def promote(self, registry_json: str, *, expected_digest: str | None = None) -> str:
        registry = SiteRegistry.from_json(registry_json)
        if any(e.issues for e in registry.entries):
            raise ValueError("Invalid registry; previous snapshot retained")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock = self.path.with_suffix(self.path.suffix + ".lock")
        # Concurrent writers fail explicitly; never remove a lock owned by another writer.
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        try:
            if expected_digest is not None:
                current, _ = self.load()
                if current != expected_digest:
                    raise ValueError("Snapshot compare-and-swap conflict")
            digest = hashlib.sha256(registry_json.encode()).hexdigest()
            envelope = json.dumps(
                {"sha256": digest, "registry_json": registry_json}, ensure_ascii=False
            )
            atomic_write(self.path, [envelope])
            return digest
        finally:
            os.close(descriptor)
            lock.unlink()


class ResultJournal:
    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.execute("PRAGMA journal_mode=WAL")
        # WAL + NORMAL: a commit reaches the OS (an interrupted process loses nothing) without an
        # fsync per result; only an OS crash or power loss can drop the last commits.
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS results "
            "(task_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, "
            "base TEXT NOT NULL, latest TEXT NOT NULL)"
        )

    def append(self, result: SearchResult) -> None:
        value = to_json(result)
        with self.connection:
            self.connection.execute(
                "INSERT INTO results VALUES (?, ?, ?, ?) "
                "ON CONFLICT(task_id) DO UPDATE SET latest=excluded.latest",
                (result.task_id, result.job_id, value, value),
            )

    def read(self, *, base: bool = False, job_id: str | None = None) -> Iterator[SearchResult]:
        column = "base" if base else "latest"
        query = f"SELECT {column} FROM results"
        parameters: tuple[str, ...] = ()
        if job_id is not None:
            query += " WHERE job_id=?"
            parameters = (job_id,)
        for row in self.connection.execute(query + " ORDER BY rowid", parameters):
            value: object = row[0]
            if not isinstance(value, str):
                raise ValueError("Corrupt result journal")
            yield from_json(SearchResult, value)

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> ResultJournal:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()
