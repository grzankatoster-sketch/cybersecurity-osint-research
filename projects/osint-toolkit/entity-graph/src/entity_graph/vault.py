"""Skarbiec dowodów: surowe odpowiedzi źródeł zapisane w katalogu badania ze skrótem SHA-256.

Każda odpowiedź fetchera (także 404, 429, 5xx i błąd sieci) trafia do pliku <ref>.bin oraz do index.jsonl
(ref, URL, status, błąd, SHA-256, rozmiar, czas, transformacja, węzeł). Nagłówki żądania NIE są zapisywane
(mogą zawierać klucze API). Silnik dopisuje skróty do dziennika audytu (łańcuch skrótów), więc verify_vault
wykrywa podmianę pliku nawet wtedy, gdy ktoś przepisał też indeks."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable

from .guardrails import verify_audit
from .http import Fetcher, HttpResponse
from .model import utc_now

INDEX = "index.jsonl"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_index(path: Path) -> list[dict]:
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").split("\n") if ln.strip()]


class EvidenceVault:
    def __init__(self, root: str | Path, now: Callable[[], str] = utc_now):
        self.root = Path(root)
        self.now = now
        self.root.mkdir(parents=True, exist_ok=True)
        self.index_path = self.root / INDEX
        if self.index_path.exists():
            self.entries: list[dict] = _read_index(self.index_path)
        else:
            self.index_path.write_bytes(b"")
            self.entries = []
        self._current: list[dict] = []
        self._transform = ""
        self._node = ""

    def begin(self, transform: str, node_id: str) -> None:
        self._transform, self._node = transform, node_id
        self._current = []

    def record(self, url: str, resp: HttpResponse) -> dict:
        data = (resp.text or "").encode("utf-8")
        ref = f"ev-{len(self.entries) + 1:04d}"
        name = f"{ref}.bin"
        (self.root / name).write_bytes(data)
        entry = {"ref": ref, "url": url, "status": resp.status if isinstance(resp.status, int) else None,
                 "error": resp.error, "sha256": _sha256(data), "size": len(data), "fetched_at": self.now(),
                 "transform": self._transform, "node": self._node, "file": name}
        with open(self.index_path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self.entries.append(entry)
        self._current.append(entry)
        return entry

    def take(self) -> list[dict]:
        out, self._current = self._current, []
        return out


class RecordingFetcher:
    """Fetcher, który każdą odpowiedź zapisuje w skarbcu i zwraca ją bez zmian."""

    def __init__(self, inner: Fetcher, vault: EvidenceVault):
        self.inner = inner
        self.vault = vault

    def get(self, url: str, headers: dict[str, str] | None = None) -> HttpResponse:
        resp = self.inner.get(url, headers)
        self.vault.record(url, resp)
        return resp


def verify_vault(case_dir: str | Path) -> tuple[bool, str]:
    """Sprawdza dziennik audytu, pliki skarbca i zgodność skrótów z łańcuchem audytu. -> (ok, opis)."""
    folder = Path(case_dir)
    audit_path = folder / "audit.jsonl"
    ok, msg = verify_audit(audit_path)
    if not ok:
        return False, f"dziennik audytu: {msg}"
    root = folder / "evidence"
    try:
        entries = _read_index(root / INDEX)
    except OSError as exc:
        return False, f"nie można odczytać indeksu skarbca: {exc}"
    except json.JSONDecodeError:
        return False, "indeks skarbca: uszkodzony JSON"
    audited: dict[str, dict] = {}
    for line in audit_path.read_text(encoding="utf-8").split("\n"):
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("event") == "transform":
            for item in event.get("evidence") or []:
                if isinstance(item, dict) and item.get("ref"):
                    audited[str(item["ref"])] = item
    seen: set[str] = set()
    for e in entries:
        ref = str(e.get("ref", ""))
        seen.add(ref)
        path = root / str(e.get("file", ""))
        if not e.get("file") or not path.is_file() or path.parent.resolve() != root.resolve():
            return False, f"{ref}: brak pliku dowodu"
        if _sha256(path.read_bytes()) != e.get("sha256"):
            return False, f"{ref}: skrót SHA-256 pliku nie zgadza się z indeksem (plik zmieniony)"
        logged = audited.get(ref)
        if logged is None:
            return False, f"{ref}: brak wpisu w dzienniku audytu"
        if logged.get("sha256") != e.get("sha256") or logged.get("url") != e.get("url"):
            return False, f"{ref}: skrót lub URL w indeksie nie zgadza się z dziennikiem audytu (indeks zmieniony)"
    missing = sorted(set(audited) - seen)
    if missing:
        return False, f"{missing[0]}: dowód z dziennika audytu nie występuje w indeksie"
    return True, f"{len(entries)} dowodów, skróty zgodne z plikami i dziennikiem audytu; {msg}"
