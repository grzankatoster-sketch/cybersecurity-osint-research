"""Retencja raportów: raport (HTML, JSON, CSV i pliki pośrednie jednego skanu) leży w osobnym katalogu skanu
`<katalog wyników>/<id skanu>/` razem z `manifest.json` (id, created_at, expires_at, pliki i ich SHA-256). Po terminie
(domyślnie 12 h) `purge_expired` usuwa cały katalog skanu, a w rejestrze `usuniecia.jsonl` (tylko dopisywanie) zostaje
ślad bez nazwy użytkownika i bez treści: id skanu, czasy, liczba plików, skróty.

Bezpieczeństwo usuwania: ruszamy wyłącznie bezpośrednie podkatalogi katalogu wyników o nazwie będącej id skanu, z
manifestem o tym samym id i terminem, który minął. Dowiązania, junctiony, podkatalogi i obce pliki nie są usuwane
(dowiązanie w środku skanu znika jako dowiązanie, cel zostaje). Katalog jest najpierw atomowo przemianowywany na
`.usuwanie-<id>-<losowo>`, więc dwa równoległe purge nie usuwają tego samego dwa razy, a przerwane usuwanie
dokończy kolejne wywołanie."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .fsutil import atomic_write_text

DEFAULT_TTL_HOURS = 12.0
MAX_TTL_HOURS = 24 * 366           # górny bezpiecznik; „bez wygasania” to wyłącznie jawne 0
MANIFEST = "manifest.json"
REGISTRY = "usuniecia.jsonl"
SCAN_ID_RE = re.compile(r"\d{8}T\d{6}Z-[0-9a-f]{8}")
PURGING_RE = re.compile(r"\.usuwanie-(\d{8}T\d{6}Z-[0-9a-f]{8})-[0-9a-f]{8}")
MAX_MANIFEST_BYTES = 1_000_000
_NAME_RE = re.compile(r"\w[\w.\- ]{0,119}")
_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
_RESERVED_NAMES = {MANIFEST, REGISTRY}


@dataclass
class Scan:
    scan_id: str
    path: Path
    created_at: datetime
    expires_at: datetime | None
    ttl_hours: float


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(value) -> datetime:
    if not isinstance(value, str):
        raise ValueError("czas: oczekiwano tekstu")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError("czas bez strefy")
    return dt.astimezone(timezone.utc)


def _now(now: datetime | None) -> datetime:
    return (now or datetime.now(timezone.utc)).astimezone(timezone.utc)


def parse_ttl_hours(value: float) -> float:
    """Ważność w godzinach: 0 = bez wygasania (tylko jawnie), inaczej liczba skończona z przedziału (0, MAX]."""
    try:
        hours = float(value)
    except (TypeError, ValueError):
        raise ValueError("--ttl-hours: oczekiwano liczby godzin") from None
    if not math.isfinite(hours) or hours < 0 or hours > MAX_TTL_HOURS:
        raise ValueError(f"--ttl-hours: liczba godzin od 0 do {MAX_TTL_HOURS} (0 = bez wygasania)")
    return hours


def safe_output_name(name: str) -> str:
    """Nazwa pliku raportu: sama nazwa (bez katalogów, dysków, '..'), trafia do katalogu skanu."""
    if (not isinstance(name, str) or not _NAME_RE.fullmatch(name) or name.endswith((".", " "))
            or name.lower().endswith(".tmp") or name.lower() in _RESERVED_NAMES
            or name.split(".")[0].strip().upper() in _RESERVED):
        raise ValueError("podaj samą nazwę pliku (bez katalogu, np. raport.html): trafi do katalogu skanu")
    return name


def expiry_note(expires_at: datetime | None) -> str:
    """Zdanie do raportu HTML o terminie ważności (czas lokalny)."""
    if expires_at is None:
        return "Raport bez terminu ważności (ustawiono --ttl-hours 0): usuń go samodzielnie, gdy nie jest potrzebny."
    local = expires_at.astimezone()
    return (f"Raport ważny do {local:%Y-%m-%d %H:%M}. Po tym terminie skan (HTML, CSV, JSON) jest usuwany "
            "automatycznie - pobierz, co potrzebne.")


def _is_junction(path: str) -> bool:
    return bool(getattr(os.path, "isjunction", lambda p: False)(path))


def _write_manifest(scan: Scan, files: list[dict]) -> None:
    doc = {"version": 1, "scan_id": scan.scan_id, "created_at": _iso(scan.created_at),
           "expires_at": _iso(scan.expires_at) if scan.expires_at else None, "ttl_hours": scan.ttl_hours,
           "files": files}
    atomic_write_text(scan.path / MANIFEST, json.dumps(doc, ensure_ascii=False, indent=1))


def start_scan(results_dir: str | Path, ttl_hours: float, now: datetime | None = None) -> Scan:
    """Tworzy katalog skanu i od razu zapisuje wstępny manifest (termin ważności obowiązuje także po awarii skanu)."""
    ttl = parse_ttl_hours(ttl_hours)
    created = _now(now).replace(microsecond=0)
    root = Path(results_dir)
    root.mkdir(parents=True, exist_ok=True)
    for _ in range(10):
        scan_id = f"{created:%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}"
        try:
            (root / scan_id).mkdir()
            break
        except FileExistsError:
            continue
    else:
        raise OSError("nie udało się utworzyć katalogu skanu")
    scan = Scan(scan_id, root / scan_id, created, created + timedelta(hours=ttl) if ttl else None, ttl)
    _write_manifest(scan, [])
    return scan


def _sha256(path: Path) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def seal_scan(scan: Scan) -> None:
    """Końcowy manifest: lista plików raportu z rozmiarem i SHA-256 (bez manifestu i plików tymczasowych)."""
    files = []
    for entry in sorted(os.scandir(scan.path), key=lambda e: e.name):
        if entry.name == MANIFEST or entry.name.endswith(".tmp") or not entry.is_file(follow_symlinks=False):
            continue
        digest, size = _sha256(Path(entry.path))
        files.append({"name": entry.name, "bytes": size, "sha256": digest})
    _write_manifest(scan, files)


# --- purge ---

def _read_manifest(directory: str, expected_id: str) -> dict:
    path = os.path.join(directory, MANIFEST)
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_MANIFEST_BYTES:
        raise ValueError("manifest: nie jest zwykłym plikiem albo jest za duży")
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict) or doc.get("scan_id") != expected_id:
        raise ValueError("manifest: inne id skanu")
    doc["_created"] = _parse_iso(doc.get("created_at"))
    doc["_expires"] = None if doc.get("expires_at") is None else _parse_iso(doc["expires_at"])
    return doc


def _registry_append(root: Path, entry: dict) -> None:
    path = root / REGISTRY
    if os.path.islink(path) or _is_junction(str(path)):
        raise OSError("rejestr usunięć jest dowiązaniem - odmowa zapisu")
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n")
        f.flush()
        os.fsync(f.fileno())


def _flat_entries(directory: str) -> list[tuple[str, bool]]:
    """Wpisy katalogu skanu jako (nazwa, czy_dowiązanie). Podkatalog lub junction = ValueError (nic nie usuwamy)."""
    entries = []
    with os.scandir(directory) as it:
        for e in it:
            mode = e.stat(follow_symlinks=False).st_mode
            if stat.S_ISDIR(mode) or (hasattr(e, "is_junction") and e.is_junction()):
                raise ValueError("nieoczekiwany podkatalog w katalogu skanu")
            entries.append((e.name, stat.S_ISLNK(mode)))
    return entries


def _remove_scan_dir(directory: str) -> tuple[int, list[str]]:
    """Usuwa pliki katalogu skanu (manifest na końcu). Zwraca (liczba plików, posortowane skróty SHA-256)."""
    entries = sorted(_flat_entries(directory), key=lambda x: x[0] == MANIFEST)
    hashes = []
    for name, is_link in entries:
        path = os.path.join(directory, name)
        if not is_link and name != MANIFEST:
            hashes.append(_sha256(Path(path))[0])
        os.unlink(path)
    os.rmdir(directory)
    return len(entries), sorted(hashes)


def purge_expired(results_dir: str | Path, now: datetime | None = None, dry_run: bool = False) -> dict:
    """Usuwa wygasłe skany z katalogu wyników. Zwraca {"deleted", "would_delete", "files", "skipped", "errors"}.
    Brak katalogu wyników nie jest błędem. Pominięte (skipped) = coś, co wygląda na skan, ale nie spełnia warunków
    bezpieczeństwa; errors = nieudane usunięcie (np. plik otwarty w przeglądarce) - zostanie ponowione."""
    now = _now(now)
    out = {"deleted": 0, "would_delete": 0, "files": 0, "skipped": 0, "errors": []}
    root = Path(results_dir)
    if not root.is_dir():
        return out
    root_real = os.path.normcase(os.path.realpath(root))
    try:
        candidates = sorted(os.scandir(root), key=lambda e: e.name)
    except OSError as e:
        out["errors"].append(f"katalog wyników: {type(e).__name__}")
        return out
    for entry in candidates:
        m = SCAN_ID_RE.fullmatch(entry.name) or PURGING_RE.fullmatch(entry.name)
        if not m:
            continue
        scan_id = m.group(1) if PURGING_RE.fullmatch(entry.name) else entry.name
        try:
            if (entry.is_symlink() or _is_junction(entry.path) or not entry.is_dir(follow_symlinks=False)
                    or os.path.normcase(os.path.dirname(os.path.realpath(entry.path))) != root_real):
                out["skipped"] += 1
                continue
            manifest = _read_manifest(entry.path, scan_id)
            if manifest["_expires"] is not None and manifest["_expires"] <= now:
                _flat_entries(entry.path)
        except (OSError, ValueError):
            out["skipped"] += 1
            continue
        if manifest["_expires"] is None or manifest["_expires"] > now:
            continue
        if dry_run:
            out["would_delete"] += 1
            continue
        target = entry.path
        if not PURGING_RE.fullmatch(entry.name):
            target = str(root / f".usuwanie-{scan_id}-{secrets.token_hex(4)}")
            try:
                os.rename(entry.path, target)      # atomowo: tylko jeden proces wygra; otwarte pliki (Windows) blokują
            except OSError:
                out["errors"].append(f"{scan_id}: nie można przenieść do usunięcia (plik otwarty?)")
                continue
        try:
            count, hashes = _remove_scan_dir(target)
        except ValueError:
            out["skipped"] += 1
            continue
        except OSError as e:
            out["errors"].append(f"{scan_id}: {type(e).__name__} przy usuwaniu")
            continue
        try:
            _registry_append(root, {"scan_id": scan_id, "created_at": _iso(manifest["_created"]),
                                    "deleted_at": _iso(now), "files": count, "sha256": hashes, "reason": "expired"})
        except OSError as e:
            out["errors"].append(f"rejestr usunięć: {type(e).__name__}")
        out["deleted"] += 1
        out["files"] += count
    return out
