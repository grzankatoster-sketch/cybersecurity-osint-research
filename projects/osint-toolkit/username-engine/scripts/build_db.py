"""Pobiera bazy WhatsMyName i Maigret, konwertuje do wspólnego schematu i zapisuje data/sites.json.

python scripts/build_db.py [--wmn plik.json] [--maigret plik.json]   (pliki lokalne zamiast pobierania)

Integralność: źródła są przypięte do konkretnego commita i skrótu SHA-256 pliku (PINS). Plik,
którego skrót się nie zgadza (pobrany albo lokalny), jest odrzucany przed parsowaniem i nic nie
jest zapisywane. Świadoma aktualizacja: --wmn-ref <commit> --wmn-sha256 <skrót> (analogicznie
--maigret-*); sam --*-ref bez skrótu jest odrzucany.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from username_engine.sources import apply_tag_overrides, from_custom, from_maigret, from_wmn, merge, save_db  # noqa: E402

CUSTOM = ROOT / "src" / "username_engine" / "resources" / "custom_sites.json"
TAG_OVERRIDES = CUSTOM.with_name("tag_overrides.json")   # dodatkowe tagi (np. fitness) dla serwisów z upstreamu

MAX_BYTES = 50 * 1024 * 1024
_COMMIT = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class Pin:
    repo: str
    path: str
    ref: str      # pełny skrót commita (nie gałąź)
    sha256: str   # SHA-256 pliku pod tym commitem
    license: str


# Ustalone 2026-10-11 (git ls-remote HEAD + pobranie pliku pod tym commitem).
PINS = {
    "wmn": Pin("WebBreacher/WhatsMyName", "wmn-data.json",
               "062bcfe48df79fa618e96edc79dc9673f3fe5643",
               "507d2f8aa5b1297ae2d713634ccc7ce08357fed85b1d40130585810f456c1cfe", "CC BY-SA 4.0"),
    "maigret": Pin("soxoj/maigret", "maigret/resources/data.json",
                   "eaf820666d15bfd545129f3223e2261c27191e74",
                   "908bac913ad473ca590074a80c7c38d9b133d2af8bf30c313d25dde6a2be5efe", "MIT"),
}


class IntegrityError(Exception):
    """Źródło nie przeszło weryfikacji (skrót, rozmiar, schemat URL, wersja)."""


def source_url(pin: Pin, ref: str) -> str:
    return f"https://raw.githubusercontent.com/{pin.repo}/{ref}/{pin.path}"


def fetch(url: str, max_bytes: int = MAX_BYTES) -> bytes:
    if not url.startswith("https://"):
        raise IntegrityError(f"tylko https: {url}")
    with urllib.request.urlopen(url, timeout=60) as r:  # nosec B310 - schemat sprawdzony wyżej
        data = r.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise IntegrityError(f"plik większy niż {max_bytes} B: {url}")
    return data


def verify(data: bytes, expected: str, label: str) -> str:
    got = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(got, expected):
        raise IntegrityError(f"{label}: SHA-256 {got} różni się od oczekiwanego {expected}")
    return got


def expected_pin(name: str, ref: str | None, sha256: str | None) -> tuple[str, str]:
    """(commit, oczekiwany skrót) dla źródła; nadpisanie wersji wymaga jawnego skrótu."""
    pin = PINS[name]
    ref = (ref or pin.ref).strip().lower()
    if not _COMMIT.fullmatch(ref):
        raise IntegrityError(f"{name}: --{name}-ref musi być pełnym skrótem commita (40 znaków hex), nie gałęzią")
    if sha256 is not None:
        sha = sha256.strip().lower()
        if not _SHA256.fullmatch(sha):
            raise IntegrityError(f"{name}: --{name}-sha256 musi mieć 64 znaki hex")
        return ref, sha
    if ref != pin.ref:
        raise IntegrityError(f"{name}: inna wersja niż przypięta wymaga --{name}-sha256")
    return ref, pin.sha256


def load(name: str, path: str | None, ref: str | None, sha256: str | None) -> tuple[dict, dict]:
    """Wczytuje źródło (plik lokalny albo przypięty URL), weryfikuje skrót, zwraca (dane, metadane)."""
    pin = PINS[name]
    commit, expected = expected_pin(name, ref, sha256)
    if path:
        data, origin = Path(path).read_bytes(), {"path": str(path)}
        if len(data) > MAX_BYTES:
            raise IntegrityError(f"{name}: plik większy niż {MAX_BYTES} B")
    else:
        url = source_url(pin, commit)
        data, origin = fetch(url), {"url": url}
    digest = verify(data, expected, name)
    meta = {**origin, "commit": commit, "sha256": digest, "license": pin.license}
    return json.loads(data.decode("utf-8")), meta


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--wmn")
    p.add_argument("--maigret")
    for name in PINS:
        p.add_argument(f"--{name}-ref", help="pełny skrót commita innej wersji (wymaga --*-sha256)")
        p.add_argument(f"--{name}-sha256", help="oczekiwany SHA-256 pliku")
    p.add_argument("--out", default=str(ROOT / "data" / "sites.json"))
    a = p.parse_args(argv)

    try:
        wmn_raw, wmn_meta = load("wmn", a.wmn, a.wmn_ref, a.wmn_sha256)
        mg_raw, mg_meta = load("maigret", a.maigret, a.maigret_ref, a.maigret_sha256)
    except IntegrityError as exc:
        print(f"Błąd integralności źródła: {exc}. Nic nie zapisano.", file=sys.stderr)
        return 2

    custom = from_custom(json.loads(CUSTOM.read_text(encoding="utf-8"))) if CUSTOM.exists() else []
    wmn = from_wmn(wmn_raw)
    mg = from_maigret(mg_raw)
    sites = merge(custom, wmn, mg)          # własne reguły wygrywają przy duplikatach
    if TAG_OVERRIDES.exists():
        apply_tag_overrides(sites, json.loads(TAG_OVERRIDES.read_text(encoding="utf-8")))
    meta = {
        "built": date.today().isoformat(),
        "sources": {
            "custom": {"path": str(CUSTOM.relative_to(ROOT)), "sites": len(custom)},
            "wmn": {**wmn_meta, "sites": len(wmn)},
            "maigret": {**mg_meta, "sites": len(mg)},
        },
    }
    save_db(sites, a.out, meta)
    weak = sum(1 for s in sites if not any(s.e_strings))
    print(f"Wlasne {len(custom)} + WMN {len(wmn)} + Maigret {len(mg)} -> {len(sites)} po deduplikacji "
          f"(slabe reguly bez tekstu obecnosci: {weak}). Zrodla: {dict(Counter(s.source for s in sites))}")
    print(f"Zapisano: {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
