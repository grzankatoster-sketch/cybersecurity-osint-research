"""Słownik miast i krajów do rozpoznawania lokalizacji: GeoNames (CC BY 4.0) -> data/geo.json.

python scripts/build_geo.py [--cities-sha256 SKROT] [--countries-sha256 SKROT]
GeoNames nie publikuje wersjonowanych zrzutów (pliki zmieniają się codziennie), więc skrótu nie da się
przypiąć na stałe: skrypt pobiera tylko przez https z limitem rozmiaru, opcjonalnie weryfikuje podany
SHA-256 i zapisuje skróty pobranych plików w metadanych wyniku (proweniencja).
Miasta > 15 tys. mieszkańców; dla miast > 100 tys. także nazwy obce (Warsaw, Varsovie…).
Przy niejednoznacznej nazwie wygrywa najludniejsze miasto."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import json
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from username_engine.variants import ascii_fold  # noqa: E402

CITIES_URL = "https://download.geonames.org/export/dump/cities15000.zip"
COUNTRIES_URL = "https://download.geonames.org/export/dump/countryInfo.txt"
ALT_MIN_POP = 100_000
NAME_OK = re.compile(r"^[\w .'\-]{3,40}$")


MAX_BYTES = 50 * 1024 * 1024


def fetch(url: str, expected_sha256: str | None = None, max_bytes: int = MAX_BYTES) -> tuple[bytes, str]:
    """Pobiera plik (tylko https, limit rozmiaru); zwraca (dane, sha256), opcjonalnie weryfikuje skrót."""
    if not url.startswith("https://"):
        raise ValueError(f"tylko https: {url}")
    with urllib.request.urlopen(url, timeout=120) as r:  # nosec B310 - schemat sprawdzony wyżej
        data = r.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"plik większy niż {max_bytes} B: {url}")
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and not hmac.compare_digest(digest, expected_sha256.strip().lower()):
        raise ValueError(f"SHA-256 {digest} różni się od oczekiwanego dla {url}")
    return data, digest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cities-sha256")
    ap.add_argument("--countries-sha256")
    a = ap.parse_args(argv)
    try:
        countries_raw, countries_sha = fetch(COUNTRIES_URL, a.countries_sha256)
        cities_raw, cities_sha = fetch(CITIES_URL, a.cities_sha256)
    except ValueError as exc:
        print(f"Błąd integralności źródła: {exc}. Nic nie zapisano.", file=sys.stderr)
        return 2

    countries: dict[str, str] = {}
    for line in countries_raw.decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        cols = line.split("\t")
        iso, name = cols[0], cols[4]
        countries[ascii_fold(name)] = iso

    rows = []
    with zipfile.ZipFile(io.BytesIO(cities_raw)) as z:
        text = z.read("cities15000.txt").decode("utf-8")
    for line in text.splitlines():
        c = line.split("\t")
        if len(c) < 15:
            continue
        pop = int(c[14] or 0)
        names = {c[1], c[2]}
        if pop >= ALT_MIN_POP:
            names |= {n for n in c[3].split(",") if n}
        rows.append((pop, c[8], names))
    rows.sort(key=lambda r: -r[0])

    cities: dict[str, str] = {}
    for _pop, cc, names in rows:
        for n in names:
            key = ascii_fold(n)
            if NAME_OK.match(key) and key not in countries:
                cities.setdefault(key, cc)

    out = ROOT / "data" / "geo.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"meta": {"source": "GeoNames", "license": "CC BY 4.0",
                                        "sha256": {"countryInfo.txt": countries_sha,
                                                   "cities15000.zip": cities_sha}},
                               "countries": countries, "cities": cities}, ensure_ascii=False), encoding="utf-8")
    print(f"Kraje: {len(countries)}, nazwy miast: {len(cities)} -> {out} ({out.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
