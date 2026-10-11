"""Złoty zestaw: poprawność klasyfikacji odpowiedzi serwisów (najważniejsze: brak fałszywych trafień).

Każdy przypadek to syntetyczna reguła serwisu (domeny .example), odpowiedź dla sprawdzanej nazwy, opcjonalnie
odpowiedź kontrolna (losowa nazwa) i prawda:
  jest        — konto istnieje: oczekiwane FOUND z pewnością >= 0.5,
  brak        — serwis jednoznacznie mówi, że konta nie ma: oczekiwane NOT_FOUND,
  nie_wiadomo — blokada, logowanie, limit, niewiarygodna reguła: oczekiwane ERROR albo FOUND z pewnością < 0.5
                (nigdy pewne trafienie i nigdy „brak”, bo to też fałszywy wniosek).
Metryka = odsetek poprawnych. Osobno: FALSZYWE_TRAFIENIA (pewne FOUND przy prawdzie brak/nie_wiadomo).

Zestaw w wersji 1 (2026-10-04, zaakceptowany kierunek przez właściciela). Katalog zamrożony w laboratorium.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from username_engine.classify import classify  # noqa: E402
from username_engine.models import Response, Site, Status  # noqa: E402

PROG_TRAFIENIA = 0.5


def _odp(d: dict | None) -> Response | None:
    if d is None:
        return None
    return Response(status=d.get("status"), text=d.get("text", ""), final_url=d.get("final_url", ""),
                    error=d.get("error"), truncated=bool(d.get("truncated")))


def ocen(p: dict) -> tuple[bool, bool, str]:
    s = p["regula"]
    site = Site(name="Ex", url=s.get("url", "https://ex.example/u/{username}"),
                check_type=s.get("check_type", "message"), e_code=s.get("e_code"), m_code=s.get("m_code"),
                e_strings=s.get("e_strings", []), m_strings=s.get("m_strings", []))
    status, pewnosc, powod = classify(site, _odp(p["odpowiedz"]), p.get("nazwa_konta", "alice"),
                                      _odp(p.get("kontrola")), p.get("nazwa_kontrolna", "zq8x3k1v9w"))
    trafienie = status is Status.FOUND and pewnosc >= PROG_TRAFIENIA
    prawda = p["prawda"]
    if prawda == "jest":
        ok = trafienie
    elif prawda == "brak":
        ok = status is Status.NOT_FOUND
    else:
        ok = not trafienie and status is not Status.NOT_FOUND
    falszywe = trafienie and prawda != "jest"
    return ok, falszywe, f"{status.value} {pewnosc:.2f} ({powod[:70]})"


def main() -> int:
    zestaw = json.loads(Path(__file__).with_name("trafienia_zestaw.json").read_text(encoding="utf-8"))
    dobre = falszywe = 0
    for p in zestaw["przypadki"]:
        ok, fp, opis = ocen(p)
        dobre += ok
        falszywe += fp
        print(f"{'OK ' if ok else 'ZLE'} prawda={p['prawda']:11} wynik={opis}  | {p['nazwa']}")
    n = len(zestaw["przypadki"])
    print(f"poprawne {dobre}/{n}, falszywe trafienia {falszywe}")
    print(f"FALSZYWE_TRAFIENIA={falszywe}")
    print(f"METRYKA={dobre / n:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
