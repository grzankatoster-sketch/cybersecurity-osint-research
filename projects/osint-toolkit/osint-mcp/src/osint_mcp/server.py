"""Serwer MCP (FastMCP, stdio) nad modułami OSINT repo.

Zakres: DEFENSYWNY, wyłącznie infrastruktura (domeny, adresy IP, własna ekspozycja w wyciekach).
Celowo NIE wystawiamy narzędzi person-oriented (username-engine, entity-graph, wyszukiwanie osób,
e-mail -> konta). Narzędzia uruchamiają moduły jako podprocesy z ich własnych .venv.
"""

from __future__ import annotations

import asyncio
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import tools

SCOPE = ("Zakres defensywny: tylko infrastruktura własna, klientów (za zgodą) lub publiczna "
         "(domeny, adresy IP). Nie służy do wyszukiwania osób.")

mcp = FastMCP(
    "osint",
    instructions=(
        "Narzędzia defensywnego OSINT-u infrastruktury (audyt DNS i poczty, RDAP, subdomeny, informacje o IP, "
        "wycieki domeny w HIBP, walidacja numeru telefonu offline). " + SCOPE + " "
        "Wynik z polem status=failed lub ERROR przy źródle oznacza 'nie udało się sprawdzić', a NIE 'brak wyników'."
    ),
)


@mcp.tool()
async def dns_audit(domain: str) -> dict[str, Any]:
    """Audyt DNS i konfiguracji poczty domeny: SPF, DMARC, DKIM, DNSSEC, MTA-STS, CAA, rekordy weryfikacyjne,
    z ustaleniami OK/INFO/WARN/FAIL i zaleceniami. Czyta wyłącznie publiczne rekordy DNS.
    Zakres defensywny: domena własna, klienta (za zgodą) lub publiczna; nie służy do wyszukiwania osób.
    Argument: sama nazwa domeny, np. example.com."""
    return await asyncio.to_thread(tools.dns_audit, domain)


@mcp.tool()
async def phone_check(number: str, region: str = "PL") -> dict[str, Any]:
    """Offline walidacja formatu numeru telefonu wg planu numeracji (poprawność, typ linii, kraj, strefa czasowa).
    Bez zapytań do sieci i bez ustalania właściciela numeru. Zakres defensywny: weryfikacja własnych danych
    kontaktowych i numerów firmowych; nie służy do wyszukiwania osób.
    Argumenty: number (dowolny zapis, np. +48 600 100 200), region (kod ISO dla numerów bez +, domyślnie PL)."""
    return await asyncio.to_thread(tools.phone_check, number, region)


@mcp.tool()
async def hibp_domain_breaches(domain: str) -> dict[str, Any]:
    """Publicznie znane wycieki (katalog Have I Been Pwned) powiązane z domeną: nazwa, data, liczba kont, klasy danych.
    Używa wyłącznie oficjalnego API bez klucza; nie zwraca żadnych adresów e-mail ani kont. Nic nie zapisuje.
    Zakres defensywny: ocena ekspozycji domeny własnej, klienta (za zgodą) lub publicznej usługi. Nie służy do wyszukiwania osób."""
    return await asyncio.to_thread(tools.hibp_domain_breaches, domain)


@mcp.tool()
async def ip_info(ip: str) -> dict[str, Any]:
    """Informacje o adresie IP: ASN i organizacja, kraj/region/miasto (przybliżone), strefa czasowa, anycast, hostname
    (ipinfo.io) oraz odwrotny DNS (PTR) jako drugie, niezależne źródło. Adresy prywatne i zarezerwowane są opisywane
    lokalnie, bez zapytań sieciowych. Zakres defensywny: infrastruktura własna, klienta (za zgodą) lub publiczna;
    to dane o adresie sieciowym, nie o osobie. Nie służy do wyszukiwania osób."""
    return await asyncio.to_thread(tools.ip_info, ip)


@mcp.tool()
async def rdap(domain: str) -> dict[str, Any]:
    """RDAP domeny: rejestrator, daty utworzenia/zmiany/wygaśnięcia, statusy, serwery nazw, DNSSEC, dni do wygaśnięcia
    oraz ustalenia (wygasa wkrótce, status hold). Dane kontaktowe rejestrującego nie są odczytywane ani zwracane.
    Zakres defensywny: domena własna, klienta (za zgodą) lub publiczna; nie służy do wyszukiwania osób.
    Argument: domena zarejestrowana (np. example.com, nie www.example.com)."""
    return await asyncio.to_thread(tools.rdap, domain)


@mcp.tool()
async def subdomains(domain: str) -> dict[str, Any]:
    """Pasywne wyliczanie subdomen z trzech niezależnych źródeł (HackerTarget, Cert Spotter, crt.sh), z informacją,
    które źródło zgłosiło którą nazwę. Źródła bywają przeciążone: wynik ma status ok/partial/failed, a gdy wszystkie
    zawiodły, znaczy to 'nie udało się sprawdzić', a NIE 'brak subdomen'. Nie wysyła zapytań do badanej domeny.
    Zakres defensywny: inwentaryzacja powierzchni ataku domeny własnej, klienta (za zgodą) lub publicznej. Nie służy do wyszukiwania osób."""
    return await asyncio.to_thread(tools.subdomains, domain)


def main() -> None:
    mcp.run()  # transport stdio


if __name__ == "__main__":
    main()
