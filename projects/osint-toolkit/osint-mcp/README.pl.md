# OSINT MCP

Serwer MCP (FastMCP, transport stdio) wystawiający wybrane moduły repo jako narzędzia dla Claude. **Defensywnie i tylko infrastruktura**: domeny, adresy IP, własna ekspozycja w wyciekach. Do użycia na zasobach własnych, klientów (za zgodą) lub publicznych. Celowo **nie wystawia** niczego person-oriented (username-engine, entity-graph, wyszukiwanie osób, e-mail -> konta).

```bash
py -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m pytest -q            # testy bez internetu (fałszywy podproces)
```

Najprościej: dwuklik `START_OSINT_MCP.cmd` (tworzy `.venv`, pokazuje polecenie rejestracji i sprawdza `.venv` modułów).

## Narzędzia

| Narzędzie | Moduł (podproces) | Wywołanie |
|---|---|---|
| `dns_audit(domain)` | `dns-audit` | `-m dns_audit DOMENA --json` |
| `phone_check(number, region="PL")` | `phone-check` | `-m phone_check NUMER --region PL --json PLIK_TMP` (offline; wynik z pliku tymczasowego) |
| `hibp_domain_breaches(domain)` | `hibp-monitor` | `-m hibp_monitor breaches --domain DOMENA --no-save --json` |
| `ip_info(ip)` | `net-intel` | `-m net_intel ip IP --json` |
| `rdap(domain)` | `net-intel` | `-m net_intel rdap DOMENA --json` |
| `subdomains(domain)` | `net-intel` | `-m net_intel subdomains DOMENA --json` |

Każdy opis narzędzia zawiera zastrzeżenie o zakresie defensywnym. Wynik to sparsowany JSON modułu (pola `status` / `counts` / `findings`, ewentualna lista jest opakowana w `{"result": ...}`). Wynik `status: failed` albo źródło z `ERROR` oznacza „nie udało się sprawdzić”, a **nie** „brak wyników”.

## Jak to działa
- Każdy moduł jest uruchamiany z **własnego** `.venv\Scripts\python.exe` (`python -m pakiet ...`), jak w `panel/app.py`: argumenty jako lista (bez powłoki), twardy timeout (phone 30 s, IP 60 s, RDAP/HIBP 90 s, DNS 120 s, subdomeny 150 s), katalog roboczy tymczasowy (np. `hibp-monitor` nie czyta ani nie zapisuje `state.json`), `stdin` podprocesu to `NUL` (nie dziedziczy kanału protokołu MCP), limit rozmiaru wyniku 20 MB.
- **Brak `.venv` modułu** = czytelny błąd z nazwą skryptu, np. „Moduł net-intel nie ma środowiska .venv ... Uruchom dwuklikiem ...\net-intel\START_NET_INTEL.cmd”.
- Błędy (zła walidacja, timeout, kod wyjścia inny niż 0/1, tekst zamiast JSON-a) wracają jako błąd narzędzia (`isError`), nigdy jako pusty wynik. Kod 1 modułów (są ustalenia WARN/FAIL, numer niepoprawny, wynik niepełny) to nadal poprawny JSON i jest zwracany.
- **Walidacja wejścia** (przed uruchomieniem czegokolwiek): domena to sama nazwa (bez schematu, ścieżki, `@`, portu, spacji), IP przez `ipaddress`, numer to cyfry z opcjonalnym `+` i separatorami, region to dwie litery. Każda wartość zaczynająca się od `-` jest odrzucana (wstrzyknięcie opcji CLI), podobnie jak znaki nowej linii.
- Katalog repo wynika z położenia pakietu; można go nadpisać zmienną `OSINT_ROOT`.

## Rejestracja

Serwer **nie rejestruje się sam** w żadnej konfiguracji Claude. Zrób to ręcznie.

**Claude Code** (zakres użytkownika, jednorazowo):

```
claude mcp add osint -- C:\path\to\security-engineering-projects\projects\osint-toolkit\osint-mcp\.venv\Scripts\python.exe -m osint_mcp
```

Dla wybranego projektu dodaj `--scope project` (zapisze `.mcp.json`) albo `--scope user` (wszędzie). Sprawdzenie: `claude mcp list`.

**Claude Desktop** (`%APPDATA%\Claude\claude_desktop_config.json`, po zmianie zrestartuj aplikację):

```json
{
  "mcpServers": {
    "osint": {
      "command": "C:\\path\\to\\security-engineering-projects\\projects\\osint-toolkit\\osint-mcp\\.venv\\Scripts\\python.exe",
      "args": ["-m", "osint_mcp"]
    }
  }
}
```

## Wymagania
`.venv` modułów, z których korzystasz: `dns-audit`, `phone-check`, `hibp-monitor`, `net-intel` (każdy tworzy dwuklik jego `START_*.cmd`). Moduł bez `.venv` psuje tylko własne narzędzia; pozostałe działają.

## Struktura
- `runner.py`: walidatory wejścia, wyszukanie `.venv`, `run_module` (podproces, timeout, parsowanie JSON, `ToolFailure`)
- `tools.py`: sześć funkcji narzędzi (bez zależności od MCP; testy wstrzykują fałszywy `subprocess.run`)
- `server.py`: rejestracja w FastMCP (funkcje `async`, praca podprocesu w wątku, by nie blokować pętli MCP)

## Znane ograniczenia
- Limity zewnętrznych źródeł (Cert Spotter bez klucza ok. 10 zapytań na godzinę, przeciążony crt.sh) wychodzą jako `ERROR` przy źródle w wyniku `subdomains`; to nie jest awaria serwera.
- Serwer nie ma stanu i nie zapisuje niczego poza katalogiem tymczasowym (usuwanym po wywołaniu).
- `phone_check` waliduje wyłącznie plan numeracji (offline) i nie ustala właściciela numeru.
