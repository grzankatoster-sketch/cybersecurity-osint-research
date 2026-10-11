# HIBP Monitor

Defensywny monitor [Have I Been Pwned](https://haveibeenpwned.com) dla **własnych** domen i haseł. Sekcja 3 audytu: `../AUDYT_OSINT_NOTATKI_2026-10-03.md`. Tylko oficjalne API HIBP; żadnych serwisów z treścią wycieków (Dehashed, LeakPeek itp.), żadnego wiązania danych z osobami.

Zasady bezpieczeństwa, proweniencji i granice legalnego użycia całego pipeline'u: `../docs/BEZPIECZENSTWO_I_PROWENIENCJA.md`.

Zero zależności uruchomieniowych (HTTP przez stdlib `urllib`); `pytest` tylko w trybie dev.

```bash
py -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m pytest -q                      # testy bez internetu
.venv\Scripts\python -m hibp_monitor {breaches,password,domain-search} ... [--json]
```

Najprościej: dwuklik `START_HIBP_MONITOR.cmd` (tworzy `.venv` i `config.toml`), potem `hibp breaches`, `hibp password`, ...

## Polecenia

### `breaches` (bez klucza)
Wycieki, w których **serwis na Twojej domenie był źródłem** (`GET /api/v3/breaches?domain=<d>`), oraz pełny katalog (`/breaches`).

```bash
copy config.example.toml config.toml        # wpisz własne domeny i User-Agent
python -m hibp_monitor breaches             # raport tylko NOWYCH wycieków od ostatniego uruchomienia
python -m hibp_monitor breaches --domain adobe.com --no-save
python -m hibp_monitor breaches --catalog --since 2026-09-01 --limit 10
```

- Stan w `state.json` (obok `config.toml`): znane nazwy wycieków + znacznik `AddedDate` + czas ostatniego uruchomienia.
- Nowy wyciek = nieznana nazwa **lub** `AddedDate` późniejszy niż znacznik. Pierwsze uruchomienie dla domeny to baseline: raportuje wszystko, co jest dziś, i zapamiętuje.
- HIBP wymaga User-Agent (ustaw `user_agent` w `config.toml` lub `--user-agent`).
- `--no-save` to podgląd bez zapisu stanu. Zapis jest atomowy.
- `--catalog --json` zwraca metadane do importu w `org-intel` (`ingest`): nazwa, tytuł, domena, daty (`breach_date`, `added_date`, `modified_date`), `pwn_count`, `data_classes`, opis bez HTML oraz flagi jakości `is_verified/is_fabricated/is_sensitive/is_retired/is_spam_list/is_malware/is_stealer_log` (flaga to tylko jawna prawda). Bez `LogoPath` i bez jakichkolwiek danych kont. Katalog i monitor domen nigdy nie wysyłają klucza API.

### `password` (bez klucza, k-anonymity)
```bash
python -m hibp_monitor password
```
Hasło wpisujesz przez `getpass` (bez echa). Liczone jest SHA-1, do `https://api.pwnedpasswords.com/range/<5 znaków>` idzie **tylko prefiks 5 znaków** z nagłówkiem `Add-Padding: true`; dopasowanie sufiksu robi się lokalnie. Wiersze paddingu (licznik 0) są ignorowane. Hasło nie jest logowane, zapisywane ani wypisywane.

### `domain-search` (opcjonalne, płatne)
```powershell
$env:HIBP_API_KEY = "..."
python -m hibp_monitor domain-search twojadomena.pl
python -m hibp_monitor domain-search twojadomena.pl --show-addresses   # dopiero jawnie
```
Wymaga płatnego klucza HIBP i domeny **zweryfikowanej na Twoim koncie HIBP**. Klucz wyłącznie ze zmiennej środowiskowej `HIBP_API_KEY` (nie z plików, nie z argumentu CLI); bez niego czytelny komunikat i brak jakiegokolwiek ruchu sieciowego. Domyślny wynik to liczby kont na wyciek; adresy tylko z `--show-addresses`. Klucz jest wysyłany wyłącznie do `https://haveibeenpwned.com` (port 443, bez danych logowania w adresie; przekierowania odrzucane) i nie trafia do komunikatów błędów ani do wyjścia; pakiet nie używa modułu `logging`. Weryfikacji własności domeny dokonuje HIBP (404 = domena niezweryfikowana na koncie); `breacheddomain` występuje w kodzie wyłącznie w `domain_search.py` (test statyczny w `tests/test_catalog_boundary.py`).

## Limity i kody wyjścia
HTTP 429 → klient czeka `Retry-After` (maks. 120 s) i ponawia do 3 razy; między domenami jest 1,6 s przerwy. Kody: 0 OK, 2 błąd użycia/konfiguracji/brak klucza, 3 błąd sieci lub API.

## Ograniczenia
- `breaches?domain=` pokazuje wycieki, w których serwis na tej domenie był **źródłem**, a nie wycieki zawierające adresy `@domena` (to robi dopiero płatne `domain-search`).
- Brak trafienia hasła nie dowodzi, że jest silne. Trafienie = zmień je wszędzie.
- Nowość oparta na `AddedDate` i nazwie: modyfikacje istniejącego wycieku (`ModifiedDate`) nie są raportowane.
- Brak powiadomień (e-mail itp.); uruchamiaj z harmonogramu i czytaj `--json`.
- Płatny endpoint nie był testowany na żywo (brak klucza); testy używają fałszywego klienta i fixtur w `tests/fixtures/`.

## Struktura
`src/hibp_monitor/`: `http.py` (klient, 429), `breaches.py` (API, stan, diff, config), `passwords.py`, `domain_search.py`, `cli.py`. Testy w `tests/` z fałszywym klientem HTTP (`conftest.py`).
