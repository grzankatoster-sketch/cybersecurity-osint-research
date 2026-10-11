# ULTIMATE_USERNAME_ENGINE

## Kalibracja detekcji — 2026-10-09

**DETECTION_QUALITY_VALIDATED.** Sam HTTP 200 nie daje już PROBABLE.
Wynik zawiera `response_class` i `evidence_level`, a metadane wymagają
powiązania z właścicielem profilu. Na 23 zapisanych kandydatach potwierdzono
6 profili i odrzucono 17 niepoprawnych kandydatur. Mały runtime potwierdził
te same 6 profili. Nie wykonano ponownego pełnego skanu.

[Wyniki i ograniczenia pomiaru](DETECTION_QUALITY_RESULTS.md),
[kryteria dowodów](EVIDENCE_MODEL.md),
[zweryfikowane profile](VERIFIED_MATCHES.md),
[URL-e obrazów z provenance](VERIFIED_PROFILE_IMAGES.json).

Komenda wyszukiwania poniżej pozostaje aktualna. Zapisane wcześniej pliki
wyników nie są przeliczane automatycznie; nowa klasyfikacja dotyczy nowych
uruchomień. NORMAL nadal ma limit 200 grup, więc wynik nie obejmuje całego
katalogu. Zgodność nicku nie potwierdza wspólnej tożsamości właścicieli kont.

## Adaptacyjny budżet i publiczny fallback — 2026-10-09

**SEARCH_RUNTIME_STRATEGY_READY.** Zwykłe wyszukiwanie używa teraz NORMAL:
do 200 grup profili i 250 żądań łącznie, z kontrolowanym fallbackiem.
Nie trzeba podawać katalogu ani ręcznie dobierać budżetu:

```powershell
Set-Location 'C:\folder\przyklad\ULTIMATE_USERNAME_ENGINE'
.\.venv\Scripts\python.exe -m ultimate_username search TwojNick --output results\TwojNick.json
```

Otwórz `results\TwojNick.analyst.json`: profile, źródło primary/fallback,
NOT_TESTED i rozliczenie kosztów. Pełne ślady pozostają w `TwojNick.json`.
`--mode quick` ogranicza próbę do 50 żądań bez retry/fallback;
`--mode deep` rozszerza plan. `--enrich full` pozwala użyć skonfigurowanych
dodatkowych żądań enrichment. `--view debug` pokazuje cały łańcuch obserwacji.
Przykład ustawień: `--runtime-config examples\runtime-policy.json`.

`--site` zawęża zbiór wejściowy; adaptacyjny tryb nadal grupuje jego donorów.
`--selection all` służy diagnostyce pojedynczych definicji i pomija adaptacyjną
deduplikację/fallback. Limit request budget jest na jeden nick.
Mały budżet daje ograniczony fragment katalogu, a nie kompletny wynik dla internetu.

- [Budżet, tryby i punktacja](BUDGET_ARCHITECTURE.md)
- [Kwalifikacja i wykonanie fallbacku](FALLBACK_ARCHITECTURE.md)
- [403, 429, klucze API i discovery-only](BLOCK_CLASSIFICATION.md)
- [Porównanie 20/50/100](REQUEST_ECONOMY.md)
- [Próby HTTP, publiczne profile i regresja](RUNTIME_BUDGET_RESULTS.md)

Poniżej zachowano dokumentację poprzednich etapów.

## Naprawa runtime — 2026-10-09

**USERNAME_RUNTIME_QUALITY_READY — 341 testów przechodzi.**
Domyślne CLI używa `--view analyst --enrich basic --selection quality`.
GitHub rozpoznaje wielkość liter nazwy konta; wynik analityczny oddziela profile
od diagnostyki i pozycje sprawdzone od `NOT_TESTED`.

```powershell
Set-Location 'C:\folder\przyklad\ULTIMATE_USERNAME_ENGINE'
.\.venv\Scripts\python.exe -m ultimate_username search JanKowalski --registry data\catalog.json --request-budget 20 --job-timeout 120 --only-matches --output results\JanKowalski.json
```

Otwórz **`results\JanKowalski.analyst.json`**. Pełne dane pozostają w
`results\JanKowalski.json`, a punktacja i alternatywy w `.selection.json`.
`--view debug` pokazuje diagnostykę. `--selection all` wybiera wszystkie definicje,
a jawne `--site` wskazuje konkretne ID. Mały budżet nie oznacza sprawdzenia całej bazy.

- [Naprawy i końcowe odpowiedzi](METADATA_FIXES.md)
- [Rzeczywisty runtime, root cause i przed/po](METADATA_RUNTIME_AUDIT.md)
- [Lejek wyszukiwania, ranking i deduplikacja](SEARCH_FUNNEL.md)
- [Model użytecznych pól](OSINT_FIELD_MODEL.md)
- [ANALYST / DEBUG — obsługa](OUTPUT_REDESIGN.md)

## Enrichment — etap 2026-10-08

Nowy moduł zbiera metadane z już pobranej odpowiedzi i zachowuje pochodzenie każdego
pola. `detection` i `profile_metadata` są oddzielne. Od etapu 2026-10-09 domyślny CLI
używa `--enrich basic`; `--enrich off` pozwala uruchomić samą detekcję.

```powershell
python -m ultimate_username.cli demo szkolenie --site found --enrich basic --output results/enrichment-demo.json
```

Poniżej skrót rzeczywistego wyniku tej komendy z fixture, bez danych prawdziwej osoby:

```json
{
  "site": "found",
  "detection": "FOUND",
  "profile_url": "https://found.example.test/szkolenie",
  "metadata": {
    "username": "szkolenie",
    "display_name": "Profil szkoleniowy",
    "bio": "Kontrolowana odpowiedź demo",
    "followers": 0,
    "verified": false
  },
  "evidence": {
    "name": "username",
    "value": "szkolenie",
    "source_site": "found",
    "source_url": "https://found.example.test/szkolenie",
    "extractor": "StructuredJsonExtractor",
    "evidence": "response$.username",
    "observed_at": "2026-10-08T14:51:52.782853+00:00",
    "quality": "HIGH",
    "priority": 10,
    "validation": "VALID"
  }
}
```

Pełny wynik: `results/enrichment-demo.json`. FULL wymaga jawnego `enrichment_urls`
i dodatniego `--enrichment-request-budget`; domyślnie nie wykonuje dodatkowych HTTP.
Szczegóły kompatybilności starego `enrichment`, limitów i profili PROBABLE są w raporcie zmian.

- [Analiza Maigret](ENRICHMENT_ANALYSIS.md)
- [Katalog wszystkich pól](ENRICHMENT_FIELDS.md)
- [Porównanie przed i po](ENRICHMENT_COMPARISON.md)
- [Wyniki runtime i diagnostyka fixture](ENRICHMENT_RUNTIME_RESULTS.md)
- [Implementacja i ograniczenia](ENRICHMENT_IMPROVEMENTS.md)

Walidacja obejmuje kontrolowane fixture i lokalny HTTP. Nie potwierdza aktualnej
skuteczności całego katalogu publicznych platform. Bieżące testy: `IMPLEMENTATION_STATUS.md`.


Biblioteka Python i niezależne CLI do wyszukiwania nazw użytkownika. Wynik oddziela
werdykt o koncie (`FOUND`, `NOT_FOUND`, `PROBABLE`, `UNKNOWN`) od stanu wykonania
(`OK`, `BLOCKED`, `RATE_LIMITED`, `TIMEOUT` itd.). Każda decyzja zawiera evidence.

**Nie wykonano skanowania publicznych platform.** Kod sprawdzono na FakeTransport
i lokalnych serwerach HTTP/HTTPS. Zaimportowany katalog wymaga osobnej walidacji
skuteczności w rzeczywistych serwisach; historyczne markery dają najwyżej `PROBABLE`.

## Uruchomienie

Projekt jest przygotowany dla Pythona 3.11+, sprawdzony na Pythonie 3.14.2 / Windows 11.
W docelowym katalogu znajduje się lokalne środowisko `.venv`.

```powershell
cd C:\folder\przyklad\ULTIMATE_USERNAME_ENGINE
.\.venv\Scripts\python.exe -m ultimate_username demo szkolenie --site found --output results\demo.json
.\.venv\Scripts\python.exe examples\offline.py
.\.venv\Scripts\python.exe tools\check.py
```

Pełne `demo szkolenie` symuluje także 429 i challenge: zapisuje wszystkie cztery
wyniki i zwraca kod 1. To oczekiwany wynik scenariusza z błędami.

Instalacja w innym środowisku:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-tested.txt
.\.venv\Scripts\python.exe -m pip install --no-deps --no-build-isolation -e .
```

`pyproject.toml` rozdziela zależności produkcyjne (`aiohttp`, `regex`), deweloperskie
i opcjonalny transport SOCKS. `requirements-tested.txt` przypina główne wersje użyte
w walidacji; nie jest pełnym lockfile wszystkich zależności przechodnich.

## Biblioteka

```python
import asyncio
from ultimate_username.demo import make_demo
from ultimate_username.engine import UsernameEngine


async def main():
    registry, transport = make_demo()
    async with UsernameEngine(registry, transport) as engine:
        async for result in engine.search_stream("training_account"):
            print(result.site_id, result.detection.verdict, result.detection.state)


asyncio.run(main())
```

- `search(username)` zbiera listę wyników — zużycie pamięci rośnie z liczbą wyników.
- `search_stream(username, site_ids=..., categories=..., options=...)` daje bounded stream.
- `search_sites(username, sites)` ogranicza wybór po dokładnych ID.
- `search_many(usernames)` jest leniwym strumieniem kolejnych jobów.
- Równoczesne wywołania na tym samym engine współdzielą scheduler i limity.
- `close()` / `async with` zamyka klienta oraz czeka na cleanup aktywnych zadań.
  Przy wcześniejszym zakończeniu własnej iteracji należy wywołać `stream.aclose()`.
- Import pakietu nie ładuje katalogu, pluginów ani klienta HTTP.

Przepływ: `input → registry/validation → normalization → request plan → bounded scheduler
→ one-hop transport → failure gate → evidence/detection → base result → optional extraction
→ Python DTO / journal → JSON, NDJSON, CSV`.

## Registry i transport HTTP

`data/catalog.json` zawiera 8 956 definicji: Maigret 7 814, Sherlock 455, WMN 687.
684 z nich zachowują flagę disabled. 164 rekordy odrzucono z wykonywalnego katalogu;
pełne dane pozostały w `data/import-records.json`. Zidentyfikowano 756 grup konfliktów.

```powershell
.\.venv\Scripts\python.exe -m ultimate_username validate data\catalog.json
.\.venv\Scripts\python.exe tools\import_catalogs.py --donors C:\folder\przyklad\01_nazwa_uzytkownika
```

ID w katalogu mają postać `donor:hash-nazwy`; konfliktujące warianty mają osobne ID.
Nie wybiera się automatycznie „najlepszego” wariantu. Przed kontrolowanym testem
należy wskazać konkretne ID albo przygotować mały, zweryfikowany plik definicji.

Polecenie rzeczywistego HTTP (nie zostało wykonane na publicznych platformach):

```powershell
.\.venv\Scripts\python.exe -m ultimate_username search training_account --registry moja_definicja.json --concurrency 2 --per-origin 1 --request-budget 5 --output results\proba.json
```

Retry, nagłówki, profile/probe URL, timeouty i reguły detekcji należą do definicji.
CLI pozwala ustawić limit globalny, per-origin, per-job, kolejkę, deadline joba,
budżet requestów, proxy oraz filtr ID/kategorii. Nie ma ukrytych opcji ignorowanych przez core.

Aiohttp wykonuje jeden hop. Redirect jest ponownie przydzielany przez scheduler;
przejście do innego origin wymaga `allowed_origins`. Nagłówki niestandardowe i credentials
nie przechodzą automatycznie do nowego origin. Body POST nie jest odtwarzane między originami.
TLS jest weryfikowany. Cookies są wyłączone. Nie ma obchodzenia challenge ani aktywatorów.
`.onion` bez jawnego proxy daje `UNSUPPORTED`; SOCKS wymaga opcjonalnej zależności.

## Detekcja i ekstrakcja

Strategie: status, message, regex, JSON path, redirect, header oraz all/any/not.
Nową strategię rejestruje się jawnie w `DetectionEngine(strategies=...)` i przekazuje
zestaw jej nazw do walidatora registry. Nie można nadpisać istniejącego ID strategii.

`FOUND` wymaga pozytywnego sygnału treści i profile binding. Sam status 200 jest
niewystarczający. Sprzeczne sygnały dają `UNKNOWN`; brak markera negatywnego nie
stanowi dowodu istnienia. Niezaobserwowany sygnał pozostaje niezaobserwowany po negacji.
`confidence.value` pozostaje `null` do kalibracji.

Ekstrakcja ma własne stany `SUCCESS/PARTIAL/EMPTY/ERROR/TIMEOUT/SKIPPED`. Parsery
JSON, regex, Discourse, XenForo i Patreon RSC nie wykonują HTTP. Baza jest zapisywana
przed enrichment; timeout parsera nie zmienia werdyktu. Parser działa w osobnym,
ograniczonym procesie. Dane bez sprawdzenia właściciela mają relację `UNVERIFIED`.
Metadane Blackbird są dostępne osobno i wymagają świadomego przypisania do definicji.

## Wyniki i odtwarzanie

CLI tworzy dziennik SQLite o nazwie UUID. `--journal` pozwala wskazać stałą ścieżkę;
ponowne uruchomienie eksportuje wyłącznie bieżące joby. `ResultJournal.read(base=True)`
odczytuje bazowe wyniki sprzed enrichment. JSON zachowuje wszystkie błędy, historię
przekierowań, próby, body hash, backend, czas i pochodzenie definicji; nie przechowuje body.

Eksport zapisuje plik tymczasowy, wykonuje fsync i atomic replace. Awaria pozostawia
poprzedni artefakt. CSV zabezpiecza komórki rozpoczynające się znakiem formuły;
oryginalne wartości zachowuje JSON. `--output -` emituje dane na stdout, komunikaty na stderr.

Kody CLI: 0 — zakończone bez błędów wykonania; 1 — wynik częściowy/błędy serwisów;
2 — konfiguracja lub zapis; 130 — przerwanie. Już zapisane obserwacje pozostają w journal.
W pracy anulowanej nie powstają pozorne wyniki dla serwisów, których jeszcze nie przyjęto do kolejki.

## Funkcje opcjonalne

Portowane z silnika OSINT; **domyślnie wyłączone** (wyniki i budżety bez flag są takie same jak wcześniej).
Każda dokłada osobną sekcję do dokumentu analitycznego (`*.analyst.json`); format journala i eksport
pełnych wyników się nie zmieniają.

- `--variants [--max-variants N]` — oprócz wpisanej nazwy skanuje jej warianty (separatory, inicjały,
  `_`/`official`/`real`…, z imienia i nazwiska: `"Jan Kowalski"` daje same warianty), maks. N nazw na
  wejście (domyślnie 6, wpisana pierwsza). Każdy wariant to pełny skan. Dokument ma sekcję
  `variants: {is_variant, variant_of}`.
- `--dorks` — sekcja `dorks.queries`: zapytania do wyszukiwarek (`"nazwa"`, grupy `site:`, `inurl:`),
  także dla wariantów. Tylko tekst do ręcznego użycia; silnik niczego nie wysyła.
- `--wayback [--wayback-budget N] [--wayback-unknown]` — dla profili FOUND/PROBABLE (opcjonalnie
  UNKNOWN) pyta Wayback CDX przez transport silnika. Budżet N (domyślnie 20) jest łączny dla całego
  przebiegu i osobny od `--request-budget`; w `request_economy` jako `wayback_requests`. Sekcja
  `wayback`: `{budget, requests, skipped_over_budget, errors, profiles:[{profile_url,
  snapshots:[{timestamp, original, status}], first_seen, last_seen}]}`. Błąd archiwum (HTTP, zły
  JSON) trafia do wpisu jako `error`, nigdy jako „brak zrzutów”.
- `--geo [--geo-gazetteer PLIK]` — sekcja `geo`: kraje z poszlak w metadanych trafień (lokalizacja,
  narodowość 1.0; język bio 0.4; domena kraju 0.15; język strony i tag kraju serwisu 0.1), z procentem
  udziału, siłą (`strong/medium/weak`) i źródłem każdej poszlaki (serwis + pole). To wnioskowanie, nie
  fakt. Słownik wbudowany obejmuje kraje i większe miasta; większy (np. `geo.json` z GeoNames z
  silnika OSINT, ok. 2,7 MB) wskazuje się jawnie przez `--geo-gazetteer` i nie jest dołączony.
- `--html PLIK` (search/demo) oraz `report ANALYST.json [--html PLIK]` — raport HTML w jednym pliku, bez JS i zasobów zewnętrznych (CSP, escapowanie danych ze stron, linki tylko http/https z `rel=noopener noreferrer`): trafienia z regułami, wynikiem żądania kontrolnego, identity score (jeśli dokument ma sekcję `identity`) i źródłem każdego pola profilu; opcjonalnie geo, Wayback, dorki, warianty; NOT_FOUND zwinięte, UNKNOWN wg powodu.

## Walidacja i ograniczenia

- [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) — aktualny status i wyniki testów.
- [REGRESSION_STATUS.md](REGRESSION_STATUS.md) — wszystkie 92 ustalenia z konkretnymi testami lub uzasadnieniem N/A.
- [IMPORT_REPORT.md](IMPORT_REPORT.md) — liczby, kwarantanna, konflikty i hashe źródeł.
- [PERFORMANCE.md](PERFORMANCE.md) — pomiary 100 / 1 000 / 10 000 definicji.
- [docs/COMPONENT_TRACEABILITY.md](docs/COMPONENT_TRACEABILITY.md) i [docs/adr](docs/adr) — pochodzenie i decyzje.
- `artifacts/test-results.json`, `quality-gates.json`, `donor-integrity.json` — dowody wykonania.

Brak browsera/JS, AI, rekurencji, domyślnych permutacji (opcjonalnie `--variants`), GUI, PDF i XLSX. Nie ma automatycznego
updatera internetowego, logowania, kalibracji confidence ani współdzielenia odpowiedzi
między konfliktującymi definicjami. Szablony zmieniające hostname są odrzucane.
Weryfikacja `.onion`/SOCKS względem rzeczywistego gateway nie została wykonana.

Cold start osobnego procesu zwiększa czas enrichment. Wbudowany sink SQLite wykonuje
transakcje synchroniczne; benchmark głównego schedulera nie mierzy dysku ani enrichment.
Callbacki telemetryczne i własne sinki muszą być krótkie. SnapshotStore odrzuca równoczesnego
pisarza; lock pozostały po nagłym zakończeniu procesu wymaga sprawdzenia przed ręcznym usunięciem.

Pe?ny wykaz zale?no?ci ko?cowego ?rodowiska Windows/Python 3.14: `requirements-lock-windows-py314.txt`. Aplikacj? instaluje si? oddzielnie przez `pip install -e .`.
