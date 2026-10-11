# ci/ - kontrole i testy E2E pipeline'u OSINT

Pipeline: oficjalne rejestry (KRS / CEIDG / REGON) -> adapter `osint-poland/src/osint_poland/org_intel_feed.py` ->
`org-intel` (`ingest`, `export --format json`, katalog HIBP) -> `entity-graph import-org-intel` (sprawa: `graph.json`,
`audit.jsonl`, `graph.graphml`, `report.html`, `maltego.csv`) -> `entity-graph export --maltego`.

Ten katalog zawiera jeden skrypt, ktory uruchamia te same kontrole lokalnie i w GitHub Actions
(`.github/workflows/osint-pipeline.yml`), oraz testy E2E calego lancucha. Zasady: **zero sieci** (testy online wylaczone),
**zero sekretow** (workflow ich nie uzywa), **tylko dane syntetyczne** (fikcyjne firmy z fixtur repozytorium, adresy w domenie
`example.test`).

## Uruchomienie lokalne

Wymagany Python >= 3.12 oraz pakiety z `ci/requirements.txt` (pytest, ruff, a dla testu adaptera httpx, pydantic i psycopg;
pakiety pipeline'u sa stdlib-only i NIE musza byc zainstalowane, bo kroki dziaja z `pythonpath = src` kazdego pakietu):

```
py -m pip install -r ci/requirements.txt         # albo: python -m venv .venv-ci && ... (poza repo albo w .venv-ci/)
py ci/run_checks.py                              # wszystkie kroki z katalogu glownego repo
py ci/run_checks.py --list                       # lista krokow
py ci/run_checks.py --only test:org-intel        # jeden krok
py ci/run_checks.py --only hygiene --only lint   # cale grupy: hygiene, test, lint
py ci/run_checks.py --skip lint --fail-fast
py ci/run_checks.py --ruff "sciezka/do/python -m ruff"   # gdy ruff nie jest w biezacym srodowisku (albo zmienna RUFF)
py ci/run_checks.py --artifacts ci-artifacts     # zapisz summary.json + summary.md i przeskanuj je (jak w CI)
cd ci && py -m pytest -q                         # tylko testy E2E i testy skryptu
```

Kody wyjscia: **0** wszystko OK, **1** testy albo kontrole nieudane (takze trafienie skanera artefaktow), **2** blad uzycia lub
srodowiska (nieznany krok, brak pytest/ruff/zaleznosci, Python < 3.12). Na koncu skrypt wypisuje podsumowanie per krok (wynik, czas,
liczby testow). Podsumowanie i wyjscie nieudanych krokow sa maskowane (e-maile, JWT, Bearer, klucze prywatne, tokeny).

## Kroki

| Krok | Co robi |
|---|---|
| `hygiene:case-data` | `git ls-files`: pada, gdy w repo sa dane spraw (`graph.json`, `audit.jsonl`, `graph.graphml`, `maltego.csv`, `store.json` poza `tests/fixtures/`), katalogi `wyniki/` i `org-intel-data/`, pliki `*.env`/`.env*` poza `.env.example` |
| `hygiene:eol` | `git ls-files --eol`: pada na pliku z MIESZANYMI koncowkami linii (`i/mixed` lub `w/mixed`) w pakietach pipeline'u (CRLF albo LF w calym pliku jest dozwolone). Znany dlug: `ci/known_mixed_eol.txt` |
| `test:osint-connectors`, `test:org-intel`, `test:hibp-monitor`, `test:entity-graph`, `test:meta-search` | `pytest -q` w katalogu pakietu (entity-graph w calosci: importer, eksport Maltego, guardrails, proxy fail-closed) |
| `test:osint-poland-feed` | tylko `osint-poland/tests/test_org_intel_feed.py` (adapter); wymaga httpx, pydantic, psycopg (conftest importuje psycopg), NIE wymaga PostgreSQL |
| `test:ci` | `ci/tests`: E2E calego lancucha + testy skryptu |
| `lint:*` | `ruff check` + `ruff format --check`, `--line-length 120`, uruchamiane z katalogu pakietu; tylko pliki ruff-czyste (lista w `LINT_TARGETS` w `run_checks.py`) |
| `artifacts:scan` | z `--artifacts`: skan katalogu artefaktow (JWT, Bearer, klucz prywatny, tokeny, przypisania sekretow, **kazdy** niezamaskowany e-mail); trafienie = kod 1 i usuniecie pliku |

`username-engine` jest w `.gitignore` (osobne repo), wiec nie ma go w checkoucie CI i nie ma dla niego kroku. mypy/pyright: repo ich
nie uzywa (brak konfiguracji), wiec ich nie ma.

## Testy E2E (`ci/tests/test_pipeline_e2e.py`)

Lancuch uruchamia sie raz na modul (fixture `pipe`, podprocesy `python -m <pakiet>` z `PYTHONPATH` na `src` pakietow):
adapter (`--strict`, z dopisanymi claimami o osobach) -> `org-intel ingest` (wynik adaptera, wlasny format z osoba i e-mailem,
katalog HIBP z e-mailem w opisie) -> `org-intel export` (maskowany i `--include-emails`) -> `entity-graph import-org-intel
--strict --report` do nowej sprawy -> `export --maltego`. Regresje, kazda w osobnym tescie:

- `--report` wskazujacy `graph.json`, `audit.jsonl`, `maltego.csv`, `graph.graphml`, `report.html` (takze przez `..`): kod 2, sprawa bajtowo bez zmian, `verify_audit` OK;
- `--dry-run` nie zapisuje nic (bajtowo; zadnego nowego pliku), z `--report` powstaje tylko raport;
- cudzy plik tymczasowy `.{raport}.{pid}.tmp`: odmowa (kod 2), plik nietkniety;
- importer bez eksportu Maltego: dry-run i import przy `sprawa.CASE_FILES` bez `maltego.csv` (nazwa `maltego.csv` nadal zastrzezona dla `--report`) oraz test AST, ze `importers/org_intel.py` nie importuje eksportu/Maltego/sprawy;
- brak proxy blokuje wyszukiwanie: `BRAVE_REQUIRE_PROXY=1` bez proxy -> kod 3, zero polaczen (dziennik prob w podprocesie + atrapa klienta HTTP w procesie), sprawa bez zmian;
- ponowny import jest idempotentny (`graph.json`, GraphML, CSV, HTML bajtowo takie same);
- osoby i e-maile nie trafiaja do grafu (brak wezlow `person`/`email`, brak pelnych adresow; jedyne dopuszczone `@` to adresy zamaskowane przez org-intel w opisie incydentu, `p***@example.test`; `maltego.csv` bez zadnego `@`);
- zrodla bez proweniencji: `org-intel ingest` odrzuca rekord bez zrodla (kod 4), importer odrzuca rekord z pustym `source_ids` (kod 4) albo odmawia przy `--strict` (kod 5, nic nie zapisane).

Siec jest zablokowana podwojnie: fixture `no_network` (autouse) podmienia `socket.socket.connect/connect_ex`,
`create_connection`, `getaddrinfo` w procesie testu, a kazdy podproces dostaje `ci/tests/_nonet/sitecustomize.py` (przez
`PYTHONPATH`), ktory loguje i blokuje proby polaczen do pliku `CI_NONET_LOG`; po kazdym tescie dziennik musi byc pusty. Podprocesy nie
dostaja zmiennych `BRAVE_*`, `OSINT_*`, `EG_*`, `HIBP_*`, `ORG_INTEL_*` ani proxy.

## CI (`.github/workflows/osint-pipeline.yml`)

`push` (main) i `pull_request` dla sciezek pakietow pipeline'u, `ci/**` i samego workflow, plus `workflow_dispatch`;
`permissions: contents: read`, `concurrency` (anulowanie starszych przebiegow), `timeout-minutes: 20`, ubuntu-latest, Python 3.12
(minimum z `pyproject.toml`). Instalacja z `ci/requirements.txt` (wersje przypiete) i `python ci/run_checks.py --artifacts
ci-artifacts`. Jedyny artefakt to podsumowanie krokow (`summary.md`, `summary.json`, retencja 7 dni); jest skanowane przed uploadem.
Workflow nie uzywa zadnych sekretow. Jest niezalezny od `workspace.yml` (frontend `osint-poland/web`).

Aktualizacja wersji narzedzi: zmien przypiecia w `ci/requirements.txt`, uruchom lokalnie `py ci/run_checks.py` (ruff 0.16 inaczej
formatuje niz starsze wersje). Rozszerzenie zakresu ruff: dopisz plik do `LINT_TARGETS` w `run_checks.py` po naprawieniu uwag.

## Znane ograniczenia

- `ci-artifacts/` powstaje w katalogu roboczym przy uruchomieniu z `--artifacts` (lokalnie warto go usunac albo dopisac do `.gitignore`).
- `hygiene:*` poza repozytorium git (np. katalog z `git archive`) skanuje drzewo plikow zamiast `git ls-files`; wynik jest wtedy oznaczony `uwaga`.
- Test E2E w `osint-poland/tests/test_org_intel_feed.py` (adapter -> org-intel -> entity-graph) jest w CI pomijany, bo szuka
  `org-intel/.venv`; ten sam lancuch pokrywa `ci/tests/test_pipeline_e2e.py`.
