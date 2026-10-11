# Component traceability

Nowy core nie importuje kodu wykonawczego donorów. Dane wejściowe są odczytywane offline.
Źródła sprawdzono przed implementacją mechanizmów; wersje i integralność:
`../artifacts/donor-integrity.json` oraz `../IMPORT_REPORT.md`.

| New component | Donor | Source path / symbol | Adapt/Rewrite | Reason |
|---|---|---|---|---|
| domain/models.py | Maigret, WMN | maigret/result.py::MaigretCheckResult; scripts/checker/models.py::CheckDetail | REWRITE | Oddzielny werdykt i stan wykonania, immutable DTO i wszystkie błędy. |
| planning.py::normalize | Sherlock, Maigret | sherlock_project/sherlock.py:248; maigret/checking.py:954 | REWRITE | Zachowanie raw/canonical, jawne transformacje tylko per site. |
| registry.py | WMN, Sherlock, Maigret | wmn-data-schema.json; sherlock_project/sites.py:161; maigret/sites.py:299 | ADAPT | Walidowany snapshot, błędny rekord nie usuwa poprawnych. |
| domain/validation.py | WMN, socid | wmn-data-schema.json:227; socid_extractor/schemes.py:2392 | ADAPT | Schema plus semantyka URL, regex capture, metody i budżety. |
| importers.py::merge_engine | Maigret | maigret/sites.py::update_from_engine | REWRITE | Jawne przypisanie dict, konflikty do kwarantanny, bez mutacji źródeł. |
| importers.py | Maigret, Sherlock, WMN | resources/data.json; sherlock_project/resources/data.json; wmn-data.json | ADAPT | Programowy import z mapą każdego pola i hashami. |
| planning.py payload/query | Sherlock, Maigret | sherlock_project/sherlock.py::interpolate_string; maigret/checking.py:921 | ADAPT | Rekurencja struktur JSON, kodowanie kontekstowe i oddzielny probe/profile URL. |
| transport.py | Maigret | maigret/checking.py::CheckerBase | REWRITE | Jawny port, pełna odpowiedź i FakeTransport bez sieci. |
| http_transport.py | Blackbird, Maigret | src/modules/core/username.py::fetchResults; maigret/checking.py::SimpleAiohttpChecker | REWRITE | Wspólne sesje, TLS, pojedynczy hop, bounded body i cleanup. |
| scheduler.py | Maigret, Blackbird | maigret/executors.py::run/worker; src/modules/core/username.py:122 | REWRITE | Leniwy dispatcher, global/per-origin/per-job, bounded kolejka i backpressure. |
| policies.py | Maigret | maigret/checking.py:259; maigret/error_detection.py:39 | REWRITE | Jeden właściciel retry, Retry-After, brak śpiących workerów. |
| detection.py failure gate | Maigret, WMN | maigret/error_detection.py::detect_error_page; scripts/checker/checker.py:304 | ADAPT | Błąd przed interpretacją, rozpoznawanie konkretnych challenge patterns. |
| detection.py strategies | Sherlock, WMN | sherlock_project/sherlock.py:405–453; scripts/checker/checker.py:304 | REWRITE | Ternary evidence; brak negatywu nie jest pozytywem; sprzeczność pozostaje UNKNOWN. |
| Confidence | Maigret | maigret/checking.py:917; maigret/result.py:156 | REWRITE | Brak zgadywanych wag; null do kalibracji. |
| extraction.py | socid | socid_extractor/schemes.py::_xenforo_profile, _discourse_html_profile, _patreon_rsc_bootstrap | ADAPT | Strukturalne parsery, kontekst właściciela, długości bajtowe RSC. |
| metadata_import.py | Blackbird | src/modules/utils/parse.py::extractMetadata; data/wmn-metadata.json | REWRITE | 17 deklaratywnych reguł, false/0 zachowane; brak mutacji i pobierania obrazów. |
| health.py | Sherlock, WMN | tests/test_validate_targets.py; scripts/checker/checker.py:336 | REWRITE | Ten sam detector, empty=UNTESTED, przypadkowy control=SUSPECT. |
| storage.py | Maigret | maigret/report.py::_normalize_xmind_archive; maigret/db_updater.py | ADAPT | Wzorzec staging→walidacja→atomic replace; własny SQLite journal i CAS. |
| engine.py / cli.py | socid, Maigret | socid_extractor/main.py::extract; socid_extractor/cli.py::run; maigret/checking.py::maigret | REWRITE | Async-native biblioteka i cienkie CLI bez powielania detekcji. |
| tests / manifest | wszystkie | audyty i DESIGN_LEDGER; socid tests/test_socid_improvements.py | ADAPT | 92 jawne identyfikatory, node IDs, rzeczywiste passed/failed/skipped. |
| Odrzucone mechanizmy | wszystkie | DO_NOT_COPY.md; szczególnie activation.py, AI fallback, browser, legacy exporters | REJECT | Brak obejść blokad, globalnego stanu, ukrytego HTTP i formatów poza MVP. |

Klasyfikacja REUSE nie była potrzebna dla kodu wykonawczego: kontrakty nowego core różnią się
od donorów. ADAPT oznacza przeniesienie sprawdzonego mechanizmu do nowych kontraktów;
REWRITE — zachowanie idei przy nowej implementacji; REJECT — świadome pominięcie.
