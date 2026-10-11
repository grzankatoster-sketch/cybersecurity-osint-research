# Phase

SEARCH_RUNTIME_STRATEGY_READY — 2026-10-09

395 PASSED / 0 FAILED / 0 SKIPPED; mypy strict (32 moduły), ruff check/format i pip check.

- Adaptacyjne canonical selection, profile QUICK/NORMAL/DEEP/EXHAUSTIVE,
  twarde limity wszystkich żądań, retry i dodatkowego enrichment.
- Kwalifikowany publiczny fallback, jeden wynik i pełen ślad primary/alternatyw.
- Request economy, API_REQUIRED, discovery-only, cooldown i circuit breaker.
- Lokalne liczniki DefinitionHealth; bez automatycznego awansowania definicji.
- Kontrolne HTTP 20/50/100 oraz dwa nowe publiczne GET: dwa FOUND, 26 pól.
- Szczegóły, dowody i ograniczenia: RUNTIME_BUDGET_RESULTS.md,
  artifacts/adaptive-budget/validation.json i installed-validation.json.
- Brak nowych zależności. Poprzednia biblioteczna ścieżka bez runtime zachowana.

Poniżej historyczny status poprzedniego etapu.

USERNAME_RUNTIME_QUALITY_READY — 2026-10-09

- GitHub owner binding, strukturalne adaptery GitHub/DEV, coverage i diagnostyka metadanych.
- ANALYST domyślnie, pełny DEBUG/eksport zachowany, jawne NOT_TESTED i summary.
- Ranking jakościowy i jedna definicja na kanoniczną grupę profilu w domyślnym CLI.
- 341 PASSED / 0 FAILED; zachowane wszystkie wcześniejsze 291 testów, dodano 50.
- Mypy strict: 30 modułów; ruff check/format zaliczone. Brak nowych zależności.
- Pięć odczytów live i odtwarzanie identycznych body; szczegóły w METADATA_FIXES.md.
- Dowody i snapshot poprzedniej wersji: artifacts/runtime-quality/.

Poniżej zachowano zapis poprzedniego etapu.

ENRICHMENT_CONTROLLED_FIXTURES_VALIDATED — 2026-10-08

## DONE

- Zachowane wcześniejsze CORE_OFFLINE_COMPLETE, REAL_HTTP_TRANSPORT, LEGACY_IMPORT,
  FULL_REGRESSION_SUITE, CLI_AND_OUTPUT i PERFORMANCE_VALIDATION.
- Audyt wszystkich 7 922 definicji Maigret i 265 schematów socid-extractor;
  498 statycznych nazw pól oraz osobny katalog pól pochodnych.
- Utrwalony kod przed zmianą; porównanie na 21 kontrolowanych odpowiedziach.
- ProfileMetadata, typed candidates, provenance, walidacja właściciela, konflikty,
  partial success, wspólny parser HTML i JSON discovery.
- CLI OFF/BASIC/FULL; jawne endpointy, osobny budżet follow-up, wspólny scheduler.
- Metryki, limity, procesy parsera z deadline, test prawdziwego lokalnego HTTP.
- Pomiary pipeline i kosztu procesów, pamięć dla 100 / 1 000 / 10 000 profili.
- Pięć raportów ENRICHMENT_*.md, przykład wyniku demo, surowe artefakty i harness.
- Donorzy niezmienieni: 419 sprawdzonych plików, zgodne HEAD, czyste worktree.

## TESTS

**291 PASSED / 0 FAILED / 0 SKIPPED.** Wszystkie wcześniejsze 237 testów nadal przechodzą;
dodano 54 przypadki. Mypy strict: 26 plików źródłowych. Ruff check i format: PASS.
`pip check` w izolowanym `.venv` projektu: PASS. Środowisko narzędzi audytu używające
globalnych site-packages ma niezależny brak aiodns wymagany przez ccxt; nie jest
to zależność Ultimate i nie zmieniano przez to jego requirements.

Stare regresje: 75 COVERED / 17 NOT_APPLICABLE. Nowe ID:
MAIGRET_ENRICHMENT_001–012, z rzeczywistymi wynikami testów w
`artifacts/enrichment/regression-proof.json`.

## CONTROLLED RESULTS

Maigret: 48 zwróconych / 45 poprawnych / 3 błędne pola.
Ultimate before: 4 / 4 / 0. Ultimate after: 108 / 108 / 0.
Oczekiwano 116 pól; 8 nieprzeniesionych pól Patreon pozostaje luką nowego modelu.
Wyniki dotyczą celowo skonstruowanych fixture, nie całego Internetu.

## LIMITATIONS

- Nie uruchomiono pełnego CLI/transportu Maigret ani live scanów publicznych platform.
  Uruchomiono rzeczywisty parser socid i oryginalny wrapper Maigret wyodrębniony z AST.
- Próba doinstalowania zależności Maigret została zatrzymana przez sandbox;
  automatyczna kontrola zgody nie mogła wykonać przeglądu z powodu limitu usługi.
- Większość importowanych definicji nadal daje najwyżej PROBABLE. Metadane wymagają
  osobnego potwierdzenia właściciela i nie zmieniają tego werdyktu.
- Nie przypisano automatycznie wszystkich 265 parserów do 7 814 importów. FULL
  wymaga własnej definicji endpointu i budżetu; aktualny import nie ma takich URL.
- Start procesu na profil jest kosztowny na Windows. Brak nadzorowanej puli parserów.
- Złożone RSC, niestandardowe daty i platformowe struktury wymagają dalszych fixture.
- Zachowano wcześniejsze ograniczenia: brak JS/browsera, AI, GUI, autoupdate;
  164 rekordy w kwarantannie; 756 grup konfliktów; brak live walidacji SOCKS/onion.

## NEXT

Kontrolowane odpowiedzi rzeczywistych kont testowych i przypisane do nich selektory;
owner-aware parser kampanii Patreon; nadzorowana pula procesów z możliwością
zakończenia zawieszonego parsera. Szczegóły: ENRICHMENT_IMPROVEMENTS.md.
