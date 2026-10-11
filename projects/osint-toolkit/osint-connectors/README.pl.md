# osint-connectors

Własny, **clean-room** rdzeń konektorów OSINT. Przejmuje tylko *koncepcję*
architektoniczną z audytu holehe/ignorant (`audit/local_source_review_20261004/`)
— rejestr wtyczek, jednolity rekord wyniku, fan-out async, izolacja błędu modułu —
i naprawia ich wady. Kod własny, bez zależności od GPLv3.

## Co naprawia względem audytowanych narzędzi
- **Pełny model statusu** `FOUND / NOT_FOUND / UNKNOWN / ERROR` + jawna `confidence`,
  zamiast sklejania czterech stanów w `exists: bool` + `rateLimit`.
- **Typowane wyjątki** → odróżnienie limitu (`UNKNOWN`) od realnej awarii (`ERROR`).
- **Jawny kontrakt** konektora (`Protocol`) i **jawny rejestr** (dekorator), zamiast
  pobierania funkcji przez `module.__dict__[nazwa_pliku]`.
- **Limit równoległości** (semafor) + per-konektorowy timeout.
- **Prywatność**: cel reprezentowany przez `subject_ref` (HMAC-SHA256 z solą
  per-sprawa); surowy e-mail/numer nie trafia do wyników, logów ani eksportu.
- **Polityka źródeł**: `OFFICIAL_API` / `PASSIVE` / `MANUAL` — bez aktywnego
  sondowania cudzych przepływów rejestracji/logowania.
- **Testy** (oryginały miały zero).

## Struktura
```
src/osint_connectors/
  model.py       # Status, Subject, Finding, InputKind, SourceKind
  errors.py      # taksonomia wyjątków
  connector.py   # Connector (Protocol), ConnectorRegistry, @connector, discover()
  runner.py      # async run() z semaforem + mapowanie wyjątków, summarize()
  privacy.py     # subject_ref() (HMAC-SHA256 z solą)
  connectors/    # konektory referencyjne: manual, passive_local (offline)
tests/           # pytest, bez sieci
```

## Przykład
```python
import asyncio
from osint_connectors import Context, InputKind, Subject, registry, run
import osint_connectors.connectors.manual        # rejestruje konektory
import osint_connectors.connectors.passive_local

subject = Subject(InputKind.EMAIL, "target@example.com")
ctx = Context(salt="tajna-sol-per-sprawa", dataset={"known_refs": set()})
findings = asyncio.run(run(registry.all(), subject, ctx, concurrency=10))
for f in findings:
    print(f.to_dict())   # surowy e-mail nigdy nie pojawia się w wyniku
```

## Testy
```bash
cd osint-connectors
python -m pytest -q      # pythonpath=src skonfigurowane w pyproject.toml
```

## Abstrakcja HTTP
Konektory nie tworzą własnego klienta — dostają go przez `Context.http`
(`HttpClient` Protocol). Testy wstrzykują atrapę → zero ruchu sieciowego.
Produkcyjny adapter `HttpxClient` ładuje `httpx` leniwie; rdzeń nie wymaga httpx.

## Integracja z modelem sprawy (entity-graph)
`osint_connectors.integration` mapuje `Finding` na rekord przebiegu zgodny z
`entity_graph.model.RunRecord` (identyczny enum statusu — mostek przez `Status.name`).
Pakiet **nie importuje** entity-graph; to entity-graph importuje ten pakiet.

```python
from osint_connectors.integration import findings_to_runs

# findings = wynik run(...); node_id z grafu sprawy, dostarcza go entity-graph
runs = findings_to_runs(findings, node_id="email:jan@example.com")

# Wynik to ZSERIALIZOWANY rekord (kształt RunRecord.to_dict(): klucze "node", status jako tekst).
# NIE da się zrobić RunRecord(**r) — konstruktor ma 'node_id' i enum Status. Dwie poprawne drogi:
#   a) wstrzyknąć do słownika grafu i odtworzyć modelem:
#        graph_dict["runs"].extend(runs); Graph.from_dict(graph_dict)
#   b) zbudować rekord wprost:
#        from entity_graph.model import RunRecord, Status
#        RunRecord(transform=r["transform"], node_id=r["node"], status=Status(r["status"]),
#                  timestamp=r["timestamp"], note=r["note"], error=r["error"], stats=r["stats"])
```
Granica odpowiedzialności za dane: hashowany (HMAC z solą) jest **tylko**
identyfikator celu → `stats.subject_ref`. Pola `note` (z `evidence`) oraz
`stats.extra.*` są przepisywane **dosłownie** z `Finding` — HMAC ich nie
zabezpiecza. To konektor odpowiada, by nie umieszczać w nich surowych danych
osobowych; `node_id` (zwykle jawny e-mail) i tak należy do grafu sprawy.

## Decyzja architektoniczna (2026-10-04, po niezależnej weryfikacji)
**Rdzeniem produktu są `entity-graph` + `entity_graph.transforms`** (rejestr `@register`, model
czterech statusów, `Context`, `RunRecord`, klient HTTP). Ten pakiet `osint-connectors` jest
**ZAMROŻONYM PROTOTYPEM**:
- bez nowych konektorów i bez dalszej integracji produkcyjnej;
- dopuszczalne wyłącznie naprawy wykrytych błędów oraz korekty dokumentacji prototypu;
- nowy async runner (semafor) **nie jest** przenoszony do rdzenia bez wykazanej potrzeby
  (graf uruchamia transformacje synchronicznie; brak semafora nie jest tam wadą, a globalnego
  budżetu czasu / limitu per host ten runner nie ma).

Istniejące nakładki (`email_gravatar`, `email_hibp` w `entity_graph/transforms/email.py`) pokrywają
ten sam obszar; rozszerzenia źródeł robimy tam, nie tutaj. Zachowujemy z prototypu użyteczne pomysły
i przypadki testowe. Pełen kontekst: `../AUDYT_WERYFIKACJA_CLAUDE_I_PLAN_2026-10-04.md`,
`../RAPORT_NAPRAW_PO_WERYFIKACJI_2026-10-04.md`.

## Status
- **Faza 1** — rdzeń + 2 konektory offline (`manual_confirm`, `passive_local_dataset`). ✓
- **Faza 2** — konektor `gravatar_public` (PASSIVE, publiczne API) + test kontraktowy
  na zredagowanym, syntetycznym fixture (`tests/fixtures/gravatar_found.json`),
  bez ruchu sieciowego. ✓
- **Faza 3** — adapter `Finding` → run sprawy (`integration/case_mapping.py`) + testy
  kontraktowe wg `entity_graph.model`. ✓ (gotowe do wpięcia)
- **Faza 3b** — faktyczne wywołanie z entity-graph: konektor `brave_search` (OFFICIAL_API,
  `InputKind.PERSON_NAME`) używany przez `eg szukaj-profili`. ✓ (2026-10-04, testy na atrapie transportu;
  produkcyjnego API nie wywoływano)

## Brave Search API (`connectors/brave_search.py`)
- Wejście `InputKind.PERSON_NAME` (imię i nazwisko jako fraza; nie e-mail, nie nick). Istniejące konektory
  go nie obsługują i działają bez zmian.
- `build_queries(nazwa, kontekst)`: deterministyczny plan `"Nazwa" site:facebook.com|instagram.com|threads.com`,
  wariant z kontekstem, wariant bez znaków diakrytycznych; walidacja blokuje operatory w polu nazwiska.
- Jedno `check` = jedno żądanie (`count` 1-20, bez `offset`). Kontekst: `extra={"query", "api_key", "count"}`.
  Klucz tylko w nagłówku `X-Subscription-Token`. Błędy: `NotConfigured`, `AuthRequired` (401/403),
  `RateLimited` (429), `RequestRejected` (400/422), `TransportError` (sieć/5xx), `ParseError`, `SchemaChanged`.
- `parse_response`: pozytywna walidacja otoczki. Dokument z kluczem `error`, `type` inny niż `"search"`, brak
  `query` i `web`, sekcje złego typu, `web` bez listy `results` albo niepusta lista bez żadnego poprawnego rekordu ->
  `SchemaChanged` (ERROR), nigdy NOT_FOUND. Poprawna odpowiedź bez `web` = zero wyników. Lista mieszana: poprawne
  rekordy przechodzą, uszkodzone są liczone (`Finding.extra["skipped_records"]`). Dokumentacja dostawcy opisuje
  `query` i `web.results[]` (`url`, `title`, `description`); wartość `type` i kształt dokumentu błędu to założenie
  (testy na atrapach, nie na produkcyjnym API).
- `UrllibClient`: produkcyjny klient na stdlib (bez przekierowań, limit rozmiaru, opcjonalne przypięte proxy
  CONNECT `http://host:port` bez fallbacku na połączenie bezpośrednie). `timeout` to **całkowity termin** żądania
  (łączenie, TLS, nagłówki, treść): żądanie działa w osobnym wątku demona, po terminie albo przy anulowaniu coroutine
  gniazda dostają `shutdown`, wołający dostaje `ConnectorTimeout` najpóźniej po `timeout + ABORT_GRACE` (0,1 s),
  a wątek kończy się bez dalszego ruchu. Wyjątek: systemowego rozwiązywania nazwy (getaddrinfo) nie da się przerwać;
  wątek czeka wtedy na system, ale potem nic nie wysyła. Bez nowych zależności.

Decyzje: osobny pakiet, pierwszy realny konektor Gravatar, `asyncio`. Szczegóły:
`../PLAN_RDZEN_KONEKTOROW_OSINT_2026-10-04.md`. Konektory `OFFICIAL_API` z
poświadczeniami (HIBP, Meta) dodajemy po decyzji o źródłach.
