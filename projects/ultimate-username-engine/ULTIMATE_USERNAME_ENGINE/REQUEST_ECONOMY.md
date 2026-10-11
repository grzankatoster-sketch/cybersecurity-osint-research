# Ekonomia żądań — pomiar kontrolowany

Źródło danych: `artifacts/adaptive-budget/benchmark.json`.
Reprodukcja: `python tools/adaptive_runtime_benchmark.py --output artifacts/adaptive-budget/benchmark.json`.

Zestaw ma 120 fikcyjnych grup profilu i 360 definicji: primary JSON, identyczny
donor tego endpointu i alternatywny HTML. Znane odpowiedzi obejmują 403, 429,
410, 500, błędny JSON, istniejące i brakujące konta. Brak danych prawdziwych osób.

A = historyczne pierwsze rekordy; B = jakość bez deduplikacji; C = canonical +
jakość bez fallbacku; D = canonical + jakość + publiczny fallback. **Wersja przed
tym etapem była już zbliżona do C, nie do A.** C w eksperymencie korzysta z tych
samych nowych wag co D, aby odizolować efekt fallbacku; nie jest pomiarem starego
commitu na całym publicznym katalogu.

Każda strategia otrzymuje taki sam twardy limit żądań. W każdym wierszu wykonano
dokładnie 20, 50 lub 100 żądań. Liczby poniżej powtórzyły się w FakeTransport
i przy rzeczywistym lokalnym HTTP przez produkcyjny AiohttpTransport.

| Limit | Strategia | Unikalne sprawdzone | Rozstrzygające unikalne | Zablokowane unikalne | Profile z metadanymi | Powtórzenia tego samego endpointu |
|---:|---|---:|---:|---:|---:|---:|
| 20 | A | 7 | 5 | 1 | 0 | 7 |
| 20 | B | 10 | 4 | 3 | 3 | 10 |
| 20 | C | 20 | 8 | 6 | 6 | 0 |
| 20 | D | 13 | 11 | 2 | 3 | 0 |
| 50 | A | 17 | 14 | 2 | 3 | 17 |
| 50 | B | 25 | 9 | 9 | 6 | 25 |
| 50 | C | 50 | 20 | 15 | 15 | 0 |
| 50 | D | 33 | 29 | 4 | 9 | 0 |
| 100 | A | 34 | 30 | 4 | 9 | 33 |
| 100 | B | 50 | 20 | 15 | 15 | 50 |
| 100 | C | 100 | 40 | 30 | 30 | 0 |
| 100 | D | 66 | 59 | 7 | 18 | 0 |

Rozstrzygające = FOUND lub NOT_FOUND dla unikalnej grupy; PROBABLE nie liczy się
do tego wskaźnika. „Zablokowane” tutaj oznacza końcowe BLOCKED/RATE_LIMITED,
nie wszystkie rodzaje nierozstrzygnięć. Metadane liczymy przez `useful_fields`.

| Limit D | Primary HTTP | Fallback HTTP | Retry | Enrichment HTTP | Odzyskane | Pozostały budżet |
|---:|---:|---:|---:|---:|---:|---:|
| 20 | 13 | 7 | 0 | 0 | 7 | 0 |
| 50 | 33 | 17 | 0 | 0 | 17 | 0 |
| 100 | 66 | 34 | 0 | 0 | 34 | 0 |

Efektywność rozstrzygnięć/żądanie: A **25/28/30%**, C **40/40/40%**, D
**55/58/59%**, odpowiednio dla 20/50/100. D ma mniej nowych sprawdzonych grup
i mniej profili z metadanymi niż C w tej próbce. Fallback nie poprawia każdej
metryki; wymienia część zasięgu na rozstrzygnięcie wcześniejszych błędów.
Kontrolne HTML mają dowód właściciela do detekcji, ale nie dostarczają użytecznych
metadanych według rygorystycznych obecnych extractorów.

D względem A usuwa 7/17/33 wykonane duplikaty endpointu. Względem C nie usuwa
nowych duplikatów — C już miało zero. Osobno `duplicate_primary_slots_prevented`
opisuje nadmiarowe definicje całego planu (tu 240), a nie tyle zaoszczędzonych
requestów w każdym małym skanie. Fallback do innego endpointu nie jest duplikatem.

## Ograniczenia pomiaru

Wszystkie fixture są hostowane na jednym originie, więc w tym eksperymencie
ustawiono concurrency=1, job_buffer=1, circuit_threshold=1000 i cooldown 1 ms.
To izoluje strategię wyboru; nie zastępuje testów produkcyjnego cooldownu.
Inne testy sprawdzają domyślną współbieżność, zagłodzenie fallbacku, twarde
limity i circuit breaker. Parser `enrich()` jest produkcyjny, ale dla własnych
fixture uruchamia się inline, bez kosztu Windows process spawn. Nie traktujemy
lokalnych czasów jako pomiaru szybkości internetu ani całej aplikacji.

Przypadki fallbacku zostały przygotowane z działającym alternatywnym HTML.
Uzyskane 100% skuteczności fallbacku jest własnością zestawu kontrolnego,
nie prognozą dla 118 grup publicznego katalogu. Porażki, drugi fallback,
ograniczenia, timeouty i nierozstrzygający fallback są objęte testami jednostkowymi.
