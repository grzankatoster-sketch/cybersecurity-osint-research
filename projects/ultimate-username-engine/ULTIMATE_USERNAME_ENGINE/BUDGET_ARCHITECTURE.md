# Budżet wyszukiwania — 2026-10-09

## Audyt przed zmianą

Przepływ: `cli.Command.search` → `select_services` → `UsernameEngine.search_stream`
→ `plan_request` → `Scheduler.stream` → `_SearchWork.step` → `_Budget.remaining -= 1`
→ `transport.send` → detekcja/retry/redirect/enrichment → journal → ANALYST.

| Pytanie | Zachowanie poprzedniej wersji |
|---|---|
| Co ograniczał request budget? | Wywołania transportu, nie serwisy ani samą liczbę definicji. |
| Czy retry kosztowało? | Tak, każde kolejne wywołanie transportu. |
| Czy fallback kosztował? | Automatyczny fallback nie istniał. |
| Czy donorzy mogli kosztować kilka jednostek? | Tak w `--selection all` i przy jawnym wyborze definicji. Domyślna selekcja jakościowa już deduplikowała. |
| Kiedy rezerwowano budżet? | Po preflight, bezpośrednio przed `send`, bez `await` pomiędzy kontrolą i dekrementacją. |
| Anulowanie? | Przed rezerwacją: 0. Po rezerwacji: 1, bez zwrotu. Brakowało rekordu próby anulowanej podczas transportu. |
| BLOCKED / TIMEOUT / 429? | Każda rozpoczęta próba kosztowała 1, niezależnie od wyniku. Timeout kolejki przed próbą kosztował 0. |
| Redirect? | Każdy hop kosztował 1. |
| Enrichment? | BASIC korzystał z tego samego body; FULL follow-up zużywał globalny limit i osobny limit enrichment. |

Domyślny limit CLI wynosił 10 000. Deadline obejmował żądania i przetwarzanie
metadanych. Limity były i pozostają **na jeden nick/job**. Trzy nicki to trzy budżety.
Istotna korekta opisu problemu: „pierwsze N rekordów” było modelem historycznym;
wersja startowa tego etapu miała już ranking i canonical services.

## Model wdrożony

`RuntimePolicy` → canonical selection z punktacją → ograniczenie service budget
→ jeden `_CanonicalWork` na serwis → primary / najwyżej dwa fallbacki
→ wspólny `_Budget` → dotychczasowy ograniczony scheduler.

Service budget ogranicza liczbę dopuszczonych grup profilu. Request budget jest
twardym sufitem wszystkich rozpoczętych żądań, również przekierowań. Retry budget
i enrichment budget są podlimitami tego samego sufitu, a nie dodatkowymi pulami.
Rozdzielenie jest uzasadnione: retry nie powinno zużyć całego skanu, a FULL nie
powinien bez ograniczenia zwiększać kosztu zbierania metadanych.

Rezerwacja jest atomowa w ramach jednej pętli asyncio. Żądanie anulowane po
rezerwacji ma teraz `AttemptRecord` z CANCELLED; nie zakładamy, że pakiet dotarł
do serwera, tylko że wywołanie transportu rozpoczęto. BASIC nadal kosztuje 0
dodatkowych żądań. Slot enrichment rezerwuje się przy planowaniu follow-up;
globalną jednostkę dopiero przy rozpoczęciu próby. Niewykorzystany slot nie jest
raportowany jako wykonane żądanie.

| Tryb | Serwisy maks. | Żądania maks. | Retry maks. | Follow-up enrichment maks. | Deadline | Fallbacki/serwis | Min. score |
|---|---:|---:|---:|---:|---:|---:|---:|
| QUICK | 50 | 50 | 0 | 0 | 90 s | 0 | 30 |
| NORMAL | 200 | 250 | 10 | 0 | 300 s | 2 | 0 |
| DEEP | 1000 | 1300 | 50 | 50 | 1200 s | 2 | -30 |
| EXHAUSTIVE | 1 000 000 | 20 000 | 200 | 200 | 3600 s | 2 | -100 |

EXHAUSTIVE obejmuje wszystkie 7557 kompatybilnych grup aktualnego katalogu.
Milion jest skończonym bezpiecznikiem dla przyszłych katalogów, a nie planowaną
liczbą żądań. Domyślne concurrency 20 / per-origin 2 / per-job 10 pozostają;
definicja może nakładać niższy limit. Budżet enrichment jest używany dopiero
z `--enrich full` i tylko przy zadeklarowanym dozwolonym URL follow-up.
Retry dodatkowo wymaga zgody polityki danej definicji; samo ustawienie 10 nie
wymusza dziesięciu powtórzeń.

Profile są jawną konfiguracją w `runtime_policy.MODES`, nie oszacowaniem
optymalności dla całego internetu. `--runtime-config plik.json` wczytuje ścisły
`RuntimePolicy` (pominięte pola mają defaults NORMAL); zastępuje profil trybu.
Jawne flagi `--request-budget`, `--service-budget`, `--retry-budget`,
`--enrichment-request-budget`, `--job-timeout` mają pierwszeństwo.

## Ranking, różnorodność i koszt

Podstawowa punktacja: poprawna definicja +10, positive +10, negative +10,
owner binding +30, treść zamiast samego statusu +15, zadeklarowany parser lub
zweryfikowany adapter +15. Nowe składniki: structured JSON rule +10,
brak positive -20, positive oparte wyłącznie o status -15,
niezgodne reguły donorów -5, index evidence -30. Niepoprawne i wyłączone
definicje nie wchodzą do planu. Każdy składnik jest zapisany w `.selection.json`.

Nie naliczamy premii „aktualna walidacja” ani kar „stale” bez pomiaru. Deklaracja
reguły nie dowodzi jej poprawności na żywo. Statyczna punktacja jest heurystyką
jakości technicznej, a nie prawdopodobieństwem istnienia konta.

Najpierw idą najwyższe progi jakości (m.in. binding/JSON), potem pozostałe
dopuszczone definicje. Różnorodność kategorii działa wewnątrz równych progów:
preferowana jest mniej dotąd reprezentowana kategoria, bez równych kwot.
Nie obniża jakości pierwszeństwa na rzecz samej kategorii. Kategorie `misc`
nie są sztucznie rozbijane. Wartość/koszt jest deterministyczna: bazowy koszt
primary to jeden send; kolejne koszty są warunkowe i podlegają wspólnym limitom.
Nie udajemy, że znamy przyszłe opóźnienia albo częstość blokad.

## Granice i dalsze decyzje

- Brak requestu: ANALYST `NOT_TESTED`, technicznie np. BUDGET_EXHAUSTED,
  API_REQUIRED, DEGRADED. Po rzeczywistej odpowiedzi 429/403 wyczerpanie limitu
  nie nadpisuje jej semantyki; przyczyna zatrzymania trafia do reasons.
- Summary obejmuje także grupy odrzucone przez service budget / próg jakości;
  `not_tested_selected` pozwala odróżnić je od dopuszczonych, lecz niewykonanych.
- Rozszerzenie jest sugestią `deep/exhaustive`; brak automatycznego podnoszenia
  kosztu, zatrzymania po pierwszym profilu czy ukrytego `max-results`.
- Rozważono resume i cache TTL. Nie wdrożono automatycznego ponownego użycia
  wyników: wymaga osobnej polityki świeżości, klucza nick+canonical+revision i
  krótszego TTL negatywów. Obecny journal zachowuje zatwierdzone obserwacje,
  ale nie udaje kompletnego checkpointu kolejki. Każda kontrolna walidacja
  wykonuje wskazane próby ponownie.
- API biblioteki bez `runtime` zachowuje dotychczasową semantykę. Adaptacyjne
  wywołanie wymaga `SelectionPlan`; limity policy obowiązują również wtedy,
  gdy caller poda większy `SearchOptions.request_budget`.

Źródła: `engine.py`, `scheduler.py`, `runtime_policy.py`, `cli.py`.
Dowody: `artifacts/adaptive-budget/`, [wyniki](RUNTIME_BUDGET_RESULTS.md).
