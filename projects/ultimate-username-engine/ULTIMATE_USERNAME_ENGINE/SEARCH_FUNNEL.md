# Lejek wyszukiwania i wybór definicji

Data: 2026-10-09. Implementacja: `selection.py`, `engine.py`, `presentation.py`, `cli.py`.

## Co naprawdę stało się we wcześniejszych skanach

`results/proba.json`, nick JanKowalski: 3 rekordy, 3 próby, 3 odpowiedzi HTTP;
1 PROBABLE, 1 NOT_FOUND, 1 UNKNOWN/BLOCKED. Brak argumentów uruchomienia w pliku
uniemożliwia odtworzenie dokładnego argv. Nie jest to pełny skan 8956 definicji.

`results/Sampler51_test.json`: 8956 rekordów, ale tylko **20 prób transportu**.

| Etap / stan tego historycznego pliku | Liczba |
|---|---:|
| Selected / emitted | 8956 |
| Tested | 20 |
| HTTP attempts z zapisanym statusem | 20 |
| Not tested | 8936 |
| Bez próby: BUDGET_EXHAUSTED | **8240** |
| Bez próby: SKIPPED | 682 |
| Bez próby: INVALID_INPUT | 14 |
| Tested / NOT_FOUND | 4 |
| Tested / PROBABLE | 2 |
| Tested / UNKNOWN | 14 |
| Tested / BLOCKED | 1 |
| Tested / RATE_LIMITED | 1 |
| Tested / BUDGET_EXHAUSTED | **1** |
| Tested / PARSE_ERROR | 1 |
| Tested / NETWORK_ERROR | 2 |
| Tested / OK | 14 |

Wiersze stanów i werdyktów to odrębne przekroje, nie składniki jednej sumy.
Łącznie BUDGET_EXHAUSTED wystąpił 8241 razy, lecz jeden z tych rekordów ma już próbę
transportu. Dlatego nie należy oznaczać całej tej grupy jako niesprawdzonej.
Także 8936 niesprawdzonych nie oznacza 8936 pominiętych wyłącznie przez budżet.
Nowy widok stosuje NOT_TESTED na podstawie braku prób, a powód podaje osobno.

Zapisany status HTTP przy NETWORK_ERROR może pochodzić z pośredniego etapu obsługi
odpowiedzi. Licznik HTTP responses nie dowodzi kompletnego, poprawnego body.

## Katalog i duplikaty

| Miara | Wynik |
|---|---:|
| Wszystkie registry definitions | 8956 |
| Kanoniczne grupy szablonów profilu | **8177** |
| Nadmiarowe definicje w tych grupach | **779** |
| Grupy mające więcej niż jedną definicję | 613 |
| Historyczne grupy z importowego conflicts.json | 756 |

8177 to wynik jawnej, zachowawczej reguły grupowania: host + ścieżka + query
szablonu profilu, bez końcowego ukośnika, z ręcznie zaakceptowanym aliasem
www.github.com → github.com. Inne subdomeny i różne ścieżki profilu pozostają osobne.
Nie jest to dowód, że istnieje dokładnie 8177 niezależnych organizacji/platform.
Bez dodatkowej mapy aliasów takiej liczby nie da się uczciwie ustalić automatycznie.

756 grup konfliktów importera nie jest liczbą duplikatów ani listą definicji, które
muszą być w całości wyłączone. W obecnym aktywnym planie 419 grup ma różne deklaracje
detekcji. Alternatywy i ten fakt pozostają zapisane; nie skleja się sprzecznych reguł
w sztuczną regułę potwierdzającą konto.

## Aktualny lejek dla JanKowalski, pełna selekcja jakościowa

```text
8956 registry entries
  → 8271 enabled po poprawkach runtime
     (684 wcześniej disabled + 1 Twitch w kwarantannie)
  → 8271 valid i enabled
  → 8260 compatible with username
     (11 niezgodnych z formatem nazwy)
  → 7557 canonical services selected / planned
     (703 alternatywne definicje w aktywnych grupach)
  → faktycznie requested: mierzone podczas uruchomienia
  → HTTP responses: mierzone podczas uruchomienia
  → positive evidence / PROBABLE / FOUND: mierzone podczas uruchomienia
```

Nie wykonano nowego szerokiego skanu 7557 serwisów. Ostatnich wierszy nie wypełniono
fikcyjnymi liczbami. Ich pomiar działa w widoku analityka dla rzeczywistego bieżącego
uruchomienia. Historyczny Sampler51 to inny nick i inna selekcja; jego liczb nie
wstawiamy do nowego lejka JanKowalski.

628 wszystkich definicji nadal nie ma reguły pozytywnej. Posiadanie tekstu braku
konta nie jest wystarczającym dowodem obecności. W tym etapie nie zamieniono tych
niepełnych definicji masowo na reguły FOUND. Gotowe silne adaptery obejmują GitHub
i DEV; reszta bazy nadal wymaga walidacji platformowej.

## Ranking przy ograniczonym budżecie

`SiteQualityScore` jest jawną heurystyką techniczną, nie prawdopodobieństwem sukcesu:

| Cecha | Punkty |
|---|---:|
| Poprawna, włączona definicja | 10 |
| Reguła obecności | 10 |
| Reguła nieobecności | 10 |
| Binding właściciela | 30 |
| Dodatni sygnał z treści | 15 |
| Deklarowany ekstraktor lub sprawdzony adapter | 15 |

Nieważne i wyłączone definicje otrzymują -100 i są wykluczane z domyślnego planu.
Nie dopisano arbitralnej popularności. Historyczny failure rate i data ostatniej
walidacji są null: brak wiarygodnego historycznego pomiaru dla całej bazy.
Mała walidacja live jest oddzielnym artefaktem, nie symulacją historii wszystkich stron.

W obecnym planie pierwsze są API DEV i GitHub (po 90 punktów), następnie reguły
z dodatnimi i ujemnymi sygnałami treści. Ranking przekazuje uporządkowaną listę do
schedulera; poprawiono również zachowanie tej kolejności przy filtrowaniu registry.
Ograniczenia współbieżności domen mogą zmieniać kolejność ukończenia i wysłania
części zadań. Nie gwarantujemy, że najwyższa statyczna punktacja oznacza najwyższą
realną wykrywalność na każdej platformie.

## Kanoniczny serwis i alternatywy

Domyślny CLI `--selection quality` wybiera jedną najlepszą aktywną, poprawną,
zgodną z nickiem definicję z każdej grupy. `--selection all` umożliwia diagnostykę
wszystkich definicji. Jawne `--site` zachowuje wskazane ID, także przy wyborze kilku
wariantów tego samego serwisu — to świadoma selekcja diagnostyczna użytkownika.

Biblioteczne `search` i `search_sites` zachowują dotychczasowy kontrakt wyboru po ID;
użytkownik API może użyć `prepared_registry` i `select_services`, tak jak robi CLI.
Nie zmieniono po cichu semantyki istniejących integracji bibliotecznych.

Nie wdrożono automatycznego przechodzenia na inny endpoint po BLOCKED, CAPTCHA,
logowaniu ani 429. Alternatywy są zachowane w planie, lecz nie uruchamiają dodatkowego
ruchu. Automatyczny fallback parsera również pozostaje wyłączony: bez walidacji
równoważności wariantów mógłby ukryć błąd reguły. Można jawnie wskazać definicję w
osobnym teście. Wszystkie rzeczywiście uruchomione próby nadal podlegają budżetowi.

## Co mierzy summary

Liczby definicji, grup, enabled, valid, compatible, selected i planned; tested,
not_tested, request_attempts, enrichment_request_attempts, http_responses,
positive_evidence; osobno werdykty i stany wykonania; powody niesprawdzenia oraz
wykluczenia przed wyszukiwaniem; profile z metadanymi i liczba niepustych użytecznych pól.

Nie sumuje się selected z excluded ani UNKNOWN z liczbą niewysłanych requestów.
NO_RULE reprezentuje licznik braku reguły obecności; CONFLICT i QUARANTINE są
informacjami o selekcji, a nie wymyślonymi odpowiedziami serwerów.

Dowód: `artifacts/runtime-quality/funnel.json`. Polecenie odtworzenia offline:

```powershell
.\.venv\Scripts\python.exe -B tools\search_funnel_audit.py `
  --project . --output artifacts\runtime-quality\funnel.json
```
