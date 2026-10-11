# Publiczny fallback — 2026-10-09

Canonical service nadal oznacza konserwatywną grupę szablonu URL profilu:
host + ścieżka + query, z wcześniej zweryfikowanym aliasem www GitHub.
Nie utożsamiamy różnych ścieżek i subdomen z jedną platformą bez dowodu.

W grupie najlepsza technicznie definicja jest primary. Pozostałe są sortowane
według tej samej jawnej jakości. Do łańcucha trafiają najwyżej dwa różne
endpointy spełniające `public_alternative`; nie powstają zgadywane URL.

## Kwalifikacja alternatywy

- Ważna, włączona, zgodna z nickiem definicja tej samej grupy.
- Inny probe URL/query niż primary; powtarzające się alternatywne endpointy
  są usuwane przed wykonaniem.
- GET, kontekst `public`, brak body i wymaganego klucza.
- Nagłówki wyłącznie Accept / Accept-Language; brak cookies, Authorization,
  dodatkowych parametrów `query` i podejrzanych parametrów klucza/sesji w URL.
- Host profilu albo jego host `api.`; źródło wyszukiwarkowe nie kwalifikuje się.
- Istnieje positive rule. Sam status może dać co najwyżej PROBABLE według
  zwykłego resolvera, nie automatyczne FOUND.

To jawna, zachowawcza kwalifikacja techniczna definicji. Nie oznacza bieżącej
walidacji dostępności każdego endpointu. Obecny katalog ma **118 grup / 121
różnych alternatywnych endpointów** spełniających te warunki. Katalog nie jest
automatycznie rozszerzany o zewnętrznych dostawców indeksów.

## Wykonanie

403/BLOCKED, brak wymaganego klucza, PARSE_ERROR, UNSUPPORTED, SERVER_ERROR
lub potwierdzony HTTP 410 mogą uruchomić alternatywę. NOT_FOUND i 429 jej nie
uruchamiają. Timeout podlega ograniczonemu retry / circuit breaker;
nie dodano automatycznego fallbacku po każdym timeoutcie lub zwykłym UNKNOWN.

Jeden `_CanonicalWork` zachowuje task ID i wspólny budżet. Po błędzie primary
przechodzi do następnej dopuszczonej definicji, bez kopiowania sesji lub
nagłówków primary. Bounded scheduler daje kontynuacji fallback pierwszeństwo
przed buforem nowych primary. Bez tego mały budżet mógłby się wyczerpać, zanim
zaplanowana alternatywa dostałaby slot. Limity originu, globalnej równoległości,
liczby fallbacków i deadline nadal obowiązują.

Ostateczny wynik jest jeden. Jeśli alternatywa daje FOUND, PROBABLE lub NOT_FOUND,
staje się źródłem wyniku. Jeśli pozostaje nierozstrzygająca, zachowujemy blokadę
lub błąd primary. W DEBUG są niezależne `DefinitionObservation` z detection,
attempts, probe URL, rolą i block class. Lista attempts wyniku obejmuje cały
łańcuch, a metadane dotyczą wybranego źródła. ANALYST pokazuje `source: fallback`
bez powielania profilu. Żaden fallback nie podnosi verdictu bez dowodów.

Przykład kontrolny: primary JSON → 403/BLOCKED, public HTML → treść + binding →
FOUND. Koszt: jeden PRIMARY_CHECK i jeden FALLBACK_CHECK; jeden canonical result.
Przykład przeciwny: primary NOT_FOUND → zakończenie przy jednym żądaniu.

## Telemetria i zdrowie definicji

`request_economy` podaje fallback_attempted, success, not_found, blocked, error,
recovered_canonical_services i obserwowane klasy blokad. Success oznacza
FOUND/PROBABLE, a odzyskane rozstrzygnięcia obejmują również NOT_FOUND.
Nierozstrzygający fallback jest zaliczany do error, nie sukcesu.

`DefinitionHealth` zapisuje lokalnie w `definition-health.sqlite` obok journalu:
checks, successful_checks, blocked_responses, timeouts, parser_failures,
metadata_success. Klucz obejmuje revision i site ID; job/task chroni przed
podwójnym zliczeniem importu. Transakcje SQLite zabezpieczają równoległe CLI.
Checks to rozpoczęte próby; successful_checks oznacza wynik definicji
FOUND/PROBABLE/NOT_FOUND, a nie niezależnie potwierdzoną poprawność. Liczniki parsera obejmują
także błędy enrichment wybranego źródła.

**Ranking zdrowotny pozostaje wyłączony.** Zebrane próby są lokalne, zależne od
nicka, czasu i sieci. Nie awansujemy definicji po jednym sukcesie, ani po kilku
retry tej samej próby. Przed włączeniem rankingu trzeba ustalić dostateczną
liczbę niezależnych obserwacji i okno czasu; obecny kod nie wymyśla tych danych.

Nie wdrożono rozwiązywania CAPTCHA, przenoszenia sesji, podszywania się pod
przeglądarkę ani rotacji proxy. Ograniczenia pozostają obserwacjami w wyniku.
