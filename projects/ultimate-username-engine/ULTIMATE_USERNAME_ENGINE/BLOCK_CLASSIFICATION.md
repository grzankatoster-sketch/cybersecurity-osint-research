# Klasy blokad i awarii

| Dowód | Klasa / stan | Zachowanie |
|---|---|---|
| HTTP 403 | HTTP_403 / BLOCKED | Zachowanie obserwacji; ewentualny odrębny publiczny endpoint z registry. |
| HTTP 429 | HTTP_429 / RATE_LIMITED | Brak fallbacku; cooldown originu, najwyżej jeden retry przy zgodzie definicji i budżetu. |
| HTTP 401 albo rozpoznana ścieżka logowania | LOGIN_REQUIRED / BLOCKED | Brak próby logowania; dopuszczalny odrębny publiczny endpoint. |
| Rozpoznany marker challenge | CHALLENGE / BLOCKED | Bez interakcji z challenge; tylko odrębny publiczny endpoint, jeśli istnieje. |
| HTTP 410 | ENDPOINT_REMOVED | Sygnał problemu endpointu; fallback dopuszczalny, chyba że detekcja już zwróciła jednoznaczne NOT_FOUND. |
| Jawne credential_env bez wartości | API_REQUIRES_KEY / API_REQUIRED | SKIPPED_API_CREDENTIAL_REQUIRED; zero primary requests; możliwy publiczny fallback. |
| BLOCKED bez bardziej szczegółowego dowodu | UNKNOWN_BLOCK / BLOCKED | Nie dopisujemy domniemanej przyczyny. |
| Kolejne 403 / 429 / timeout / 5xx originu | DEGRADED, CIRCUIT_OPEN | Wstrzymanie następnych prób do upływu okna circuit breaker. |

Znany challenge lub login ma pierwszeństwo przed ogólną klasą statusu.
`http_403_responses` i `http_429_responses` w economy niezależnie liczą rzeczywiste
kody HTTP, również z enrichment. HTTP 403 nie dowodzi ograniczenia regionalnego,
a HTTP 451 sam nie wskazuje regionu. Dlatego REGION_UNAVAILABLE nie jest
przypisywany bez zweryfikowanego adaptera dostarczającego taki dowód.
404 nie oznacza automatycznie „usunięty endpoint” — może dotyczyć konta.

Cooldown 429: maksimum poprawnego Retry-After i skonfigurowanego minimum
(domyślnie 30 s). Obsługiwane są liczby i daty HTTP. Długi cooldown może skończyć
job deadline bez retry; zachowujemy RATE_LIMITED. Pozostałe originy mogą działać.
Retry wymaga wolnego globalnego slotu, retry budget i polityki definicji.
Pozostałe retry mają domyślnie co najmniej 1 s odstępu.

Circuit breaker jest lokalny dla jobu i originu: po 3 kolejnych niepowodzeniach
otwiera się na 60 s. Udana odpowiedź zeruje serię. Nie uruchamia dodatkowych
„health probe”; po wygaśnięciu zwykła oczekująca praca może spróbować ponownie.
Już rozpoczęte równoległe próby mogą dobiec końca, dlatego liczba odpowiedzi
ponad próg jest ograniczona concurrency, a nie zawsze dokładnie równa 3.

Klucz API: definicja może zawierać `credential_env`, `credential_header` i
`credential_prefix`. Wartość jest pobierana z ENV dopiero w pracy requestu.
Nie zapisujemy jej do wyników ani śladów. Nagłówki i nazwy ENV są walidowane;
wartości z CR/LF są odrzucane. Nagłówek nie przechodzi do fallbacku, a redirect
między originami zachowuje istniejącą listę bezpiecznych nagłówków.
Obecny katalog nie otrzymał żadnych kluczy ani automatycznych integracji płatnych.

Źródła indeksowe: jawne `discovery_only` oraz rozpoznane trasy wyszukiwania
Google/Bing/DuckDuckGo/Yahoo dostają `INDEX_EVIDENCE`. Ich verdict pozostaje
UNKNOWN; w ANALYST sprawdzony wynik OK ma etykietę DISCOVERY_ONLY. Nie wykonujemy
automatycznie linków ze strony wyszukiwarki. Lista rozpoznawanych hostów jest
wąska; inne źródło indeksowe wymaga jawnego oznaczenia definicji.
