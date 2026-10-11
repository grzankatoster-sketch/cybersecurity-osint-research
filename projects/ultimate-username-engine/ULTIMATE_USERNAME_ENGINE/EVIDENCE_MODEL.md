# Model dowodów detekcji — 2026-10-09

Wynik potwierdza publiczny profil o podanym nicku. Nie potwierdza tożsamości osoby ani tego, że konta z kilku platform należą do tej samej osoby.

## Kolejność i warunki

`TransportResponse → response_quality / classify_response → reguły detekcji → owner binding → enrichment → eksport`

Istniejący failure gate został rozszerzony. Nowy moduł `response_quality.py` dostarcza również ograniczone do konkretnych endpointów parsery profili. Nie wykonuje żądań HTTP ani JavaScript.

1. Błędy transportu, niepełna odpowiedź, 401/403/429/5xx, challenge i logowanie uniemożliwiają pozytywny wynik. `verdict=UNKNOWN` współistnieje ze stanem wykonania, np. `BLOCKED`.
2. Strona ogólna, wyszukiwanie, przekierowanie do homepage/parkingu i niewłaściwy właściciel nie są profilami. Klasa odpowiedzi jest osobnym polem `response_class`; nie należy sumować jej z verdictami jak rozłącznych kategorii.
3. Wąskie parsery zweryfikowanych endpointów wymagają zgodnego adresu żądania i odpowiedzi, HTTP 200, kompletnego body oraz danych właściciela. Są świadomą korektą słabych reguł donorów. Nie skanują rekurencyjnie dowolnych obiektów JSON w poszukiwaniu pasującego nicku.
4. Dla pozostałych definicji konflikt positive/negative daje `UNKNOWN`. Zadeklarowany, ale niespełniony binding blokuje pozytywny wynik. Pozytywny dowód treści i spełniony binding pozwalają uzyskać `FOUND`.
5. `PROBABLE` wymaga pozytywnej reguły oraz sygnału profilu: zgodnego root username/login i pola profilu w JSON albo pozytywnego message/regex wskazującego profile/member/player/nickname/account. To nadal heurystyka wymagająca weryfikacji. Sam HTTP 200 ani samo niewystąpienie komunikatu błędu nie wystarczają.
6. Dowód nieistnienia zachowuje `NOT_FOUND` tylko przy treści negatywnej lub zweryfikowanej regule negatywnej. Odrzucone kandydatury nie są automatycznie zamieniane w nieistniejące konta.

## Jawne poziomy

| Poziom | Strength | Znaczenie i wynik |
| --- | --- | --- |
| 4 | STRONG | Obiekt profilu, username, identyfikator konta i zgodny endpoint; FOUND |
| 3 | STRONG | Treść profilu i jawny binding; FOUND. Pinterest: author URL + poprawny oEmbed profilu, bez account ID |
| 2 | MODERATE | Sygnał profilu bez mocnego bindingu; PROBABLE |
| 1 | WEAK | Słaba reguła pozytywna bez sygnału profilu; UNKNOWN |
| 0 | INSUFFICIENT | Brak dowodu, konflikt, blokada albo odpowiedź niebędąca profilem |

`confidence.value` pozostaje `null`. Strength i evidence_level opisują kryteria, nie prawdopodobieństwo. Dla legacy negatywów zachowano `COMPOSITE`; ich poziom 0 nie mierzy pewności nieistnienia. Błędy mogą zachować starszy komunikat o braku modelu — żaden model ML nie został dodany.

Dotychczasowe reguły content + binding otrzymują poziom 3 również wtedy, gdy mają dodatkowy identyfikator konta, jak adapter GitHub. Poziom 4 nadają nowe, jawnie obsługiwane parsery obiektów profilu. Nie należy traktować tej liczby jako porównawczej oceny wiarygodności platform.

## Zakres parserów

| Serwis | Dowód wiążący profil | Dodatkowe ograniczenie |
| --- | --- | --- |
| GitHub | login + dodatni ID + html_url | Dotychczasowy zweryfikowany adapter GitHub |
| Kick | slug + user.username + user.id = user_id | Dodatni int; channel ID nie jest user ID |
| Chess | username + player_id + @id + public URL | Casefold wyłącznie dla obsługiwanego endpointu |
| FACEIT | result=OK + payload.nickname + payload.id | ID o formacie UUID |
| GOG | jawny window.profilesData.profileUser + username + userId | JSONDecoder bez wykonywania JS; dodatni numeryczny ID, maks. 32 znaki |
| Pinterest | author_url + provider + type + author_name + iframe grid | Wyłącznie oficjalny oEmbed wskazujący dokładnie profil; poziom 3 |

Znaczniki Anubis wymagają struktury skryptu challenge i odpowiedniego tytułu. Sam artykuł o Anubis nie jest blokadą. WAF może sygnalizować challenge nagłówkiem, nawet przy pustym body HTTP 202. Link „login” w menu nie wystarcza do klasyfikacji strony jako logowania.

## Metadane i obrazy

Enrichment ponownie sprawdza klasę odpowiedzi i binding. Pola są pobierane z właściwego obiektu profilu, z provenance i oceną jakości. Sprzeczne pola nie trafiają do zestawu użytecznych danych. Metadane serwisu, Organization, podgląd OG i treść innego użytkownika nie są danymi właściciela profilu.

`VERIFIED_PROFILE_IMAGES.json` zawiera wyłącznie powiązane z potwierdzonymi profilami URL-e. GOG może używać predefiniowanego tła; avatar może być domyślny. Nie wykonano pobierania obrazów, rozpoznawania twarzy ani ustalania tożsamości osoby.

## Punktacja i utrzymanie definicji

Runtime `technical_quality`, zwracający SiteQualityScore, obniża punktację definicji status-only o 25, premiuje obsługiwany endpoint z bindingiem o 30 i odejmuje 20 za jawny NEEDS_RULE_FIX. To strukturalne kryteria; nie są historycznym wskaźnikiem błędów ani miarą popularności.

Wersjonowana nakładka `detection-quality-v1` oznacza 10 definicji z 7 serwisów jako NEEDS_RULE_FIX i wyłącza 4 definicje 2 parkingów jako QUARANTINE. Pełna lista: `artifacts/detection-quality/definition-overlays.json`. Powodem są rozpoznane treści i błędne trasy profili, a nie pojedynczy timeout. Serwisy blokujące boty nie są z tego powodu objęte kwarantanną. Donor, oryginalny katalog i wcześniejsza kwarantanna Twitch pozostają zachowane. Powrót z kwarantanny wymaga poprawnej trasy i testów profilu oraz kontroli negatywnej.

Klasyfikator obejmuje rozpoznane wzorce, nie wszystkie strony internetu. Testy kalibracyjne nie stanowią dowodu globalnej precision ani recall.
