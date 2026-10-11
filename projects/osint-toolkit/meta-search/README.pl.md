# meta-search

Wyszukiwanie w serwisach Meta przez **oficjalne API**, ze wspólnym kontraktem wyniku. Etap 1: Threads. Etap 2: Instagram Business Discovery i Strony Facebooka (Graph API). Zero zależności (stdlib).

```
py -3 -m meta_search config                          # stan konfiguracji (bez wartości tokenu)
py -3 -m meta_search threads-profile meta --json w.json --html w.html
py -3 -m meta_search threads-search "osint" --type RECENT --limit 25 [--author nick]
py -3 -m meta_search instagram-profile natgeo --media 5 --json w.json   # konto profesjonalne IG
py -3 -m meta_search facebook-page natgeo --html w.html                  # publiczne dane Strony FB (id lub nazwa)
py -3 -m meta_search purge ../panel/wyniki --days 30 [--delete]   # retencja: stare meta_*.json/.html (bez --delete podgląd)
py -3 -m meta_search links natgeo                    # linki do ręcznego sprawdzenia, nic nie pobiera
```
(z katalogu `meta-search`, `PYTHONPATH=src`; w panelu: zakładka Meta)

## Konfiguracja

Zmienne środowiskowe albo plik `~/.osint/meta.env` (inna ścieżka: `META_SEARCH_ENV_FILE`; środowisko wygrywa z plikiem; plik w repozytorium jest odrzucany):

| Źródło | Klucze | Uwagi |
|---|---|---|
| Threads | `THREADS_ACCESS_TOKEN`, `THREADS_API_VERSION` (domyślnie `v1.0`) | uprawnienia `threads_basic` + `threads_profile_discovery` (profil) / `threads_keyword_search` (posty) |
| Instagram | `INSTAGRAM_ACCESS_TOKEN`, `INSTAGRAM_USER_ID` | token (Facebook Login) i numer konta profesjonalnego WŁAŚCICIELA tokenu; `instagram_basic` + `instagram_manage_insights` + `pages_read_engagement` (referencja business_discovery, 04.10.2026; `ads_read`, gdy rolę na Stronie nadano przez portfolio firmowe); `pages_show_list` do znalezienia numeru konta |
| Strony Facebooka | `FACEBOOK_ACCESS_TOKEN` | cudze Strony: funkcja aplikacji Page Public Content Access / Page Public Metadata Access po App Review |
| sieć | `META_PROXY` (`http(s)://[login:hasło@]host:port`), `META_REQUIRE_PROXY=1` | panel ustawia fail-closed: przy tokenie i braku proxy nie ma ruchu bezpośredniego; martwe lub błędne proxy = zero ruchu; jawne `META_PROXY` wygrywa z `NO_PROXY`/`no_proxy` (także `*`), wyjątkami systemowymi i zmiennymi `*_PROXY`; tylko HTTPS (tunel CONNECT); socks/Tor celowo nieobsługiwane: token i tak identyfikuje konto u Meta, a zmienne IP grozi blokadą tokenu. Alternatywa: VPN systemowy |
| wspólne | `GRAPH_API_VERSION` (domyślnie `v26.0`, graph.facebook.com) | najnowsza wg changelogu Meta (29.07.2026) |

`py -3 -m meta_search config` pokazuje, które źródła są skonfigurowane (bez wartości tokenów i numeru konta).

## Ograniczenia API (dokumentacja Meta, 03.10.2026)

- `profile_lookup`: tylko publiczne profile z ≥100 obserwującymi; bez zaawansowanego dostępu (App Review) tylko konta Meta; 1000 zapytań/24 h.
- `keyword_search`: bez zatwierdzonego `threads_keyword_search` tylko posty właściciela tokenu; 2200 zapytań/24 h; jedna strona (≤100), kolejnych nie pobieramy.
- Kody błędów mapowane wg ogólnej konwencji Graph API. Niejednoznaczne błędy (m.in. 100/110/24/803) dają `source_error` i niezerowy kod wyjścia. Nie są traktowane jako poprawne wyszukiwanie bez wyników.

- `instagram-profile` (Business Discovery): tylko konta profesjonalne; konta prywatne i osobiste są niewidoczne. Media: `--media 0-50`, jedna strona.
- `facebook-page`: tylko Strony po id lub nazwie; odpowiedź bez `category`/`fan_count` jest odrzucana. Szukanie Stron po frazie (`/pages/search`) nie jest zaimplementowane - wymagania niepotwierdzone.
- Przegląd 04.10.2026: testy na atrapach transportu i lokalnych podprocesach. W tym przeglądzie nie wykonano autoryzowanych wywołań żadnego z trzech API. Limity, pola oraz uprawnienia wymagają potwierdzenia przy uruchomieniu własnej aplikacji Meta.

## Kontrakt wyniku (`--json`)

`tool`, `schema`, `platform`, `operation`, `query`, `status`, `source{kind: api|html_heuristic|manual, endpoint, api_version}`, `fetched_at`, `items`, `message`, `caveats`, `http_status`, `error_code`.
Statusy: `found`, `no_result` (nie dowodzi braku konta), `not_configured`, `auth_error`, `permission_denied`, `rate_limited`, `source_error`, `invalid_input`, `manual`. Kod wyjścia: 0 / 1 błąd źródła / 2 zapytanie / 3 konfiguracja / 4 token-uprawnienia / 5 limit.
Token nie trafia do wyniku, raportu ani terminala (redakcja `access_token=`); brak automatycznego scrapowania po błędzie API.

Import do grafu: `entity-graph` rozpoznaje plik JSON (profil Threads/Instagram → `has_account`, post/media → `authored`, Strona Facebooka → organizacja + URL, relacja `has_page`; z pochodzeniem i czasem pobrania; bez treści postów, bio i opisu Strony).

Wspólna część klientów (transport bez przekierowań, limit rozmiaru, redakcja tokenu, klasyfikacja błędów) jest w `graph.py`; `threads.py`, `instagram.py`, `facebook_pages.py` to cienkie klasy na tym samym `MetaResult`.

Testy (bez sieci, fałszywy transport): `py -3 -m pytest -q`
