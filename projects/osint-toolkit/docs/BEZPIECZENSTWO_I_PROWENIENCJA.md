# Bezpieczeństwo i proweniencja w pipeline OSINT

Stan na 2026-10-05, gałąź `lab/wdrozenie-2026-10-03`, HEAD `4ef32db`. Dokument dla analityka/audytora (co narzędzie robi, czego nie robi, skąd wiadomo, że wynik jest wiarygodny) i dla dewelopera (gdzie w kodzie leży dana zasada). Opisuje stan **kodu zacommitowanego**; rzeczy niezacommitowane (np. asystent sprawy w `entity-graph`) są poza zakresem. **To nie jest opinia prawna** (patrz sekcja 3).

Dane w przykładach są wyłącznie syntetyczne (`example.test`, `Example Sp. z o.o.`, `Jan Kowalski`, `DemoBreach`). Dokument nie zawiera żadnych wartości haseł, tokenów ani kluczy.

## Spis treści

1. [Pipeline](#1-pipeline)
2. [Źródła danych](#2-źródła-danych)
3. [Granice legalnego użycia](#3-granice-legalnego-użycia)
4. [Metadane incydentu a surowy wyciek](#4-metadane-incydentu-a-surowy-wyciek)
5. [Proweniencja](#5-proweniencja)
6. [Tryb offline i online](#6-tryb-offline-i-online)
7. [Kody wyjścia](#7-kody-wyjścia)
8. [Fail-closed](#8-fail-closed)
9. [Raportowanie i dziennik audytu](#9-raportowanie-i-dziennik-audytu)
10. [Ograniczenia HIBP](#10-ograniczenia-hibp)
11. [Nieprzechowywanie haseł i tokenów](#11-nieprzechowywanie-haseł-i-tokenów)
12. [Odłożone tematy i znane ograniczenia](#12-odłożone-tematy-i-znane-ograniczenia)
13. [Rozbieżności kod–dokumentacja zauważone przy pisaniu](#13-rozbieżności-koddokumentacja-zauważone-przy-pisaniu)

---

## 1. Pipeline

```
 oficjalne rejestry                      publiczny katalog HIBP
 (KRS, CEIDG, REGON/GUS)                 (GET /api/v3/breaches, bez klucza)
        |                                        |
        v                                        v
 adapter osint-poland                     org-intel fetch-hibp-catalog
 (org_intel_feed.py;                      albo hibp-monitor breaches --catalog --json
  konektory KRS/CEIDG,                    (metadane incydentów; jedyny kontakt z HIBP)
  wynik REGON z pliku)                           |
        |  plik wejściowy org-intel              |
        +------------------+---------------------+
                           v
                    org-intel  (ingest -> store.json; export --format json)
                    firmy, domeny, incydenty, źródła, obserwacje
                    strażnicy: proweniencja, zero wycieków, zero sekretów
                           |  eksport JSON albo store.json
                           v
                    entity-graph import-org-intel  (--dry-run / --strict / --report)
                    teczka sprawy: graph.json + audit.jsonl (łańcuch skrótów)
                           |
                           v
                    eksport: graph.graphml, report.html,
                             maltego.csv  (albo eg export --maltego PLIK)
                           |
                           v
                    CI: ci/run_checks.py + .github/workflows/osint-pipeline.yml
                    (zero sieci, zero sekretów, dane syntetyczne, E2E całego łańcucha)
```

Zasady przekrojowe:

* Pakiety **nie importują się nawzajem**. Strażnicy i normalizacja są kopiowane (`entity-graph/.../importers/org_intel.py` kopiuje `org-intel/guards.py`, `quality.py` i listę rejestrów z adaptera) i w importerze **wzmacniane**. Skutek: każdy etap waliduje wejście niezależnie od poprzedniego (nie ufa mu).
* Kierunek jest jednostronny: dane płyną w dół. `entity-graph` nie wywołuje sieci w imporcie org-intel; `org-intel` nie zna `entity-graph`.
* Osoby fizyczne **nie wchodzą do grafu** przez ten import (sekcja 3).

## 2. Źródła danych

Typ źródła w org-intel (`source_type`) jest ograniczony enumem. Importer `entity-graph` dodatkowo wymaga, żeby **host adresu pasował do typu** (allowlisty w `HostRules`; typ bez reguły jest odrzucany). Hosty pasują dokładnie albo jako subdomeny wpisu.

| Typ źródła | Przykład hosta | Co przechowujemy | Jakość bazowa (importer) |
|---|---|---|---|
| `official_registry`: KRS | `api-krs.ms.gov.pl` (także `ekrs.ms.gov.pl`, `prs.ms.gov.pl`) | nazwa prawna, KRS, NIP, REGON, status, adres siedziby osoby prawnej, dawne nazwy (odpis pełny), `retrieved_at`, sha256 odpowiedzi | high |
| `official_registry`: CEIDG | `dane.biznes.gov.pl` (także `biznes.gov.pl/ceidg`) | wyłącznie z flagą `--include-sole-proprietors`: nazwa firmy, NIP, REGON, status; **bez adresu**; dostęp przez token operatora (zmienna środowiskowa, nie plik, nie argument) | high |
| `official_registry`: REGON/GUS | `wyszukiwarkaregon.stat.gov.pl`, `api.stat.gov.pl` | to samo co KRS; adres tylko dla typu P (osoba prawna). W tym repo wynik GUS wchodzi **z pliku** (`--input`), nie z sieci | high |
| `official_registry`: inne | `wl-api.mf.gov.pl` | dozwolony host w allowliście (biała lista VAT); w HEAD brak konektora w adapterze | high |
| `company_website` | domena oficjalna organizacji z tego samego importu | dowód obecności faktu na stronie firmy (adres, skrót), nie treść strony | low w imporcie (domena z niezaufanego pliku), high w org-intel |
| `cert_advisory` | `cert.pl`, `cert.europa.eu`, `enisa.europa.eu` (kategoria `cert`); `nask.pl` (`nask`); `csirt.gov.pl`, `gov.pl` (`csirt`); domena organizacji (`vendor_advisory`) | adres komunikatu jako dowód incydentu; opis incydentu bez HTML | high (`vendor_advisory`: low) |
| `official_document` | `*.gov.pl`, `*.europa.eu` albo domena organizacji | adres dokumentu, jego skrót | medium (high dla hostów urzędowych; low, gdy uznane tylko przez domenę z pliku) |
| `hibp_catalog` | `haveibeenpwned.com`, `api.haveibeenpwned.com` | **tylko metadane** incydentu (sekcja 4) | medium; incydent bez flagi `verified` ma obserwację low |
| `ct_log` | `crt.sh`, `ct.googleapis.com` i inne znane logi CT | dowód istnienia certyfikatu/domeny | medium |
| `passive_dns` | dowolny host publiczny | dowód powiązania domena–zasób | low |
| `manual` | dowolny host publiczny | wpis ręczny operatora | low |

Wspólne blokady hostów (dotyczą `url` źródła i `evidence_url`): adresy IP w każdej postaci (także dziesiętne i szesnastkowe), `localhost`, `*.local`, `*.internal`, sieci ukryte (`.onion`, `.i2p`), hosty bez kropki, znane fora i rynki z wyciekami oraz serwisy paste i komunikatory (host, subdomeny, słowa w nazwie hosta). Przyjmowany jest wyłącznie HTTPS na porcie 443; adres z danymi logowania lub znakiem `@` (także zakodowanym jednokrotnie i dwukrotnie) odrzuca rekord, a nie jest po cichu „czyszczony”.

Jakość źródła = minimum z bazy typu i zadeklarowanej `reliability`. Źródło uznane **wyłącznie** dlatego, że jego host to `official_domain` z tego samego niezaufanego pliku, ma jakość najwyżej low (plik mógł wskazać dowolną domenę, np. hosting współdzielony).

Źródeł **nie ma** i nie będzie w tym pipeline: dumpy, combolisty, stealer logi, kanały komunikatorów i paste, fora z wyciekami, serwisy sprzedające treść wycieków.

## 3. Granice legalnego użycia

**Dopuszczalny cel:** weryfikacja kontrahenta i due diligence na podstawie danych publicznych; bezpieczeństwo **własnej** organizacji (własne domeny, historia publicznych incydentów firmy); autoryzowane badania na zlecenie z jasnym celem i podstawą. Narzędzie wymaga jawnego celu (`--purpose`, min. 2 słowa i 12 znaków) i zapisuje go w dzienniku audytu.

**Czego pipeline NIE robi** (i w większości nie ma na to typów danych ani kodu):

* nie wyszukuje osób w wyciekach i nie łączy adresu e-mail, loginu ani numeru telefonu z osobą (brak relacji e-mail → osoba i osoba → incydent; incydent łączy się wyłącznie z domeną/organizacją);
* nie enumeruje kont w serwisach (sondowanie rejestracji/resetu hasła), nie wykonuje credential stuffingu ani żadnego testowania haseł przy logowaniu;
* nie pobiera, nie kupuje i nie indeksuje zrzutów (fora, komunikatory, paste, combolisty), także „tylko do weryfikacji”;
* nie scrapuje wyszukiwarek, prywatnych ani nieoficjalnych API; jedyna automatyczna wyszukiwarka to oficjalne Brave Search API z kluczem operatora (`eg szukaj-profili`);
* nie obchodzi zabezpieczeń: bez logowania do serwisów, bez rozwiązywania CAPTCHA, bez **rotacji IP** po blokadzie, bez **podrabiania odcisku przeglądarki** (stały, uczciwy User-Agent; dopuszczalne jest wyłącznie jedno stałe proxy chroniące operatora, w trybie fail-closed, sekcja 8);
* nie ustala tożsamości: trafienie to trop, nie dowód (wyniki wyszukiwania profili są hipotezami do decyzji operatora).

**Osoby fizyczne poza grafem importu:** `import-org-intel` pomija osoby w całości (żadnych węzłów Person/Email/Username/Phone, twarda asercja i testy; także publiczne osoby z rejestru). Adapter rejestrów pomija claimy o osobach (zarząd, wspólnicy, prokurenci, beneficjenci), a jednoosobowe działalności (CEIDG, REGON typu F) tylko na jawną flagę i bez adresu. Adres siedziby jest przyjmowany wyłącznie dla osób prawnych / jednostek z KRS ze źródła rejestrowego. W samym `org-intel` osoba publiczna jest dopuszczalna tylko ze źródła first-party/official, a jej e-mail tylko przy podwójnym potwierdzeniu (sekcja 5); eksport maskuje e-maile domyślnie.

**Minimalizacja:** zapisywane są tylko pola z listy dozwolonych; cytat dowodu jest zapisywany jako sha256 (tekst tylko w jawnym `--audit-mode`); `notes` źródeł i obserwacji nie trafiają do grafu; e-maile w polach tekstowych są zastępowane znacznikiem (sekcja 9).

**To nie jest opinia prawna.** Przed wdrożeniem produkcyjnym lub zmianą granic wymagana jest konsultacja z prawnikiem. Ryzyka do skonsultowania:

* RODO art. 6 (podstawa przetwarzania) i art. 14 (obowiązek informacyjny przy danych niepozyskanych od osoby), także dla danych „publicznych” z rejestrów: publiczność nie zastępuje podstawy ani celu;
* dane osobowe z wycieków i ich ewentualne łączenie z osobami (RODO art. 9 przy danych szczególnych; odpowiedzialność karna za przetwarzanie bez uprawnienia i ujawnianie informacji uzyskanych bezprawnie): dlatego pipeline w ogóle ich nie przetwarza;
* regulaminy i warunki użycia API źródeł (CEIDG, Brave, HIBP: m.in. atrybucja CC BY 4.0 i zakaz zapytań w celu szkodzenia ofiarom wycieków);
* retencja: graf i dziennik zawierają to, co operator wpisał jako cel i wejścia; usuń sprawę po zakończeniu badania (usunięcie katalogu sprawy usuwa też dziennik);
* oferowanie wyników klientom SaaS (inny reżim niż użycie własne).

## 4. Metadane incydentu a surowy wyciek

Z publicznego katalogu HIBP (`/api/v3/breaches`, bez klucza) pipeline przyjmuje wyłącznie **opis zdarzenia**:

| W katalogu (dozwolone pola) | Uwagi |
|---|---|
| nazwa (`Name`), tytuł (`Title`), domena serwisu (`Domain`) | domena serwisu będącego źródłem incydentu |
| daty: `BreachDate`, `AddedDate`, `ModifiedDate` | `ModifiedDate` tylko w notatce obserwacji |
| liczba kont (`PwnCount`) | liczba, nie lista |
| klasy danych (`DataClasses`) | etykiety, np. „Email addresses”; etykieta „Passwords” **nie** oznacza obecności haseł w repo |
| opis (`Description`) | HTML usunięty, adresy e-mail zamaskowane, maks. 2000 znaków |
| flagi: verified, fabricated, sensitive, retired, spam list, malware, stealer log | flaga to tylko jawna prawda (`true`/`1`); tekst „false” nią nie jest |

Pola spoza listy (np. logo, atrybucja) są ignorowane. **Rekord zawierający pole kont, adresów, haseł lub sekretów jest odrzucany w całości**, reszta importu trwa.

**Czego NIGDY nie ma w repo ani w magazynie/grafie/eksportach:** adresów e-mail kont z wycieków, haseł, hashy haseł, tokenów i kluczy, rekordów kont, stealer logów (par domena–konto), list „kto jest w wycieku”. Dotyczy to też cache katalogu HIBP (zapisywana jest odpowiedź już zminimalizowana, surowa nie) i trybu audytowego (tylko dozwolone pola).

Dlaczego tak (model HIBP, patrz `AUDYT_HIBP_POZYSKIWANIE_WYCIEKOW_2026-10-05.md`): HIBP działa legalnie i etycznie dzięki minimalizacji (przy adresie trzyma tylko nazwy wycieków), weryfikacji źródeł, ujawnianiu wobec firm, opt-outowi właściciela adresu, bramkom własności domeny przy wyszukiwaniu zbiorczym i partnerom instytucjonalnym (CERT, organy ścigania). Własna baza zrzutów nie ma żadnej z tych cech, a jej jedynym zastosowaniem byłoby wyszukiwanie innych ludzi. Katalog metadanych daje to, co użyteczne dla analizy firmy (czy domena/organizacja miała publicznie opisany incydent, kiedy, jak duży, jakie klasy danych), bez danych osobowych.

Pozostałe funkcje HIBP są **poza** pipeline'em: wyszukiwanie po adresie e-mail, wyszukiwanie zbiorcze po domenie, paste i stealer logs. W kodzie występują tylko w `hibp-monitor` (opcjonalnie, płatne: klucz i zweryfikowana własność domeny; sekcja 6); testy statyczne pilnują, że endpointów tych funkcji nie ma w `org-intel`.

## 5. Proweniencja

Każda zapisana informacja ma przynajmniej jedno źródło i obserwację. Pola (w grafie `provenance` w atrybutach węzła; w org-intel jako `Source` + `Observation`):

| Pole | Znaczenie |
|---|---|
| `source_url_original` | adres w postaci zapisanej przez org-intel (org-intel normalizuje już przy zapisie: bez fragmentu, `utm_*`, końcowego `/`), więc to nie jest wejście sprzed `org-intel ingest` |
| `source_url_normalized` | klucz entity-graph (bez schematu i `www.`); służy wyłącznie do deduplikacji i identyfikacji węzła źródła |
| `source_type`, `source_category` | typ z org-intel i kategoria importera (`SOURCE_TYPE_TABLE`: np. `official_registry`, `official_company`, `cert`, `nask`, `csirt`, `vendor_advisory`, `public_report`, `hibp_catalog`) |
| `retrieved_at` | czas pobrania źródła (ISO 8601; musi być prawdziwą datą, od 1990 r., nie później niż doba po czasie importu) |
| `confidence` | high/medium/low; w krawędziach grafu liczbowo 0,9 / 0,6 / 0,3, dla `inferred` najwyżej 0,6 |
| `derivation` | `direct` (fakt wprost ze źródła) albo `inferred` (wniosek, np. incydent na subdomenie przypisany domenie nadrzędnej, domena dopasowana po nazwie firmy) |
| `evidence_hash` | sha256 dowodu (w org-intel także `content_hash` źródła = sha256 odpowiedzi serwera; cytat zapisywany tylko jako skrót) |
| `quality` | jakość źródła = min(baza typu, `reliability`) |
| `import_id` | `imp_` + 12 znaków sha256 (skrót pliku + czas importu); w raporcie, w obu wpisach audytu i w każdym nowo wnoszonym wpisie proweniencji |

Zasady:

* **Bez źródła = odrzucenie.** Rekord bez `source_ids`, ze wskazaniem nieistniejącego źródła, bez obserwacji albo bez `derivation`/`confidence`/`reliability`/`verification_status` (importer entity-graph **nie ma wartości domyślnych**; wielkość liter ma znaczenie), a także źródło bez nazwy, typu, adresu http(s) lub `retrieved_at`, jest odrzucane z powodem. Literówka w kluczu źródła nie może po cichu zgubić proweniencji.
* **Słabsze nie nadpisuje lepszego.** Pierwsza niepusta wartość wygrywa; `verification_status`: verified > pending > unverified > failed (`failed` nie cofa `verified`); `affected_accounts_count` = maksimum; flagi `is_*` łączone przez OR; pewność krawędzi = maksimum; wpis proweniencji z wyższą pewnością zastępuje starszy razem z jego `import_id`. Sprzeczne identyfikatory (ten sam KRS, inny NIP) odrzucają późniejszy rekord. Adres siedziby: pierwsza wartość wygrywa, różnica to ostrzeżenie.
* **Idempotencja.** Ponowny import tego samego pliku (także pod inną nazwą) nie zmienia węzłów, krawędzi ani atrybutów; wpis proweniencji zachowuje `import_id` pierwszego importu. Raport pokazuje „bez zmian”, a pliki sprawy nie są przepisywane (test E2E sprawdza bajtową identyczność `graph.json`, GraphML, CSV i HTML). W org-intel źródła scalane są po znormalizowanym URL: zostaje pierwsze źródło, każde kolejne pobranie to nowa obserwacja z nowszym `observed_at`.
* **Osoby publiczne w org-intel:** tylko ze źródła `official_registry`, `company_website` albo `official_document`; **e-mail osoby** zapisywany tylko, gdy źródło e-maila jest first-party/official **oraz** domena adresu to domena oficjalna organizacji (lub jej subdomena) albo adres występuje dosłownie w cytacie dowodu. W przeciwnym razie osoba zostaje bez e-maila, z adnotacją o odrzuceniu.
* **Kolizja URL źródła (fail-closed).** Jeśli w grafie sprawy istnieje węzeł o tym samym id z `kind` innym niż `source` (profil, gravatar), źródło jest odrzucane; `has_source` nigdy nie wskazuje węzła o innym `kind`. Podobnie kolizja klucza Organization (tytuł incydentu równy nazwie firmy) odrzuca rekord zamiast scalać atrybuty.
* **Brak tekstu dowodowego w grafie:** `notes` źródeł i obserwacji nie są zapisywane; cytaty wyłącznie jako sha256.

## 6. Tryb offline i online

**Offline jest domyślny** w każdym kroku pipeline'u. Polecenie sieciowe `org-intel` bez `--online` kończy się kodem 2 bez żadnego ruchu; adapter rejestrów domyślnie czyta wynik konektora z pliku (`--input`); `entity-graph import-org-intel` w ogóle nie ma trybu sieciowego; CI blokuje sieć podwójnie (podmiana funkcji gniazd w procesie testu i `sitecustomize` w każdym podprocesie; po każdym teście dziennik prób połączeń musi być pusty).

Tryb `--online` (jawny, per polecenie):

| Narzędzie | Co robi online | User-Agent | Timeout | Rate limit | Cache |
|---|---|---|---|---|---|
| `org-intel fetch-hibp-catalog --online` | publiczny `GET /api/v3/breaches`, **bez klucza** (polecenie nie ma opcji klucza, zmienna klucza nie jest czytana) | wymagany `--user-agent` (brak = kod 2) | 30 s | min. 1,6 s między zapytaniami; 429 z `Retry-After` (maks. 3 próby, czekanie do 120 s) | na dysku obok magazynu, TTL 24 h, `--refresh` pomija; limit odpowiedzi 20 MB; zapisywana odpowiedź zminimalizowana |
| `org-intel verify-domain --check --online` | sprawdzenie rekordu TXT przez DNS-over-HTTPS (jeden dostawca) | wg klienta `http.py` | wg klienta | brak własnego | brak; błąd sieci nie zmienia statusu domeny |
| adapter `osint_poland.org_intel_feed --online --krs ...` | istniejące konektory KRS (odpis aktualny i pełny) i CEIDG (po NIP, tylko z `--include-sole-proprietors`, token w zmiennej środowiskowej) | konektory KRS/CEIDG nie ustawiają własnego nagłówka (domyślny klienta HTTP); patrz sekcja 13 | 20 s na zapytanie | przerwa min. 1 s między zapytaniami | brak |
| `entity-graph szukaj-profili` | oficjalne Brave Search API (klucz operatora), wyłącznie przez kanał fail-closed (sekcja 8) | stały, uczciwy | twardy czas przebiegu 60 s domyślnie (maks. 120 s) | limity wywołań 6 domyślnie (maks. 12); klient HTTP ma limit szybkości na host | brak; pełne odpowiedzi nie są zapisywane |
| `hibp-monitor breaches` | `/breaches?domain=` lub pełny katalog (`--catalog`) | wymagany (`config.toml` albo `--user-agent`) | wg klienta | 1,6 s między domenami; 429 jak wyżej | stan w `state.json` (znane wycieki), nie cache odpowiedzi |

**Płatne endpointy HIBP** (wyszukiwanie zbiorcze po domenie, `domain-search`) istnieją wyłącznie w `hibp-monitor`, za kluczem w zmiennej `HIBP_API_KEY` (nigdy z pliku ani argumentu CLI) i **tylko dla domeny zweryfikowanej na koncie HIBP właściciela**. Bez klucza: czytelny komunikat i zero ruchu. Klucz jest wysyłany wyłącznie do `https://haveibeenpwned.com` (port 443, przekierowania odrzucane) i nie trafia do komunikatów ani wyjścia. Adresy w wyniku tylko z jawnym `--show-addresses`. Nie było to testowane na żywo (sekcja 10).

## 7. Kody wyjścia

| Narzędzie | 0 | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|
| `org-intel` (`ingest`, `search-company`, `export`, `verify-domain`, `fetch-hibp-catalog`) | OK | nie używany | błąd użycia/konfiguracji: składnia, nieczytelny plik, brak User-Agent, nieznana domena, polecenie sieciowe bez `--online` | błąd sieci/API | `ingest` zapisał poprawne rekordy, część odrzucono | nie używany |
| adapter `osint_poland.org_intel_feed` | OK | nie używany | błąd użycia/pliku (także istniejący plik wyjściowy; wynik zapisywany tylko do nowego pliku) | sieć/konektor, nic nie zapisano | część rekordów odrzucona, reszta zapisana | `--strict` i jakiekolwiek odrzucenie: plik wyjściowy nie powstaje (raport tylko na jawne `--report`) |
| `entity-graph import-org-intel` | wszystkie rekordy przyjęte (także gdy nic się nie zmieniło) | nie używany | błąd użycia/pliku: zły plik, CSV, nierozpoznany format lub wersja schematu, sprzeczne `--json`/`--format`, zła ścieżka `--report`, uszkodzony dziennik audytu; nic nie zapisano | nie używany | część rekordów odrzucona, reszta zaimportowana (także w `--dry-run`) | `--strict`: odmowa, nic nie zapisano, brak wpisu w dzienniku |
| `entity-graph export --maltego` (i `--graphml`, `--html`) | OK | nie używany | naruszenie zasad zapisu: istniejący plik bez `--force`, nazwa pliku sprawy, plik wejściowy, cudzy plik tymczasowy, brak katalogu | nie używany | nie używany | nie używany |
| `entity-graph szukaj-profili` | OK | co najmniej jedno zapytanie zakończone ERROR (brak autoryzacji, limit dostawcy, timeout, `proxy_down` w trakcie, uszkodzona odpowiedź); wyniki częściowe zostają w sprawie | naruszenie zasad: nieznana osoba bez `--dodaj`, zła nazwa, limity spoza zakresu | brak/błąd konfiguracji, **proxy wymagane i niedostępne**, SOCKS bez proxy HTTP, brak klucza: **zero ruchu, sprawa bez zmian** | nie używany | nie używany |
| `ci/run_checks.py` | wszystkie kroki OK | testy albo kontrole nieudane, także trafienie skanera artefaktów | błąd użycia/środowiska: nieznany krok, brak pytest/ruff/zależności, Python < 3.12 | nie używany | nie używany | nie używany |
| `hibp-monitor` | OK | nie używany | błąd użycia/konfiguracji/brak klucza | błąd sieci lub API | nie używany | nie używany |

`entity-graph audit-verify` i `evidence-verify`: 0 przy spójnym łańcuchu/skarbcu, 1 przy błędzie.

## 8. Fail-closed

Zasada: gdy warunek bezpieczeństwa nie jest spełniony albo nie da się go sprawdzić, narzędzie **odmawia i nic nie robi** (zamiast „spróbować mimo to”).

**Kanał proxy w `szukaj-profili`** (`profile_discovery.py`):

* `BRAVE_PROXY=http://host:port`: ruch wyłącznie przez to proxy; proxy niedostępne = błąd, **nigdy połączenie bezpośrednie**. Transport obsługuje tylko proxy HTTP (CONNECT); HTTPS i SOCKS jako wartość `BRAVE_PROXY` są błędem konfiguracji.
* `BRAVE_REQUIRE_PROXY`: wymóg proxy wyłączają tylko jawne `0`/`false`/`no`/`nie`/`off`; **każda inna wartość, także literówka, go włącza**.
* `OSINT_PROXY` (kanał całego zestawu, np. Tor; panel ustawia go domyślnie) **wymusza proxy**. Gdy ma postać `http://host:port` i brak `BRAVE_PROXY`, jest użyty jako kanał; w postaci SOCKS (np. Tor) bez `BRAVE_PROXY` = odmowa (dla Tora: `HTTPTunnelPort` i `BRAVE_PROXY` na ten port).
* **Sonda:** przed pierwszym zapytaniem sprawdzane jest samo połączenie TCP z proxy (3 s); nieosiągalne = zero zapytań, kod 3, sprawa bez zmian.
* **`proxy_down`:** błąd połączenia przez proxy w trakcie przebiegu zatrzymuje przebieg bez ponowień i bez żadnego połączenia bezpośredniego; zebrane wyniki częściowe zostają (kod 1).
* Przy wymaganym proxy zmienne systemowe `HTTP(S)_PROXY`/`NO_PROXY` nie mają wpływu (trasa przypięta). Jedno stałe proxy na cały przebieg, stały User-Agent, **bez rotacji IP, bez podrabiania odcisku przeglądarki, bez samoczynnego przejścia na Tor lub połączenie lokalne**. Login i hasło z adresu proxy nie trafiają do komunikatów, audytu ani raportu. Zasada jest zapisana w `guardrails.EXCLUDED_CAPABILITIES` i pokryta testem E2E w CI (wymagane proxy bez konfiguracji: kod 3, zero prób połączeń).
* Klucz `BRAVE_SEARCH_API_KEY` z pliku: plik w katalogu repozytorium jest odrzucany; klucz trafia wyłącznie do nagłówka żądania.

**`--report` w `import-org-intel`** (sprawdzane **przed czymkolwiek innym**, także przy `--dry-run`; odmowa = kod 2):

* nazwy zastrzeżone dla plików sprawy (`graph.json`, `audit.jsonl`, `graph.graphml`, `maltego.csv`, `report.html`, `kropki.svg`) w dowolnym katalogu, bez względu na wielkość liter, końcowe kropki i spacje oraz strumień alternatywny;
* ścieżka w katalogu bieżącej sprawy i w katalogu **dowolnej** sprawy lub jego podkatalogu (katalog z `graph.json` lub `audit.jsonl`);
* plik `--input`; każdy istniejący plik (także symlink lub twarde dowiązanie); ścieżki rozwiązywane po `..`, ścieżkach względnych, symlinkach i junctionach;
* zapis tylko do **nowego** pliku (plik tymczasowy + `os.link`, które nie nadpisuje celu); **cudzy plik tymczasowy** o nazwie roboczej raportu = odmowa wykrywana **przed importem** (poprawka z `622856b`: wcześniej import był już zapisany, a kod 2 wracał dopiero przy zapisie raportu); cudzego pliku tymczasowego nie usuwamy.

**`--strict`:** pierwsze odrzucenie rekordu (także nieznane pole rekordu; nieznany klucz najwyższego poziomu odrzuca cały plik) = kod 5, nic nie zapisano, **brak wpisu w dzienniku** (dziennik notuje zmiany sprawy, a odmowa jej nie zmienia). Ślad odmowy to kod 5 i raport na ekranie/`--report` z `import_id`. W adapterze `--strict` oznacza, że plik wyjściowy nie powstaje.

**`--dry-run`:** liczy to samo na kopii grafu w pamięci; **nie zapisuje niczego** (ani plików sprawy, ani dziennika; test E2E: bajtowo bez zmian i bez nowego pliku). Z `--report` powstaje tylko raport, z nagłówkiem „DRY-RUN: nic nie zapisano”.

**Eksport `--maltego`:** nie nadpisuje istniejącego pliku (wyjątek: jawne `--force`), odmawia nazw plików sprawy i pliku wejściowego, `maltego.csv` w katalogu sprawy zapisuje wyłącznie sama sprawa, plik tymczasowy powstaje trybem „tylko nowy”, więc cudzy plik nie jest ruszany.

**Inne zasady fail-closed:** rekord z kolizją URL lub klucza odrzucany zamiast scalany; typ źródła bez reguły hosta odrzucany; `verified` bez poprawnej `verified_at` odrzuca domenę; hex 32/40/64 znaków w polu tekstowym traktowany jako podejrzenie hasha; `emails_masked` ≠ `true` w eksporcie (a także `store.json`) = importer sam maskuje i dopisuje ostrzeżenie; allowlisty hostów celowo wąskie (prawdziwy, ale niewymieniony host, np. inny krajowy CERT, jest odrzucany do czasu świadomego rozszerzenia listy w kodzie); higiena repo w CI pada, gdy w repozytorium są dane spraw lub pliki `.env`.

## 9. Raportowanie i dziennik audytu

**Raport importu** (`import-org-intel`, ekran i `--report`; format `text` lub `json`): `import_id`, nazwa pliku (bez ścieżki), format, ścieżka sprawy, liczby (węzły i krawędzie utworzone/zaktualizowane/bez zmian/odrzucone), liczba pominiętych osób, liczba zamaskowanych pól (`masked_fields`), liczba nieznanych pól, lista odrzuceń (rodzaj + identyfikator org-intel + nazwa **tylko gdy nie wygląda na sekret ani e-mail** + powód), ostrzeżenia, liczby rekordów w pliku. Brak danych osobowych w treści; **uwaga:** raport zawiera lokalną ścieżkę katalogu sprawy, więc przed przekazaniem raportu na zewnątrz sprawdź ją pod kątem nazwy użytkownika systemu.

**Maskowanie e-maili:** w każdym polu tekstowym zapisywanym do grafu (nazwa prawna, dawne nazwy, nazwa i tytuł incydentu, opis, klasy danych, nazwa i licencja źródła, adres siedziby) adres e-mail jest zastępowany w całości znacznikiem `[e-mail ukryty]` (bez pierwszej litery i bez domeny). Dotyczy to także adresów **częściowo** zamaskowanych już przez org-intel (np. `j***@example.test`): po poprawce `622856b` w plikach sprawy nie zostaje domena adresu. Węzły typu Email nie są eksportowane do `maltego.csv`; w pozostałych komórkach adres jest zastępowany znacznikiem, a komórka z sekretem staje się `[usunięto: sekret]`. Test E2E: `maltego.csv` bez żadnego znaku `@`; w plikach sprawy dopuszczone są wyłącznie adresy zamaskowane przez org-intel w opisie incydentu (w testach w domenie `example.test`).

**Dziennik audytu** `audit.jsonl`: kto (operator), kiedy, po co (cel, sygnatura sprawy), wejścia i opcje, wpis na każdą operację. Pierwszy wpis powstaje **przed** pierwszym działaniem; gdy nie da się go zapisać, operacja się nie zaczyna. Wpisy tworzą łańcuch skrótów SHA-256 (`eg audit-verify` wykrywa zmianę lub usunięcie wpisu ze środka; **nie** chroni przed skasowaniem całego pliku ani przed zmianą ostatniego wpisu bez śladu). Import org-intel zapisuje wpisy `org_intel_import` przed/po: nazwa pliku, sha256, `import_id`, liczby; **nigdy treść rekordów ani adresy e-mail**. Wyszukiwanie profili zapisuje `profile_search`/`profile_material` (przed/po), bez treści materiału.

**Raport HTML:** jeden plik, bez JavaScriptu i zewnętrznych zasobów, polityka CSP `default-src 'none'`, treść z cudzych źródeł escapowana, linki tylko http/https z `rel="noopener noreferrer nofollow"`, sekcja „czego narzędzie nie robi”. **Eksporty tabelaryczne** (CSV org-intel, `maltego.csv`) chronią przed formułami arkusza (apostrof przed wartością zaczynającą się od `=`, `@`, a przy `+`/`-` gdy nie jest liczbą).

**Atrybucja:** eksport JSON org-intel zawiera blok `attribution` (Have I Been Pwned, CC BY 4.0), CSV plik `ATTRIBUTION.txt`, gdy w magazynie są źródła `hibp_catalog`. Licencja źródła jest przenoszona do grafu.

## 10. Ograniczenia HIBP

* **Pokrycie:** katalog obejmuje tylko wycieki, które HIBP załadował; brak wpisu o domenie **nie dowodzi**, że incydentu nie było. `breaches?domain=` (hibp-monitor) pokazuje wycieki, w których serwis na tej domenie był **źródłem**, a nie wycieki zawierające adresy z tej domeny (to wymaga płatnego, zweryfikowanego wyszukiwania zbiorczego).
* **Opóźnienie ujawnień:** HIBP ładuje wyciek po weryfikacji i procedurze ujawnienia wobec firmy (rzędu dni roboczych), często długo po samym incydencie; `BreachDate` i `AddedDate` to różne daty. Modyfikacje istniejącego wpisu (`ModifiedDate`) nie są raportowane przez `hibp-monitor`, a przy ponownym imporcie zmienionego opisu lub flag w org-intel zachowywane są pierwsze wartości (statusy są sumowane).
* **Sensitive breaches:** wycieki wrażliwe są w HIBP chronione (m.in. wyszukiwanie po adresie tylko dla zweryfikowanego właściciela adresu); pipeline przenosi flagę `sensitive`, ale **nie weryfikowano w tym repo na żywo**, w jakim zakresie publiczny katalog je zwraca. Nie wyciągaj wniosków o „braku” takich incydentów.
* **Jakość wpisu:** incydent z katalogu bez flagi `verified` ma obserwację low; `fabricated` i `spam_list` także low. Flaga `retired` oznacza, że dane przestały krążyć, a nie że incydent się nie wydarzył.
* **Brak weryfikacji na żywo w tym repo:** konektor katalogu HIBP i resolver DoH nie były testowane na żywo (testy używają fałszywych klientów i blokują gniazda); płatny endpoint `domain-search` także nie (brak klucza).
* **Zasady użycia:** wymagana atrybucja (CC BY 4.0), uczciwy User-Agent, limity zapytań; API zabrania zapytań w celu szkodzenia ofiarom wycieków. Polski odpowiednik dla osoby sprawdzającej **siebie** (bez automatyzacji): serwis bezpiecznedane.gov.pl (Ministerstwo Cyfryzacji i CERT Polska).

## 11. Nieprzechowywanie haseł i tokenów

**Strażnicy** (`org-intel/guards.py`; kopia wzmocniona w `entity-graph/.../importers/org_intel.py`; w eksporcie Maltego i w skanerze artefaktów CI osobne, analogiczne wzorce). Rekord jest odrzucany w całości, gdy:

* **nazwa pola** wskazuje sekret: hasło (warianty), hash lub pole kończące się na „hash” (poza polami skrótów dowodu `content_hash` i `evidence_hash`), token (także dostępowy i odświeżający), klucz API, sekret, ciasteczko, sesja, nagłówek autoryzacji, klucz prywatny;
* **wartość** zawiera token JWT (trzy segmenty zaczynające się od zakodowanego nagłówka i ładunku), nagłówek autoryzacji z tokenem okaziciela o istotnej długości, klucz prywatny w formacie PEM, hash bcrypt, parę „adres e-mail + znak rozdzielający + ciąg znaków” wyglądającą na login i hasło, albo samodzielny ciąg szesnastkowy o długości 32, 40 lub 64 znaków (podejrzenie hasha; wyjątek: pola skrótu dowodu i adresy URL);
* klasa danych „Passwords” w katalogu HIBP **nie** powoduje odrzucenia (to etykieta; sprawdzane są wzorce wartości).

Dodatkowe zabezpieczenia: `RedactingFilter` w loggerze org-intel (redaguje e-maile, JWT, nagłówki autoryzacji, klucz HIBP, przypisania haseł i tokenów, token weryfikacji domeny, długie ciągi hex); token weryfikacji domeny jest pokazywany raz, a zapisywany tylko jako sha256 i nie jest eksportowany; podprocesy narzędzi siostrzanych dostają środowisko bez zmiennych zawierających `KEY`, `TOKEN`, `SECRET`, `PASSWORD`; podsumowanie i wyjście nieudanych kroków CI jest maskowane, a katalog artefaktów CI skanowany przed uploadem (trafienie = kod 1 i usunięcie pliku; każdy niezamaskowany e-mail jest trafieniem); higiena repo w CI blokuje pliki `.env*` (poza przykładowym) i dane spraw.

**Hasła użytkownika (`hibp-monitor password`):** model k-anonymity. Hasło wpisywane jest bez echa; liczony jest SHA-1, do usługi Pwned Passwords wysyłany jest **wyłącznie 5-znakowy prefiks skrótu** z nagłówkiem paddingu, a dopasowanie sufiksu odbywa się lokalnie; wiersze paddingu (licznik 0) są ignorowane. Hasło nie jest logowane, zapisywane ani wypisywane; pakiet nie używa modułu `logging`. Brak trafienia nie dowodzi, że hasło jest silne; trafienie oznacza: zmień je wszędzie.

## 12. Odłożone tematy i znane ograniczenia

* **REGON online:** w zacommitowanym kodzie nie ma konektora REGON/GUS wołanego przez adapter (`--online` obsługuje tylko KRS i CEIDG); wynik REGON podaje się z pliku (`--input`).
* **Rejestry w org-intel:** brak automatycznego pobierania rejestrów w samym `org-intel` (robi to adapter `osint-poland`); KRS nie ma sumy kontrolnej (sprawdzany tylko format, w odróżnieniu od NIP i REGON).
* **HIBP na żywo:** konektor katalogu, resolver DoH i płatny `domain-search` nieprzetestowane na żywo (sekcja 10); przy zmianie formatu odpowiedzi po stronie HIBP parser może odrzucić rekordy.
* **Maltego:** `maltego.csv` i mapowanie typów (`maltego.Person` itd.) nie były testowane w aplikacji Maltego (brak licencji); kolumny mapuje się przy imporcie (*Import Graph from Table*). GraphML sprawdzono pod kątem poprawności XML (Gephi/yEd), nie Maltego.
* **Higiena końcówek linii:** dwa pliki testów w `entity-graph` mają zacommitowane **mieszane** końcówki (CRLF + LF): `entity-graph/tests/test_transforms_ip.py` i `entity-graph/tests/test_transforms_person_phone_username.py`. Znany dług w `ci/known_mixed_eol.txt`; kontrola `hygiene:eol` pada na każdy **nowy** plik z mieszanymi końcówkami.
* **`username-engine`:** poza repozytorium (osobne repo, w `.gitignore`), więc nie ma go w checkoucie CI i nie ma dla niego kroku testowego; `entity-graph` korzysta z niego tylko jako z narzędzia siostrzanego.
* **Asystent sprawy (`eg asystent`, `eg dziennik`):** poza zakresem tego dokumentu i poza zacommitowanym stanem w chwili pisania.
* **Typowanie:** repo nie używa mypy/pyright (brak konfiguracji); lint (ruff) obejmuje tylko pliki ruff-czyste (`LINT_TARGETS`).
* **CI:** test adapter→org-intel→entity-graph w `osint-poland/tests/test_org_intel_feed.py` jest w CI pomijany (szuka `org-intel/.venv`); ten sam łańcuch pokrywa `ci/tests/test_pipeline_e2e.py`. Katalog `ci-artifacts/` powstaje lokalnie przy `--artifacts` (warto go usunąć lub dopisać do `.gitignore`).
* **Granice heurystyk:** dopasowanie nazw firm jest heurystyczne (formy prawne tylko na końcu nazwy), relacja domena→firma po nazwie jest zawsze `inferred`; weryfikacja domeny sprawdza TXT tylko na domenie głównej u jednego dostawcy DoH; filtr adresów profili to heurystyka struktury adresu, nie pełny filtr (sekret jako zwykły segment ścieżki przejdzie); `polacz` używa tego samego parsera, ale bez rankingu, deduplikacji i wykrywania kolizji URL względem sprawy.
* **Sprawy sprzed poprawek wyszukiwania profili** mogą zawierać fragmenty wyników wyszukiwarki i adresy z kontaktem; poprawka niczego nie przepisuje (dziennik jest łańcuchem skrótów); procedura oczyszczenia w `entity-graph/README.md`.

## 13. Rozbieżności kod–dokumentacja zauważone przy pisaniu

Zebrane do decyzji właściciela; dokument opisuje stan **kodu**.

1. **User-Agent w konektorach KRS i CEIDG.** `osint-poland/src/osint_poland/connectors/base.py` definiuje stały `USER_AGENT`, ale zapytania GET w `krs.py` i `ceidg.py` go nie przekazują (inne konektory: BZP, GUS, SAOS, TED: tak). Adapter `--online` używa domyślnego klienta HTTP. Dokumentacja pipeline'u mówi o „uczciwym User-Agent” ogólnie; dla rejestrów to nieprawda wprost.
2. **Baza jakości `company_website`.** `org-intel/README.md` podaje high, importer entity-graph: low, gdy host uznany tylko przez domenę oficjalną z tego samego pliku. To celowe wzmocnienie importera, ale README org-intel go nie wspomina.
3. **Wysoka jakość dokumentu urzędowego.** README org-intel wymienia hosty gov.pl, nask.pl, cert.pl, europa.eu; allowlista importera: `*.gov.pl` i `*.europa.eu` (nask.pl i cert.pl są pokryte kategoriami `nask`/`cert` dla `cert_advisory`, nie dla `official_document`).
4. **Raport importu zawiera lokalną ścieżkę sprawy** (pole `case`); nie jest to dana osobowa z rejestrów, ale może ujawniać nazwę użytkownika systemu.
5. **`entity-graph/README.md`, punkt „Bez omijania zabezpieczeń”** mówił „brak … proxy i rotacji tożsamości (klient HTTP nie ma takich opcji)”; po `cdeffbf` to nieaktualne (`UrllibClient` ma stałe proxy, fail-closed). Poprawiono wraz z tym dokumentem.
6. **Dwa pliki testowe z mieszanymi końcówkami** (sekcja 12) nadal w repozytorium.
