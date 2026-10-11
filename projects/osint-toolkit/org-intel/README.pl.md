# org-intel

Lokalny rejestr informacji o **firmach, domenach, publicznych osobach i publicznie opisanych incydentach bezpieczeństwa** z **obowiązkową proweniencją**: każda encja ma co najmniej jedną obserwację (źródło, adres dowodu, data, pewność, rodzaj wnioskowania). HIBP jest tu tylko **publicznym katalogiem metadanych incydentów** (licencja CC BY 4.0, atrybucja w eksporcie), nie źródłem danych o kontach.

Czego pakiet **nie robi** (i nie ma na to typów danych): żadnych dumpów ani źródeł z wyciekami (Telegram, paste, fora), żadnych wyszukiwań adresów e-mail w wyciekach, żadnych relacji e-mail → osoba ani osoba → incydent. Incydent łączy się wyłącznie z domeną/organizacją.

Zasady bezpieczeństwa, proweniencji i granice legalnego użycia całego pipeline'u: `../docs/BEZPIECZENSTWO_I_PROWENIENCJA.md`.

Zero zależności uruchomieniowych (stdlib, HTTP przez `urllib`); `pytest` tylko w trybie dev. **Domyślnie offline**: polecenia sieciowe bez `--online` kończą się kodem 2 bez żadnego ruchu.

```bash
py -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m pytest -q                 # testy bez internetu (fałszywy klient HTTP i resolver)
.venv\Scripts\python -m org_intel <polecenie>     # albo: org-intel <polecenie>
```

## Polecenia i kody wyjścia

| Polecenie | Działanie |
|---|---|
| `org-intel ingest PLIK.json [--store P] [--audit-mode]` | import własnego formatu albo katalogu HIBP; raport zaakceptowanych i odrzuconych (z powodami) |
| `org-intel search-company "Nazwa" [--json]` | po nazwie (tokeny, po fold), KRS, NIP, REGON, poprzednich nazwach; firma + domeny + incydenty + osoby + źródła |
| `org-intel incidents --domain firma.pl [--json]` | incydenty domeny (direct) i jej subdomen (inferred) |
| `org-intel export --format json\|csv --out ŚCIEŻKA [--include-emails]` | JSON (plik) albo CSV (katalog, plik na typ encji) |
| `org-intel verify-domain firma.pl` | wydaje token i instrukcję rekordu TXT (offline) |
| `org-intel verify-domain firma.pl --check --online` | sprawdza TXT przez DNS-over-HTTPS (Cloudflare) |
| `org-intel fetch-hibp-catalog --online --user-agent "..." [--refresh]` | pobiera publiczny katalog HIBP i zapisuje przez parser |

Magazyn domyślnie: `./org-intel-data/store.json` (`--store` nadpisuje; cache katalogu HIBP w `cache/` obok magazynu, surowe rekordy audytu w `raw/`).

Kody wyjścia: **0** OK; **2** błąd użycia/konfiguracji (zła składnia, nieczytelny plik, brak User-Agent, nieznana domena, polecenie sieciowe bez `--online`); **3** błąd sieci/API; **4** ingest zapisał poprawne rekordy, ale część odrzucono (lista w raporcie).

## Własny format wejściowy (JSON)

```json
{"sources":[{"key":"s1","name":"Odpis z KRS","url":"https://...","source_type":"official_registry",
             "license":"dane publiczne","retrieved_at":"2026-10-05T10:00:00Z","reliability":"high"}],
 "organizations":[{"legal_name":"Example Sp. z o.o.","krs":"0000123456","nip":"5271001238","regon":"360123459",
                   "official_domain":"example.test","previous_names":[],"sources":["s1"],
                   "confidence":"high","derivation":"direct","evidence_url":"https://..."}],
 "domains":[{"domain":"shop.example.test","organization":"0000123456","sources":["s2"]}],
 "persons":[{"name":"Jan Kowalski","role":"Prezes Zarządu","organization":"<KRS, NIP, REGON lub nazwa>",
             "public_email":"jan.kowalski@example.test","sources":["s2"],"email_source":"s2",
             "evidence_quote":"Prezes Zarządu: Jan Kowalski, jan.kowalski@example.test"}],
 "incidents":[{"name":"DemoBreach","incident_date":"2026-08-15","published_date":"2026-09-01",
               "affected_domain":"shop.example.test","affected_accounts_count":12345,
               "data_classes":["Email addresses"],"status":["verified"],"description":"...","sources":["s3"]}]}
```

* `key` źródła jest lokalny dla pliku; rekordy wskazują źródła w `sources`. Nieznany klucz odrzuca rekord (literówka nie może po cichu zgubić proweniencji).
* Opcjonalne pola wspólne: `confidence` (high/medium/low), `derivation` (direct/inferred, domyślnie direct; dla domen: direct tylko ze źródła first-party), `evidence_url`, `evidence_hash` (sha256 hex), `evidence_quote` (zapisywany **tylko jako sha256**, nie jako tekst).
* `official_domain` organizacji tworzy też rekord domeny powiązany z organizacją.
* Opcjonalne pola organizacji z rejestrów urzędowych: `status` (tekst z rejestru albo wartość z listy `aktywna, zawieszona, w_likwidacji, w_upadlosci, w_restrukturyzacji, wykreslona, inny`; zapisywany jako wartość znormalizowana, a oryginalny tekst jako `status_raw`, który można też podać jawnie) oraz `registered_address` (adres siedziby). **Adres tylko dla osób prawnych / jednostek z KRS**: wymaga `krs` albo jawnego `"legal_entity": true` (REGON typu P) i źródła `official_registry`; w przeciwnym razie (także przy `"legal_entity": false`) rekord jest odrzucany, więc adresy osób fizycznych (JDG) nie trafiają do magazynu. `legal_entity` jest tylko znacznikiem wejścia (nie jest zapisywany). Przy ponownym imporcie pierwsza wartość wygrywa, a różnica to ostrzeżenie (bez cichego nadpisania). `search-company` pokazuje oba pola.
* `status` incydentu to **lista** wartości: `verified, fabricated, spam_list, sensitive, retired, malware, stealer_log` (flagi metadanych HIBP; `stealer_log` to tylko etykieta, pakiet nie obsługuje stealer logs).
* Format katalogu HIBP jest rozpoznawany po zawartości: lista z `/api/v3/breaches` (PascalCase) albo `{"breaches":[...]}` z `hibp-monitor breaches --catalog --json` (snake_case). Źródło tworzone automatycznie: `hibp_catalog`, `https://haveibeenpwned.com/api/v3/breaches`, licencja `CC BY 4.0 (wymagana atrybucja: Have I Been Pwned)`. Opis: HTML usunięty, adresy e-mail w opisie i tytule zamaskowane (`j***@domena`), maks. 2000 znaków. **Dozwolone pola:** `Name`, `Title`, `Domain`, `BreachDate`, `AddedDate`, `ModifiedDate` (trafia do notatki obserwacji), `PwnCount`, `DataClasses`, `Description`, flagi `IsVerified/IsFabricated/IsSensitive/IsRetired/IsSpamList/IsMalware/IsStealerLog` (flaga to tylko jawna prawda: `true`/`1`; tekst `"false"` nią nie jest). Pola spoza listy (`LogoPath`, `Attribution`...) są ignorowane. **Rekord z polem kont, adresów e-mail albo sekretów** (np. `Emails`, `Accounts`, `Passwords`, `api_key`) jest odrzucany w całości (zgodnie z `guards.py`: incydent nie łączy się z kontami ani osobami), reszta importu trwa; nazwa incydentu z adresem e-mail też jest odrzucana.
* Limit pliku 50 MB, tylko JSON. Odrzucenie jednego rekordu nie przerywa importu.

## Zasady (guards)

1. **Proweniencja**: rekord bez co najmniej jednego istniejącego źródła jest odrzucany ("brak źródła"). Źródło wymaga `url` http/https, `retrieved_at` (ISO 8601) i typu z enuma: `official_registry`, `company_website`, `official_document`, `cert_advisory`, `hibp_catalog`, `ct_log`, `passive_dns`, `manual`.
2. **Zero wycieków**: źródło z sygnałem `dump`, `leak`, `combolist`, `stealer`, `paste`, `breachforums`, `t.me/`, `telegram` (w nazwie, typie, URL lub hoście t.me) jest odrzucane; rekordy oparte na nim też.
3. **Zero surowych sekretów** w *każdym* rekordzie (rekurencyjnie): klucze `password`, `passwd`, `pass`, `pwd`, `hash`, `*_hash`, `token`, `access_token`, `refresh_token`, `api_key`, `apikey`, `secret`, `cookie`, `session`, `authorization`, `private_key` (poza `content_hash`/`evidence_hash`); wartości: JWT, klucz prywatny PEM, bcrypt, `Bearer ...`, `e-mail:hasło`, ciągi hex 32/40/64 znaków (poza polami hashy dowodu i adresami URL). Klasa danych `Passwords` w `data_classes` katalogu HIBP **nie** jest odrzucana (to etykieta, sprawdzamy wzorce wartości).
4. **Osoby publiczne**: wymagają źródła `official_registry`, `company_website` lub `official_document`; źródła innych typów są pomijane (ostrzeżenie), a jeśli żadne nie spełnia warunku, osoba jest odrzucana. Wymagane `organization` (KRS > NIP > REGON > nazwa).
5. **E-mail osoby** zapisywany tylko, gdy **oba** warunki: (a) źródło e-maila (`email_source`, domyślnie źródła osoby) jest first-party/official, oraz (b) domena e-maila to `official_domain` organizacji (lub jej subdomena) **albo** adres występuje dosłownie w `evidence_quote`. W przeciwnym razie osoba zostaje zapisana **bez** e-maila, a obserwacja dostaje notatkę „e-mail odrzucony: brak potwierdzenia w źródle first-party/official”.
6. Brak relacji e-mail → osoba i osoba → incydent: rekord incydentu z polami `person(s)/email(s)/account(s)` albo osoby z `incident(s)` jest odrzucany.

## Pewność i proweniencja

Pewność obserwacji = `min(jakość źródła, pewność zadeklarowana)`, a jakość źródła = `min(baza z typu, reliability użytkownika)`. Baza: rejestr/strona firmy/komunikat CERT = high; dokument = medium (high dla hostów urzędowych: gov.pl, nask.pl, cert.pl, europa.eu); `hibp_catalog` i `ct_log` = medium; `passive_dns` i `manual` = low. Incydent z flagą `fabricated` lub `spam_list` ma obserwację **low**; incydent z katalogu HIBP bez flagi `verified` także **low**.

Relacje (`correlate.py`), każda z `derivation` i dowodami:
* organizacja → domena: **direct** (rekord z `organization` i obserwacja direct ze źródła first-party), **inferred** (źródło nie-first-party albo domena bez organizacji dopasowana po nazwie firmy);
* domena → incydent: **direct** (ta sama domena), **inferred** (incydent na subdomenie, np. `shop.example.test` → `example.test`; także gdy domena firmy jest sama inferred);
* organizacja → osoba: po `Person.organization_id`.

## Magazyn i deduplikacja

* Zapis atomowy (plik tymczasowy + `os.replace`), wersja schematu `schema_version: 1`.
* Id deterministyczne: krótki sha256 z typu i klucza naturalnego (organizacja: KRS > NIP > REGON > znormalizowana nazwa; domena: domena; incydent: nazwa po fold; źródło: znormalizowany URL; osoba: id organizacji + fold(imię i nazwisko)). Nowa organizacja trafiająca na istniejącą po identyfikatorze (albo po nazwie, jeśli identyfikatory nie są sprzeczne) jest scalana z jej id.
* **Źródła scalane po znormalizowanym URL** (bez fragmentu, `utm_*`, końcowego `/`, danych logowania, schematu; host małymi literami). Zostaje **pierwsze** źródło (jego `retrieved_at`), a każde kolejne pobranie to nowa Observation z nowszym `observed_at`. Ponowny import tego samego pliku jest idempotentny.
* Encje: scalanie `source_ids` i `previous_names`; pierwsza wartość pola wygrywa, konflikty identyfikatorów to ostrzeżenia; status weryfikacji domeny nigdy nie jest cofany.
* Tryb audytowy (`--audit-mode`, domyślnie wyłączony): zaakceptowane rekordy wejściowe trafiają do `raw/ingest-*.json`. Rekordy odrzucone (np. z sekretami) nigdy tam nie trafiają. Poza trybem audytowym cytaty dowodu nie są zapisywane, tylko ich sha256.

## Eksport

* JSON: cały magazyn plus blok `attribution` (Have I Been Pwned, CC BY 4.0), jeśli są źródła `hibp_catalog`. Skróty tokenów weryfikacji nie są eksportowane.
* CSV: `sources.csv`, `organizations.csv`, `domains.csv`, `persons.csv`, `incidents.csv`, `observations.csv` (UTF-8 z BOM), listy łączone `;`, wartości zaczynające się od `= + - @` lub tab/CR dostają przedrostek `'` (ochrona przed CSV injection), plus `ATTRIBUTION.txt` przy źródłach HIBP.
* E-maile osób maskowane (`j***@example.test`); pełne tylko z `--include-emails`.

## Weryfikacja własności domeny

`verify-domain firma.pl` wydaje losowy token (`secrets.token_urlsafe`), pokazuje go **raz** i zapisuje tylko jego sha256; domena dostaje status `pending`. Po dodaniu rekordu TXT `org-intel-verification=<token>` na domenie: `verify-domain firma.pl --check --online` → `verified` (z `verified_at`) albo `failed` (można ponowić). Błąd sieci nie zmienia statusu. Domena musi już być w magazynie (po `ingest`).

## Konektor katalogu HIBP

`fetch-hibp-catalog` używa wyłącznie publicznego `GET https://haveibeenpwned.com/api/v3/breaches` (bez klucza): wymagany `--user-agent`, timeout 30 s, odstęp min. 1,6 s między zapytaniami, cache na dysku (TTL 24 h; `--refresh` pomija), limit rozmiaru odpowiedzi 20 MB, obsługa 429 z `Retry-After` (maks. 3 próby, czekanie do 120 s). Do cache trafia tylko poprawna odpowiedź, i to **zminimalizowana** (tylko dozwolone pola, e-maile zamaskowane, rekordy z polami kont odrzucone; surowa odpowiedź nie jest zapisywana, cache sprzed tej zmiany jest ignorowany).

**Klucz API nie jest ani wymagany, ani akceptowany**: zapytanie niesie tylko `User-Agent` i `Accept`, polecenie nie ma opcji klucza, zmienna `HIBP_API_KEY` nie jest czytana. `--online` jest wymagane (bez niego kod 2 i zero zapytań). **Proweniencja pobrania:** źródło `hibp_catalog` ma `retrieved_at` (czas pobrania), `content_hash` = sha256 odpowiedzi serwera (przed minimalizacją), a w notatce pochodzenie (online/cache/plik lokalny), `ETag` (pierwsze 24 znaki) i `Last-Modified`, jeśli serwer je podał; każda obserwacja niesie ten sam skrót w `evidence_hash`. Przy imporcie z pliku `content_hash` to sha256 pliku (bez ścieżki). Źródło zachowuje pierwsze wartości (nowe pobranie = nowe obserwacje z nowym `retrieved_at` i skrótem). Surowe rekordy (tylko dozwolone pola) zapisuje wyłącznie jawny `--audit-mode` (`ingest` i `fetch-hibp-catalog`).

**Wyszukiwanie po adresie e-mail lub domenie (breachedaccount, breacheddomain), pasteaccount i stealer logs nie są częścią tego pakietu** i zostają w `hibp-monitor` (opcjonalne, płatne, tylko dla własnej, zweryfikowanej domeny).

## Logowanie

`get_logger()` zwraca logger z `RedactingFilter`: redaguje e-maile (`j***@domena`), JWT, nagłówki Authorization/Bearer, `hibp-api-key`, `password=...`, `token=...`, `org-intel-verification=...` i ciągi hex 32+.

## Ograniczenia

* Brak automatycznego pobierania rejestrów (KRS/CEIDG/REGON): dane wprowadza się własnym formatem JSON z podaniem źródła (plik w tym formacie generuje adapter `osint-poland`: `py -m osint_poland.org_intel_feed`, który nie importuje org-intel); KRS nie ma sumy kontrolnej (sprawdzany tylko format).
* Dopasowanie nazw firm jest heurystyczne (formy prawne rozpoznawane tylko na końcu nazwy); relacja domena→firma po nazwie jest zawsze `inferred`.
* Id nowej organizacji zależy od najsilniejszego identyfikatora znanego przy pierwszym wprowadzeniu (późniejsze scalanie zachowuje to id).
* Weryfikacja domeny sprawdza TXT na domenie głównej przez jednego dostawcę DoH.
* Konektor HIBP i resolver DoH nie były testowane na żywo (testy używają fałszywych klientów; testy blokują `socket`).
* Ponowny import zmienionego opisu/flag istniejącego incydentu zachowuje pierwsze wartości (statusy są sumowane); `ModifiedDate` jest tylko w notatce obserwacji.

## Struktura

`src/org_intel/`: `models.py`, `normalize.py`, `guards.py`, `parsers.py`, `quality.py`, `store.py`, `correlate.py`, `export.py`, `verify.py`, `hibp_catalog.py`, `http.py`, `logging_redact.py`, `cli.py`. Testy w `tests/` (fixtury wyłącznie syntetyczne w `tests/fixtures/`: Jan Kowalski, Example Sp. z o.o., example.test, DemoBreach).
