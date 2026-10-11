# Entity Graph

Graf powiązań OSINT dla zleconych, autoryzowanych badań: due diligence, audyt własnej infrastruktury, zlecenia z jasnym celem. Składa wyniki z małych transformacji w jeden graf (JSON, GraphML, raport HTML), pokazuje dowód każdej krawędzi i prowadzi dziennik audytu. Korzysta z narzędzi siostrzanych z tego repo: `username-engine`, `dns-audit`, `hibp-monitor`, `phone-check` (nie kopiuje ich kodu). Katalog narzędzi i kategorii: `CATALOG.md`.

**Przeznaczenie:** własne domeny, adresy i konta albo badanie na zlecenie z podstawą prawną. To nie jest narzędzie do ustalania, kim jest cudza osoba. Trafienie to trop, nie dowód: ta sama nazwa lub awatar nie znaczy, że to ta sama osoba.

```bash
py -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"      # zero zależności uruchomieniowych (tylko stdlib)
.venv\Scripts\python -m entity_graph run --purpose "audyt własnej infrastruktury firmy X, zlecenie 2026/14" --domain example.com
.venv\Scripts\python -m pytest -q                    # testy bez internetu
```

Najprościej: dwuklik `START_ENTITY_GRAPH.cmd`, potem `eg run --purpose "..." --domain example.com` (ściąga na starcie).

## Użycie

```
eg run --purpose "..." [--case-ref SYGNATURA] [--operator KTO]
       [--ip A] [--domain D] [--email E] [--username U] [--person "Jan Kowalski"] [--phone N] [--url URL]
       [--depth 1] [--out KATALOG] [--only t1,t2] [--skip t1,t2] [--offline]
eg polacz --purpose "..." PLIK_LUB_KATALOG [...] [--out KATALOG] [--min-confidence 0.6]
eg export graph.json --graphml g.graphml --html raport.html
eg kropki graph.json [--svg kropki.svg] [--max-nodes 200] [--min-confidence 0.5]
eg przeglad KATALOG --person "Jan Kowalski"
eg potwierdz KATALOG --person "Jan Kowalski" --profil URL --dowod "..." [--odrzuc] [--dodaj]
eg relacja KATALOG --person "A" --typ rodzic|dziecko|rodzenstwo|partner|inna --druga-osoba "B" --zrodlo URL|dokument:ŚCIEŻKA
            --dowod "..." [--fragment "..."] [--opis "..."] [--dodaj]
eg relacja-potwierdz KATALOG --id r-XXXXXXXXXX --dowod "..." [--odrzuc]
eg telefon KATALOG (--numer N | --plik wynik.json) [--region PL]
eg telefon KATALOG --numer N --operator-aktualny NAZWA --zrodlo URL|dokument:ŚCIEŻKA --data RRRR-MM-DD
eg kandydaci KATALOG (--person "Jan Kowalski" | --username U) [--nazwy a,b] [--max-nazw 3] [--max-queries 3]
             [--max-cost 15] [--max-seconds 600] [--max-rounds 3] [--ue-tags social,pl] [--ue-limit N]
eg szukaj-profili KATALOG --person "Jan Kowalski" [--kontekst "Kraków"] [--dodaj] [--max-calls 6]
             [--max-results 20] [--max-candidates 50] [--max-seconds 60]
eg material-profilu KATALOG --person "Jan Kowalski" --url URL (--tekst "..." | --tekst-stdin) [--dodaj]
eg sprawa KATALOG                       # widok sprawy jako JSON (używa go panel)
eg audit-verify KATALOG/audit.jsonl
eg rozszerz IDENTYFIKATOR --purpose "..." [--profile URL] [--website W] [--email E] [--display-name N]
            [--entity-kind person|organization] [--auto] [--max-rounds 2] [--max-queries 10] [--max-seconds 1800]
            [--max-cost 50] [--adapters username_scan] [--out KATALOG]
eg transforms
```

Zalążki można powtarzać. Wyniki trafiają do nowego katalogu (`--out`, domyślnie `eg-<data>`): `graph.json`, `graph.graphml`, `report.html`, `audit.jsonl`. Istniejący `graph.json` nie jest nadpisywany. Kod wyjścia: 0 = koniec, 1 = co najmniej jedna transformacja zakończyła się ERROR, 2 = błąd użycia lub naruszenie zasad.

## Model danych

- **Węzły:** Person (imię i nazwisko), Username, Email, Domain, IP, Phone, Organization, URL, Photo (plik zdjęcia, tylko z importu), Parcel (działka ewidencyjna, tylko z importu). Węzły o tej samej znormalizowanej wartości są jednym węzłem (domena bez schematu i wielkości liter, IDN jako punycode, URL bez `www`, śledzenia `utm_*`, danych logowania i fragmentu, `twitter.com` = `x.com`, telefon do E.164, nazwa użytkownika bez wielkości liter, imię i nazwisko bez polskich znaków).
- **Krawędzie:** `src`, `dst`, `relation`, `source` (transformacja), `timestamp`, `confidence` (0 do 1), `evidence` (tekst). Ta sama krawędź z dwóch źródeł zachowuje wyższą pewność i oba dowody. `confidence` musi być liczbą skończoną z zakresu 0-1 (nie bool, nie tekst): NaN, nieskończoność albo liczba spoza zakresu to błąd danych (wczytanie grafu się nie udaje, wiersz skanu staje się ERROR), nigdy pewność 1.0.
- **Obserwacje:** pola dowodowe (`entity_kind`, `website`, `insecure`, `display_name`, `avatar_hash`) są zapisywane razem ze źródłami (`observations` węzła). Sprzeczne obserwacje tego samego rekordu nie są rozstrzygane kolejnością: pole staje się nieznane (`insecure`: true), sprzeczność widać w raporcie, a ocena kandydata kieruje do przeglądu.
- **Uruchomienia:** każda transformacja zostawia rekord ze statusem, uwagą i błędem (sekcja w raporcie).
- Format JSON ma pole `schema: 1` i `observation_model: 1`; wczytanie sprawdza spójność (krawędź do nieistniejącego węzła = błąd). Graf zapisany przed modelem obserwacji (bez `observation_model`) jest czytany świadomie: wartość pola dowodowego traktowana jest jak jedna obserwacja wszystkich źródeł węzła.

## Statusy

| Status | Znaczenie |
|---|---|
| FOUND | źródło odpowiedziało i dostarczyło dane |
| NOT_FOUND | źródło jawnie odpowiedziało, że nic nie ma (np. HTTP 404 z API, brak PTR, pusta lista z crt.sh) |
| UNKNOWN | nie sprawdzono lub nie da się rozstrzygnąć: brak klucza, adres prywatny, tryb offline, brak narzędzia siostrzanego, skan z błędami bez trafień |
| ERROR | błąd sieci, timeout, limit (429), blokada (401/403), 5xx, zły format odpowiedzi, wyjątek |

Błąd sieci nigdy nie staje się NOT_FOUND. Dla `domain_rdap` HTTP 404 to UNKNOWN, bo `rdap.org` zwraca 404 także wtedy, gdy dla końcówki nie ma serwera RDAP w bootstrapie IANA. Skan `username_scan` bez trafień, ale z błędami serwisów, to UNKNOWN.

## Transformacje

Każda to czyste funkcje `parse_*` (testowane na fixture'ach) plus cienka warstwa sieciowa.

| Transformacja | Wejście | Co robi |
|---|---|---|
| `ip_rdap` | IP | RDAP przez `rdap.org` (zapas: RIPE): nazwa sieci, kraj rejestru, zakres, CIDR, organizacje (tylko typu org/group; osoby fizyczne pomijane). Rola `registrant` to `allocated_to` (0.9), pozostałe role to `contact_org` (0.6) |
| `ip_asn` | IP | RIPEstat `prefix-overview`: ASN, nazwa operatora ASN, prefiks BGP; brak ogłoszenia w BGP to NOT_FOUND |
| `ip_rdns` | IP | PTR systemowym resolverem (z limitem czasu); wynik jako węzeł Domain |
| `ip_internetdb` | IP | Shodan InternetDB (bez klucza): otwarte porty, CPE, tagi, nazwy hostów, CVE oznaczone jako niezweryfikowane. To dane z cudzych skanów; 404 nie dowodzi, że porty są zamknięte |
| `dns_audit` | Domain | podproces `dns-audit --json`: A/AAAA do węzłów IP, NS i MX do węzłów Domain, atrybuty SPF/DMARC/DNSSEC. Błędy zapytań DNS dają ERROR lub uwagę o wyniku częściowym, nie "brak rekordu" |
| `domain_rdap` | Domain | RDAP: rejestrator (Organization), daty rejestracji i wygaśnięcia, statusy. Danych rejestranta nie zbiera |
| `domain_crtsh` | Domain | crt.sh: subdomeny z Certificate Transparency (pasywnie), limit `--max-subdomains`; obecność w certyfikacie nie dowodzi, że host działa |
| `email_domain` | Email | domena z adresu (bez sieci); domeny publicznych dostawców poczty nie są dalej badane |
| `email_gravatar` | Email | czy istnieje awatar Gravatar dla skrótu SHA-256 adresu (publiczny endpoint `d=404`); zapisuje skróty jako atrybuty |
| `email_hibp` | Email | wycieki z adresem przez `hibp-monitor` (jego klient HTTP i parser). **Tylko z własnym kluczem w `HIBP_API_KEY`**; bez klucza UNKNOWN. Klucz nie trafia do grafu, dziennika ani podprocesów |
| `username_scan` | Username | podproces `username-engine` (~5800 serwisów). Z profilu zostają: nazwa wyświetlana, skrót awatara, strona www, linki, typ encji, odcisk bio (skróty słów, bez treści). Treść bio i lokalizacja nie są przenoszone |
| `person_candidates` | Person | kandydaci nazw użytkownika (złożenie polskich znaków, separatory `.` `_` `-`, inicjały), limit `--max-usernames` (domyślnie 12), plus linki dorków (Google, Bing, DuckDuckGo) do ręcznego otwarcia. Nic nie jest wysyłane. Kandydaci to hipotezy z pewnością krawędzi 0 i nie są skanowani bez `--expand-candidates` |
| `phone_metadata` | Phone | podproces `phone-check` (offline): poprawność w planie numeracji, kraj, typ linii, pierwotny przydział operatora z ostrzeżeniem o przenoszeniu numerów |
| `url_host` | URL | host adresu jako Domain lub IP (bez sieci) |

Rozwijanie (`--depth`, domyślnie 1): z wyniku transformacji badane są dalej tylko adresy IP z DNS (`resolves_to`), domeny z adresu e-mail (`mailbox_at`) i host z URL (`hosted_on`). Nie są rozwijane hosty NS/MX, rejestrator, organizacje, konta ani publiczni dostawcy poczty (cudza infrastruktura). Subdomeny i kandydaci nazw tylko na jawną prośbę (`--expand-subdomains`, `--expand-candidates`). Twarde limity: `--max-nodes` (500) i `--max-runs` (200); ucięcie jest zapisane w grafie i dzienniku.

Zasięg geograficzny IP kończy się na tym, co publicznie podaje RDAP/ASN (organizacja, kraj rejestru). Narzędzie nie geolokalizuje osób.

## Korelacja (`correlate.py`)

Scalanie dotyczy tylko identyfikatorów identycznych po normalizacji. **Węzłów Person nie scala się nigdy.** Powiązanie "ta sama osoba" (krawędź `same_person` między profilami) powstaje wyłącznie z jawnych sygnałów:

| Sygnał | Siła |
|---|---|
| profile linkują do siebie nawzajem / w jedną stronę | 0.85 / 0.7 |
| ten sam adres e-mail powiązany z oboma profilami (np. awatar profilu to Gravatar tego adresu) | 0.8 |
| ta sama własna strona www (domena spoza listy platform) | 0.6 |
| ta sama nazwa wyświetlana **i** ten sam skrót awatara, na różnych serwisach | 0.75 |

Same nazwy użytkownika, sama nazwa wyświetlana albo sam awatar nie są sygnałem. Reguła i wagi pochodzą ze wspólnego modułu `evidence.py` (ta sama co w `eg rozszerz` i w username-engine). Pola, które da się skopiować (link w jedną stronę, strona www, nazwa z awatarem), liczą się jako **jedna zależna grupa**: najsilniejsze z nich, nie więcej niż 0.7. Sprzeczność twarda (osoba / organizacja) ogranicza wynik do 0.3. Pozostałe grupy łączą się jako niezależne poszlaki, wynik jest ograniczony do 0.95 **oraz do pewności najsłabszego z dwóch kont** (konto znalezione z pewnością 0.62 nie da powiązania o pewności 0.9). Każda krawędź niesie listę sygnałów jako dowód. Skrót awatara liczony jest z adresu obrazu (dla Gravatara z skrótu w URL), nie z treści: ten sam obraz pod różnymi adresami nie zostanie dopasowany. Sygnały nie są w pełni niezależne (np. wzajemny link i wspólna strona często idą w parze), więc traktuj wynik jako porządkowanie tropów, nie prawdopodobieństwo.

## Rozszerzanie rekordów (`eg rozszerz`)

Rundy: zebranie kandydatów przez skonfigurowane adaptery (domyślnie `username_scan`) -> porównanie z danymi początkowymi -> decyzja z uzasadnieniem -> kolejna ograniczona runda -> raport. Wejście: identyfikator tekstowy i opcjonalne atrybuty startowe. `--profile` to **kotwica**: profil, o którym operator wie, że należy do badanego podmiotu.

Polecenie `eg` działa w terminalu otwartym przez `START_ENTITY_GRAPH.cmd`. W zwykłym PowerShell, z katalogu `entity-graph`, można uruchomić kod bez instalacji pakietu:

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
python -m entity_graph rozszerz --help
```

Poniższe `eg ...` odpowiada wtedy `python -m entity_graph ...`. Samo przejście do katalogu nie udostępnia pakietu znajdującego się w `src`.

```
eg rozszerz ziarno7 --purpose "audyt własnych kont firmy X, zlecenie 2026/9" --profile https://github.com/ziarno7 \
   --website https://ziarno.example --auto --max-rounds 2 --max-queries 6 --ue-tags coding --out sprawa
```

| Decyzja | Kiedy |
|---|---|
| `rozwin` | mocny dowód kontroli po stronie danych początkowych (kotwica linkuje do kandydata albo linki są wzajemne), brak sprzeczności i rozbieżności, wiarygodne źródło (pewność konta >= 0.6, TLS zweryfikowany). Dopiero wtedy nazwy kont z linków kandydata idą do kolejnej rundy |
| `przeglad` | jakikolwiek sygnał bez mocnego dowodu: tylko pola kopiowalne (możliwa kopia), link kandydata do kotwicy (jego twierdzenie), sprzeczność (osoba / organizacja), rozbieżność (inna własna strona, zupełnie inna nazwa), słabe źródło, łańcuch przez pośrednika |
| `zatrzymaj` | brak dowodu względem danych początkowych (sama zbieżność identyfikatora) |

Ocena to **poziom dowodów** (brak / słabe / umiarkowane / mocne), nie procent pewności. Każdy kandydat w każdej rundzie jest porównywany z kotwicą, nie z poprzednikiem: A-B i B-C nie potwierdza A-C (łańcuch trafia do raportu i co najwyżej kieruje do przeglądu). Kandydat zawsze pozostaje hipotezą (krawędź `candidate_match` z pewnością 0); potwierdza człowiek (`eg potwierdz`).

Wiarygodność jest sprawdzana również dla pobranej kotwicy: sam adres wskazany przez operatora nie potwierdza prawdziwości treści pobranej bez TLS lub ze słabego źródła. Nieudane wyniki adapterów (`ERROR`, `UNKNOWN`, `NOT_FOUND`) nie wprowadzają profili do automatycznej kontynuacji. Adapter nieobsługujący typu wejścia i niefinitywne limity (`NaN`, nieskończoność) są odrzucane przed uruchomieniem.

Bez `--auto` wykonuje się tylko runda 1, a kolejne identyfikatory trafiają do raportu jako propozycje. Limity: `--max-rounds` (głębokość), `--max-queries`, `--max-seconds` (sprawdzany przed każdym zapytaniem; trwające zapytanie ogranicza `--ue-timeout`), `--max-cost` (jednostki umowne: `username_scan` = 5, inne = 1), `--max-candidates` na rundę, `--max-followups` na kandydata. Deduplikacja: identyfikator jest odpytany raz (powrót do niego to cykl, odnotowany w raporcie), kandydat oceniany raz. Zatrzymanie: plik `STOP` w katalogu `--out` albo Ctrl+C; raport i dziennik powstają także wtedy. ERROR/UNKNOWN adaptera to "nie rozstrzygnięto", nigdy "rekordu nie ma".

Raport HTML ma sekcję **Rozszerzanie rekordów: rundy i decyzje**: zapytania ze statusami, kandydaci z decyzją, poziomem, powodami i sygnałami (grupa: kontrola / identyfikator / kopiowalne), kolejne identyfikatory, pominięcia z powodem, niewykonane propozycje i powód zakończenia. Ocena jest powiązana z obserwacjami, z których pochodzi: nowe obserwacje kandydata (np. sprzeczny typ encji z innego zapytania) wymuszają ponowną ocenę także w kolejnej rundzie, a zaplanowane rozwinięcie z kandydata, który stracił decyzję `rozwin`, jest wstrzymane (`meta.expansion.held`). Wcześniejsza decyzja zostaje w raporcie swojej rundy. To samo w `graph.json` (`meta.expansion`), decyzje w `audit.jsonl` (`expansion_decision`).

`--max-queries` liczy wywołania adaptera, a nie żądania HTTP: jeden `username_scan` odpytuje wiele serwisów. Do małego testu ustaw również `--ue-limit`, np. 30, oraz kategorię `--ue-tags`. Koszt jest budżetem umownym, nie kwotą pieniężną. Funkcja `rozszerz` jest obecnie dostępna w CLI; panel WWW nie ma jeszcze jej formularza.

## Łączenie kropek (`polacz`)

`eg polacz --purpose "..." wyniki/ plik.json [...]` składa **gotowe pliki wynikowe** narzędzi siostrzanych w jeden graf, uruchamia korelację (`correlate.py`) i zapisuje `graph.json`, `graph.graphml`, `report.html`, `audit.jsonl` jak `run`. Działa **offline** (zero zapytań), wymaga `--purpose` i prowadzi dziennik audytu (wpis `import` z skrótem SHA-256 na każdy plik, potem `merge` i `end`). Katalogi są czytane rekurencyjnie (bez ukrytych); katalog `--out` jest pomijany.

**Rozpoznawane formaty** (po zawartości, nie po nazwie; moduł `importers/`):

| Źródło | Plik | Co trafia do grafu |
|---|---|---|
| username-engine | `--json`, `--csv` | Username -> konta (URL, kind=profile) z pewnością i statusem **dokładnie jak w skanie**; NOT_FOUND/ERROR zostają jako liczniki na Username |
| dns-audit | `--json` | Domain, hosty NS/MX, adresy IP (ta sama logika co transformacja `dns_audit`) |
| phone-check | JSON, CSV (`;`) | Phone z samymi metadanymi planu numeracji; żadnych powiązań z osobami |
| hibp-monitor | `breaches --domain --json`, `domain-search --json`, lista wycieków | Domain, Email, wyciek (Organization, kind=breach). Katalog całego HIBP: SKIPPED |
| exif-map | JSON, CSV | Photo z aparatem, oprogramowaniem i GPS jako atrybutem (bez geokodowania i bez powiązań z osobami) |
| osint-poland | snapshot `teczka-spolki/v1`, surowy Wykaz VAT, odpis KRS, tekst ULDK | Organization (KRS, NIP, REGON, adres, rachunki IBAN), strona/e-mail z KRS, Parcel. Dane osób nie są importowane (KRS jest zanonimizowany w źródle, przedstawicieli z VAT pomijamy) |
| entity-graph | własny `graph.json` | scalenie wcześniejszych badań; krawędź z dwóch grafów ma wyższą z pewności, nie sumę; dziennik uruchomień zachowuje statusy |

Plik nierozpoznany, pusty, binarny lub większy niż 50 MB jest raportowany jako **SKIPPED** z powodem, uszkodzony jako **ERROR**; żaden nie przerywa pracy. Statusy rekordów (np. błąd zapytania DNS, skan bez rozstrzygnięcia, nieczytelne zdjęcie) trafiają do `graph.runs` jako ERROR i **nigdy** nie stają się brakiem danych. Kod wyjścia: 1, gdy jakikolwiek plik lub rekord to ERROR albo nic nie zaimportowano.

**Reguły łączenia** (`links.py`; każda krawędź ma dowód, źródło `links`, pewność nie wyższa niż 0.9 i nie wyższa niż pewność konta):

- **Scalanie węzłów:** firmy o tym samym NIP/KRS/REGON (REGON 9 cyfr = początek REGON-u 14-cyfrowego); konflikt (różne NIP albo KRS) nie scala i trafia do raportu. Wycieki o tej nazwie. Reszta (e-mail małymi literami, domena IDNA, telefon E.164, nazwa użytkownika bez wielkości liter, URL) scala się już przy tworzeniu węzła; wszystkie źródła zostają na węźle.
- **E-mail <-> organizacja:** domena adresu = strona www organizacji (np. z KRS), pewność = siła deklaracji strony x 0.85 (subdomena x 0.6). Domeny publicznych dostawców poczty pomijane.
- **Domeny:** wspólny IP (do 0.5), wspólny serwer NS (do 0.4, osłabiany przy dużym dostawcy), wspólny ASN (0.15). Powyżej 25 domen na zasób: bez powiązania.
- **Konta:** profil z linkiem/bio do domeny obecnej w grafie (0.6, nie więcej niż pewność konta); wzajemne linki profili obsługuje `correlate`.
- **Rachunki:** ten sam IBAN u dwóch różnych organizacji to powiązanie (0.7), nie scalenie: rachunek bywa wspólny.

Raport HTML ma sekcję **Powiązania między źródłami**: liczniki IMPORTED/SKIPPED/ERROR i tabela plików z powodami, scalone węzły, konflikty oraz powiązania wg pewności z dowodem i plikami źródłowymi.

**Ograniczenia importu:** format zmieniony w narzędziu siostrzanym może dać SKIPPED/ERROR (test na fixture'ach z ich formatów, nie na wersjach przyszłych); CSV username-engine nie zawiera danych profilu (brak sygnałów www/linków); `bank_accounts` jest atrybutem organizacji (nie osobnym węzłem); parcela z teczki jest tylko "wspomniana obok" firmy (0.5), nie dowodem własności; podobieństwo nazw firm bez wspólnego identyfikatora nie scala.

## Zabezpieczenia obowiązkowe

- **`--purpose` jest wymagany** (min. 2 słowa, 12 znaków; "test", "xxx" odrzucane). Bez niego nic się nie uruchamia i nie powstaje żaden plik.
- **Dziennik audytu** `audit.jsonl`: kto (operator), kiedy, po co (purpose, sygnatura sprawy), wejścia, opcje, a potem wpis na każdą transformację (status, błąd) i podsumowanie. Pierwszy wpis powstaje przed pierwszym zapytaniem; gdy nie da się go zapisać, badanie się nie zaczyna. Wpisy tworzą łańcuch skrótów SHA-256 (`eg audit-verify` wykrywa zmianę lub usunięcie wpisu ze środka; nie chroni przed skasowaniem całego pliku ani przed zmianą ostatniego wpisu bez śladu).
- **Bez omijania zabezpieczeń:** brak logowania do serwisów, rozwiązywania CAPTCHA, rotacji IP i tożsamości oraz podrabiania odcisku przeglądarki (blokady 401/403/429 to ERROR, nie powód do obejścia). Klient HTTP transformacji (`http.py`) nie ma żadnych opcji proxy. Jedyny wyjątek to `eg szukaj-profili`: jedno stałe proxy HTTP chroniące operatora, tylko fail-closed (`BRAVE_PROXY`, `OSINT_PROXY`, `BRAVE_REQUIRE_PROXY`; sonda przed pierwszym zapytaniem, `proxy_down` w trakcie, nigdy połączenie bezpośrednie ani samoczynna zmiana kanału; szczegóły w sekcji „Szukaj profili po nazwisku”). Brak scrapowania wyszukiwarek i prywatnych lub nieoficjalnych API. Dorki to tylko adresy do ręcznego otwarcia. Jedyna automatyczna wyszukiwarka to oficjalne Brave Search API z własnym kluczem operatora (`eg szukaj-profili`); bez klucza nic nie jest wysyłane. Klient ma uczciwy User-Agent, limit szybkości na host, limit rozmiaru odpowiedzi i przekierowania tylko na http/https.
- **Sekrety:** podprocesy narzędzi siostrzanych dostają środowisko bez zmiennych z `KEY`, `TOKEN`, `SECRET`, `PASSWORD`; w dzienniku zapisywany jest tylko fakt posiadania klucza HIBP. Klucz `BRAVE_SEARCH_API_KEY` trafia wyłącznie do nagłówka żądania do API (nie do argumentów, adresu, grafu, dziennika, raportu ani wyjścia).
- **Minimalizacja danych:** z RDAP nie bierze się osób fizycznych ani kontaktów; z profili nie bierze się treści bio ani lokalizacji (zostaje tylko odcisk bio: skróty słów do porównania podobieństwa). Dziennik i graf zawierają jednak wartości wejściowe (to dane osobowe, jeśli badasz osobę): przechowuj je zgodnie z celem badania i usuń po jego zakończeniu.

## Wyłączone z założenia: wyszukiwanie osoby po numerze telefonu

Narzędzie **nie zawiera** i nie będzie zawierać integracji z CallApp, Truecaller, Sync.me ani żadną inną usługą "numer na osobę" (caller ID, książki kontaktowe, odwrotne wyszukiwanie). Powody: (1) brak oficjalnego API dla takiego użycia, a nieoficjalne wymagałyby scrapingu lub podszywania się pod aplikację; (2) dane pochodzą z książek adresowych użytkowników wgranych bez wiedzy osób, których dotyczą; (3) regulaminy tych usług zabraniają automatycznego i zawodowego wyszukiwania; (4) przetwarzanie takich danych bez podstawy to ryzyko wobec RODO (art. 5 i 6). Transformacja `phone_metadata` zwraca wyłącznie metadane z publicznego planu numeracji i nie tworzy węzłów osób. Test `test_no_caller_id_or_phone_to_person_transforms` pilnuje, że to się nie zmieni po cichu. Do numeru własnego lub firmowego służy `phone-check`, do operatora aktualnego baza UKE (ręcznie).

## Eksport

- **GraphML:** standardowy format (węzły z `label`, `type`, `value`, `attrs`; krawędzie z `relation`, `confidence`, `evidence`, `timestamp`). Sprawdzono poprawność XML (znaki niedozwolone w XML są usuwane); import do Gephi/yEd to zwykłe GraphML. Nie testowano importu do Maltego: jeśli Twoja wersja wymaga własnego mapowania encji, użyj `graph.json` lub tabeli z raportu.
- **CSV dla Maltego** (`maltego.csv` w sprawie, zapis atomowy, albo `eg export graph.json --maltego plik.csv`): krawędzie jako pary encji. Kolumny: `source_type`, `source_value`, `relation`, `target_type`, `target_value`, `confidence`, `evidence`, `source`, `timestamp_utc` (zgodnie z wcześniejszym formatem) oraz dopisane na końcu `source_id`, `target_id` (id węzłów grafu), `derivation` (`direct`/`inferred`, tylko dla krawędzi z importu org-intel; poza tym pusta, nic nie jest zgadywane), `evidence_hash` (sha256 dowodu z provenance; gdy brak pełnego skrótu, skrócony zapis z tekstu dowodu; pusta, gdy dowodu nie ma) i `evidence_ref` (refy skarbca dowodów, rozdzielone spacją). Typy: `maltego.Person`, `maltego.Alias`, `maltego.PhoneNumber` itd.; import: *Import Graph from Table* z mapowaniem kolumn `*_type`. Format: UTF-8 bez BOM (Excel: Dane > Z tekstu, kodowanie UTF-8), wiersze kończone `\r\n`, wartości bez CR/LF i znaków sterujących (zamieniane na spację), przecinki i cudzysłowy cytowane. Węzły typu Email nie są eksportowane (zamaskowana wartość zlałaby różne adresy w jedną encję Maltego); adres e-mail w każdej innej komórce zastępuje `[e-mail ukryty]`, a komórka z sekretem (JWT, Bearer, klucz prywatny, bcrypt, e-mail:hasło, hasło w URL, `password=...`) cała staje się `[usunięto: sekret]`. Komórki zaczynające się od `=` lub `@` (także po spacjach) dostają apostrof, a od `+`/`-` tylko wtedy, gdy nie są samą liczbą lub numerem (ochrona przed formułami w arkuszach; numer `+48 603 123 456` zostaje wartością encji). `eg export --maltego` nie nadpisuje istniejącego pliku (błąd, kod 2; wyjątek: jawne `--force`) i odmawia zapisu do plików sprawy (`graph.json`, `audit.jsonl` itd.) oraz do pliku wejściowego; plik tymczasowy powstaje trybem `x`, więc cudzy plik o tej nazwie nie jest ruszany. Nie testowano na licencji Maltego: mapowanie kolumn ustawiasz przy imporcie.
- **Raport HTML:** jeden plik, bez JavaScriptu i zewnętrznych zasobów, CSP `default-src 'none'`, cała treść z cudzych źródeł escapowana, linki tylko http/https z `rel="noopener noreferrer nofollow"`. Sekcje: cel i zakres, podsumowanie, uruchomienia ze statusami, powiązania "ta sama osoba", linki do ręcznego przeglądu, węzły, krawędzie (do 3000 wierszy), czego narzędzie nie robi.

## Kropki (`eg kropki`)

`eg kropki graph.json` rysuje graf jako statyczny SVG (domyślnie `kropki.svg` obok `graph.json`; offline, bez JS, teksty escapowane). Węzeł to kropka w kolorze typu, większa przy większej liczbie połączeń; linia jest grubsza przy wyższej pewności, przerywana dla hipotez (pewność 0). Po najechaniu na kropkę lub linię widać wartość, relację i dowód. Układ siłowy jest deterministyczny (ten sam graf = ten sam rysunek). Przy więcej niż `--max-nodes` węzłach zostają najbardziej połączone, a legenda podaje, ile pominięto. `--min-confidence` ukrywa słabe krawędzie. Rysunek to podgląd, nie dowód: położenie kropek nic nie znaczy, liczą się linie i ich dowody.

## Teczka osoby: potwierdzanie profili (`eg przeglad`, `eg potwierdz`)

Praca jak w Maltego: narzędzie podsuwa profile, a decyzję "to ta osoba" podejmuje operator. Dopiero potwierdzenie łączy dane z profilu z osobą.

```
eg run --purpose "due diligence ..., zlecenie 2026/7" --person "Jan Kowalski" --expand-candidates --ue-tags social,pl --out sprawa
eg przeglad sprawa --person "Jan Kowalski"
```

1. `przeglad` pokazuje po kolei kandydatów: profile znalezione z nazw użytkownika wygenerowanych z imienia i nazwiska (od najwyższej pewności konta), z serwisem, nazwą wyświetlaną, stroną www, linkami i informacją, skąd się wziął. Odpowiedź: `t`ak, `n`ie, `p`omiń, `k`oniec.
2. Przy `t` i `n` trzeba podać dowód (co się zgadza lub nie: zdjęcie, firma, miasto, wzajemne linki). Decyzja z dowodem i operatorem trafia do `audit.jsonl` (wpis `decision`).
3. Potwierdzenie tworzy krawędź `confirmed_profile` (pewność 0.9: ocena człowieka, nie dowód tożsamości). Dane z profilu, czyli nazwa użytkownika, e-mail, domena i inne węzły niebędące profilami, łączą się z osobą krawędzią `via_confirmed_profile`. Pewność jest nie wyższa niż krawędź profilu, a dowód mówi, przez który profil. Własna strona www z profilu (0.6) i linki do domen spoza dużych platform (0.5) stają się węzłami Domain osoby. Takie domeny znikają z grafu po odrzuceniu profilu, chyba że znało je też inne źródło.
4. **Inne profile** powiązane z potwierdzonym (`same_person` z korelacji) nie są dołączane same: wracają w `przeglad` jako nowi kandydaci.
5. Odrzucenie (`rejected_profile`) albo zmiana decyzji usuwa dane dołączone przez ten profil. Przeliczenie jest idempotentne.

`eg potwierdz` robi jedną decyzję bez pytań, a `--dodaj` dopisuje profil znaleziony ręcznie (np. z linków dorków w raporcie). Oba polecenia wymagają katalogu badania ze spójnym dziennikiem audytu (cel badania jest brany z dziennika) i osoby obecnej w grafie. Po każdej sesji odświeżane są `graph.json`, `graph.graphml`, `report.html` (sekcja **Teczka osoby**) i `kropki.svg` (potwierdzenia na zielono, odrzucone niewidoczne). Nic nie jest wysyłane do sieci. Żeby zbadać dane dołączone do osoby (np. domenę), uruchom dla nich nowe `eg run`.

## Sprawa: twierdzenia o relacjach, kontekst numeru, kandydaci profili

Polecenia działają na katalogu sprawy (`graph.json` + spójny `audit.jsonl`; cel sprawy pochodzi z pierwszego wpisu dziennika). Każda zmiana zapisuje w dzienniku wpis `phase: przed` (zanim cokolwiek zmieni; gdy się nie da, operacja się nie wykonuje) i `phase: po` z wynikiem (`zmieniono`, `bez zmian` albo `błąd`). Potem odświeżane są `graph.json`, `graph.graphml`, `report.html` i `kropki.svg`. Wspólny kod: `sprawa.py`. Przy każdej pozycji widać osobno trzy rzeczy: **status źródła**, **pewność powiązania** i **decyzję operatora**.

**Źródło** to publiczny adres `http(s)` (bez danych logowania) albo `dokument:ŚCIEŻKA` pliku, który już leży w katalogu sprawy (np. `dokument:dokumenty/akt.pdf`). Dla dokumentu zapisujemy ścieżkę względną, skrót SHA-256 i rozmiar; treść nie trafia ani do grafu, ani do dziennika. Źródło bez takiej referencji (`brak`, `od klienta`, `../plik`, `C:\...`, `javascript:...`) jest odrzucane.

### Twierdzenie o relacji (`eg relacja`, `eg relacja-potwierdz`)

Zapis informacji dostarczonej przez operatora, np. „Anna Kowalska jest rodzicem Jana Kowalskiego wg aktu z dokumentów klienta”. Narzędzie **nie szuka i nie wnioskuje** relacji: wspólne nazwisko, adres, numer telefonu, zdjęcie, znajomi ani podobne profile nie tworzą żadnego twierdzenia.

- Typy: `rodzic`, `dziecko`, `rodzenstwo`, `partner` (małżonek lub partner), `inna` (wymaga `--opis`). Wymagane: źródło, dowód (min. 2 słowa) i cel sprawy (z dziennika). Osoby muszą być w grafie; nową dopisuje się jawnie przez `--dodaj`.
- Nowe twierdzenie ma status `oczekuje` i pewność 0 (krawędź `claim_<rodzaj>`, źródło `relacje:<id>`). Kierunek jest zachowany: „A dziecko B” zapisuje się jako „B rodzic A”, a relacje symetryczne mają stałą kolejność osób. To samo twierdzenie dodane drugi raz (także w odwrotnej kolejności osób) nie tworzy drugiej krawędzi; inne źródło dopisuje się do tego samego twierdzenia.
- `relacja-potwierdz` wymaga **osobnego** uzasadnienia (nie można powtórzyć dowodu z twierdzenia). Potwierdzenie daje krawędź `confirmed_<rodzaj>` z pewnością 0.9: to ocena człowieka, nie dowód pokrewieństwa ani tożsamości. `--odrzuc` daje `rejected_<rodzaj>` z pewnością 0 i usuwa krawędź potwierdzenia (dane pochodne). Ta sama decyzja z tym samym uzasadnieniem to `bez zmian`; historia decyzji zostaje w twierdzeniu i w dzienniku.
- Kilka nieodrzuconych twierdzeń różnego rodzaju dla tej samej pary (np. „partner” i „rodzeństwo”) raport pokazuje jako **sprzeczne twierdzenia do wyjaśnienia**; narzędzie żadnego nie wybiera.
- Dodanie ani potwierdzenie niczego nie uruchamia: drugiej osoby nie bada się automatycznie. Osobne badanie to osobne polecenie z własnym celem i limitem.
- W raporcie sekcja **Twierdzenia o relacjach**, w `kropki.svg` linia fioletowa (przerywana, dopóki czeka na potwierdzenie; odrzucone nie są rysowane), w GraphML krawędź z relacją i dowodem. Szczegóły (źródła, fragmenty, decyzje) są w `graph.json` pod `meta.relation_claims`.

Błędne odczytanie, którego trzeba unikać: „potwierdzone” znaczy „operator sprawdził źródło i uznał je za wiarygodne”, a nie „narzędzie ustaliło rodzinę”.

### Kontekst numeru (`eg telefon`)

Wynik `phone-check` (offline) dołączony do sprawy jako obserwacje węzła Phone: numer E.164, poprawność i możliwość w planie numeracji, kraj i **region planu numeracyjnego**, typ linii, pierwotny przydział operatora z ostrzeżeniem o przenoszeniu numerów, strefy czasowe planu, źródło i czas obserwacji (`phone_context_log`). Import tego samego wyniku drugi raz nic nie zmienia (rozpoznanie po skrócie SHA-256), a numer jest jednym węzłem.

- Dla numeru komórkowego region planu numeracyjnego to **tylko kraj**: opis miasta lub województwa z biblioteki nie jest zapisywany. Dla stacjonarnego to obszar numeru kierunkowego. Przykład błędnej interpretacji: „+48 22... → Warszawa” znaczy, że pulę przydzielono strefie 22, nie że urządzenie albo osoba jest w Warszawie.
- `phone-check` podaje link do oficjalnej weryfikacji aktualnego operatora (baza UKE): raport i panel pokazują go jako link otwierany przez Ciebie, nic go nie otwiera automatycznie. Wynik takiej ręcznej weryfikacji dopisujesz przez `--operator-aktualny ... --zrodlo ... --data ...` jako **osobną** obserwację (`phone_carrier_manual`). Operator z planu numeracji nie jest nadpisywany i nikt nie rozstrzyga, czy numer przeniesiono.
- Dwa źródła z różną wartością (np. dwie ręczne weryfikacje z innym operatorem albo wyniki z dwóch wersji biblioteki) dają **konflikt obserwacji**: pole staje się nieznane, a obie wartości ze źródłami widać w raporcie.
- Numer nie jest wiązany z osobą. Nie ma i nie będzie danych o położeniu urządzenia, właściciela numeru ani usług „numer na osobę”.

Zgodność formatu: pola telefonu doszły do modelu obserwacji bez zmiany `schema: 1` i `observation_model: 1`. Każdy starszy `graph.json` czyta się bez zmian (stary atrybut `phone_geo_description` jest pokazywany jako region planu, dla komórkowego tylko kraj). Plik z obserwacjami pól telefonu nie wczyta się w wersji entity-graph sprzed tej zmiany: odrzuci nieznane pole zamiast zgadywać.

### Kandydaci profili (`eg kandydaci`)

Jedna jawnie uruchomiona runda dla osoby (jej kandydaci nazw z `person_candidates`; brak = wygenerowanie ze wzorców) albo dla nazwy użytkownika z grafu. Każda nazwa to jedno wywołanie `username_scan` (username-engine) w budżecie: zapytania (do 10), koszt (do 50, skan = 5), czas (do 1800 s), nazw w rundzie (do 12), rund w sprawie (do 10). Limity są sprawdzane w entity-graph niezależnie od panelu.

- Trafienia FOUND to **kandydaci** do ręcznego przeglądu (krawędź `candidate_match`, pewność 0) i pojawiają się w `eg przeglad`. NOT_FOUND, UNKNOWN i ERROR zostają ze swoim znaczeniem w raporcie rundy i w `graph.runs`. Opisują źródło, a nie osobę.
- Ocena (ta sama reguła co w `eg rozszerz`) opisuje tylko techniczne dopasowanie profilu: sama zgodna nazwa użytkownika, imię i nazwisko, awatar albo serwis to co najwyżej „wymaga przeglądu”. Sprzeczność osoba/organizacja ogranicza ocenę, a zasady `same_person` pozostają bez zmian.
- Profil z osobą łączy wyłącznie `eg potwierdz` (dowód wymagany). Potwierdzenie niczego nie skanuje. Nazwy z mocno dopasowanych kandydatów trafiają do raportu jako **propozycje**: kolejna runda to osobne polecenie `eg kandydaci --username PROPOZYCJA`.
- Facebook, Instagram, Threads i LinkedIn nie są sprawdzane automatycznie: nazwa dostaje tylko linki do ręcznego otwarcia (sekcja „Linki do ręcznego przeglądu”). Z profili zostają wyłącznie pola minimalne (URL, nazwa wyświetlana, skrót awatara, strona www, linki, typ encji, odcisk bio).

Przykład błędnej interpretacji: „jan.kowalski na serwisie X = profil Jana Kowalskiego”. Takich kont jest wiele, a trafienie to tylko kandydat.

**Retencja:** entity-graph nie ma wspólnej retencji. Katalog sprawy (graf, raport, dziennik, dokumenty) zawiera dane osobowe: usuń go ręcznie po zakończeniu celu, np. `Remove-Item -Recurse panel\wyniki\sprawy\NAZWA`. Pliki tymczasowe skanów są kasowane od razu po rundzie.

## Szukaj profili po nazwisku (`eg szukaj-profili`, `eg material-profilu`)

Przepływ bez integracji Meta: imię i nazwisko -> linki do możliwych profili z oficjalnego **Brave Search API** -> analiza
materiału, który faktycznie jest dostępny (fragment wyniku wyszukiwarki albo tekst wklejony przez operatora) -> karty
kandydatów w sprawie -> decyzja operatora (`eg potwierdz`). **Nie znajduje wszystkich kont i nie ustala tożsamości.**

**Konfiguracja klucza** (własne konto u dostawcy, jego limity i regulamin): zmienna `BRAVE_SEARCH_API_KEY` albo plik
poza repozytorium `%USERPROFILE%\.osint\brave.env` (inna ścieżka: `BRAVE_SEARCH_ENV_FILE`) z linią
`BRAVE_SEARCH_API_KEY=...`. Plik w katalogu repozytorium jest odrzucany. Kanał (fail-closed): `BRAVE_PROXY=http://host:port`
(wtedy wyłącznie przez to proxy, niedostępne proxy = błąd, nigdy połączenie bezpośrednie); `BRAVE_REQUIRE_PROXY=1`
albo ustawiony `OSINT_PROXY` (kanał Tor/proxy zestawu; panel ustawia go domyślnie) wymagają proxy. `OSINT_PROXY`
w postaci `http://host:port` jest użyty jako kanał; SOCKS (Tor, np. `socks5h://127.0.0.1:9150`) bez `BRAVE_PROXY` =
odmowa, bo transport obsługuje tylko proxy HTTP (dla Tora: `HTTPTunnelPort` w torrc i `BRAVE_PROXY=http://127.0.0.1:PORT`).
Przed pierwszym zapytaniem sprawdzana jest osiągalność proxy (samo połączenie TCP z proxy); nieosiągalne = zero zapytań.
Błąd połączenia przez proxy w trakcie (timeout, błąd transportu) zatrzymuje przebieg bez ponowień (`proxy_down`).
Wymóg proxy (`BRAVE_REQUIRE_PROXY`) wyłącza tylko jawne `0`/`false`/`no`/`nie`/`off`; każda inna wartość (także literówka) go włącza. Przy wymaganym proxy zmienne systemowe `HTTP(S)_PROXY`/`NO_PROXY` nie mają wpływu (trasa przypięta do jednego proxy); bez wymogu i bez `BRAVE_PROXY` transport używa proxy systemowego, jeśli jest ustawione. Jedno stałe proxy na cały przebieg, stały uczciwy User-Agent, bez rotacji IP, bez podrabiania odcisku przeglądarki i bez samoczynnego przejścia na Tor albo połączenie lokalne. Login i hasło z adresu proxy nie trafiają do komunikatów, audytu ani raportu.
Brak klucza albo błędna konfiguracja: kod wyjścia 3, zero ruchu, sprawa bez zmian.

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
python -m entity_graph szukaj-profili ..\panel\wyniki\sprawy\NAZWA --person "Jan Kowalski" --kontekst "Kraków"
python -m entity_graph material-profilu ..\panel\wyniki\sprawy\NAZWA --person "Jan Kowalski" `
       --url https://www.instagram.com/przyklad/ --tekst "tekst skopiowany przez operatora"
python -m entity_graph potwierdz ..\panel\wyniki\sprawy\NAZWA --person "Jan Kowalski" `
       --profil https://instagram.com/przyklad --dowod "co sprawdziłeś" [--odrzuc]
```

- **Zapytania** (deterministyczne, konektor `brave_search` z `osint-connectors`): `"Imię Nazwisko" site:facebook.com`,
  `site:instagram.com`, `site:threads.com`; potem wariant z kontekstem (jeśli podany); potem wariant bez polskich znaków
  (tylko gdy różny). Nazwa: 2-6 słów z liter (bez cudzysłowów, `:` i operatorów); kontekst: do 5 słów, zapisywany
  małymi literami. Warianty nie są nickami. Bez stronicowania.
- **Limity backendu** (domyślnie / maks.): wywołania API 6 / 12 (ponowienie po timeoucie lub błędzie sieci też się
  liczy), wyników na wywołanie 20 / 20 (limit dostawcy), unikalnych kandydatów 50 / 100, czas 60 / 120 s. Limit kosztu
  to liczba wywołań, nie kwota. Czas jest twardy: każde wywołanie dostaje najwyżej czas pozostały do końca przebiegu,
  a transport (`UrllibClient`) przerywa zablokowane albo powolne połączenie po terminie. Gdy zostaje mniej niż 1 s,
  kolejne zapytania i ponowienia nie startują („limit czasu przebiegu”), a zebrani kandydaci są zapisywani.
  Odpowiedź-dokument błędu albo nieznana struktura to ERROR „uszkodzona odpowiedź”, nigdy NOT_FOUND; rekordy
  uszkodzone w liście mieszanej są pomijane i liczone (`broken_records` w wierszu zapytania).
- **Statusy zapytania**: FOUND (wyniki), NOT_FOUND (brak wyników *tego zapytania*, nie brak kont), ERROR z przyczyną:
  brak autoryzacji (401/403), limit dostawcy (429), timeout, uszkodzona odpowiedź, odrzucone zapytanie (400/422),
  błąd sieci/proxy/5xx. Po 401/403/429 dalsze zapytania są pomijane z powodem. Wyniki częściowe zostają w sprawie.
- **Adresy**: tylko http(s), bez danych logowania; serwis po faktycznej nazwie hosta (`facebook.com.example.org` to nie
  Facebook). Kanonizacja usuwa śledzenie, zostawia identyfikatory (`profile.php?id=` z różnym `id` to różne adresy).
  Małe litery tylko w hoście, słowach kluczowych ścieżki i nazwach kont (Facebook, Instagram, Threads); kody postów
  (`/p/AbCd123`, `/reel/...`, `/post/...`) i nierozpoznane ścieżki zachowują pisownię, więc `/p/AbC` i `/p/abc` to dwa
  rekordy. Adres z kontaktem, danymi logowania albo sekretem (e-mail, telefon, `token=`, `password=`, `email=` itp.
  w ścieżce, zapytaniu lub fragmencie) jest odrzucany z przyczyną: wynik wyszukiwarki trafia do „odrzucone adresy”
  (tylko host), `--url` operatora kończy się kodem 2 bez zapisu, adres w materiale jest pomijany i liczony. Adresu nie
  „poprawiamy”. To heurystyka struktury adresu, nie pełny filtr (np. sekret jako zwykły segment ścieżki przejdzie).
  Klasa adresu: prawdopodobny profil / post lub treść / grupa / strona organizacji / nieustalony. Tylko „prawdopodobny
  profil” i „nieustalony” dostają krawędź `candidate_match` (pewność 0) i przyciski decyzji; post, grupa i strona
  organizacji to `mentioned_in_result`, nie konto osoby. Ten sam adres z kilku zapytań = jeden kandydat z wieloma
  obserwacjami (pochodzenie zachowane); osób się nie scala. Wspólny adres dwóch osób to dwie karty: obserwacje, ocena
  dopasowania i domyślny cel decyzji należą do pary osoba-adres (raport ma kolumnę „Osoba”, panel nagłówek „Osoba:”).
- **Analizator** (`profile_analyzer.py`, lokalny, bez LLM): jawne adresy w tekście (propozycje, nic nie uruchamiają),
  identyfikatory profili z tych adresów, para „Nazwa (@nick)”, wzmianka szukanej nazwy. Każde ustalenie ma dowód
  (dosłowny dopasowany fragment, bez otoczenia), pozycję w materiale, metodę, czas i źródło. Nie wyciąga zawodu,
  miejsca, bio, relacji ani ocen. Pusty materiał = „brak materiału do analizy”. Fragment wyszukiwarki jest
  opisany jako fragment, nie odczyt profilu; tekst operatora jako niezweryfikowana kopia strony (do 20 000 znaków).
- **Zapis (zakres pozytywny, od R5A)**: `graph.json` -> `meta.profile_discovery` (przebiegi i kandydaci: adresy,
  SHA-256 i długość materiału, ustalenia z dowodem, pominięte adresy z przyczyną), węzły URL, krawędzie;
  `audit.jsonl` -> `profile_search`/`profile_material` (przed/po); raport HTML -> sekcja „Wyszukiwanie profili po
  nazwisku”. Tekst materiału (tytuł i fragment wyszukiwarki, tekst operatora) jest analizowany w pamięci i **nie jest
  zapisywany** w żadnym pliku sprawy; pełne odpowiedzi API też nie. Nie jest to filtr danych wrażliwych: zapisuje się
  po prostu tylko lista dozwolonych ustaleń. Ponowny import tego samego materiału dla tej samej osoby = „bez zmian”;
  ten sam materiał dla innej osoby dostaje jej własną analizę. Decyzje operatora nie są przez import zmieniane.
- **Sprawy sprzed R5A** mogą zawierać pola `title`, `excerpt` (fragment do 300 znaków) i `redacted_contacts`
  w `graph.json` oraz ich kopie w `report.html`, a także adresy z kontaktem w zapytaniu (np. `?email=`) jako węzły URL,
  `source_urls`, `source_url`/`source` ustaleń, w `graph.graphml`/`kropki.svg` i w polu `url` wpisów
  `profile_material` w `audit.jsonl`. Odczyt działa, raport oznacza stare fragmenty „fragment zapisany przed R5A”, ale
  poprawka **niczego nie przepisuje ani nie usuwa** w istniejących plikach. Oczyszczenie `graph.json`: kopia zapasowa,
  usunięcie pól `title`/`excerpt`/`redacted_contacts` z `meta.profile_discovery.items.*.observations` (i ewentualnie
  kandydatów z niebezpiecznym adresem), potem dowolna operacja zapisu w sprawie odtworzy `report.html`, `graph.graphml`
  i `kropki.svg`. `audit.jsonl` jest łańcuchem skrótów: edycja przerywa weryfikację (`eg` odmówi otwarcia sprawy),
  więc jeśli dziennik zawiera taki adres, jedyną czystą drogą jest usunięcie całej sprawy i założenie nowej.
- **Usunięcie danych**: wszystko leży w katalogu sprawy; usunięcie sprawy (`Remove-Item -Recurse
  panel\wyniki\sprawy\NAZWA`) usuwa też kandydatów, fragmenty i dziennik. Starsze sprawy bez tej sekcji otwierają się
  bez zmian.
- **Pokrycie**: tylko to, co indeks Brave zwróci dla zapytań `site:` (operatory dostawca opisuje jako eksperymentalne);
  profile prywatne, nieindeksowane albo pod inną nazwą nie pojawią się. Brak wyniku niczego nie dowodzi.

## Asystent sprawy i dziennik (`eg asystent`, `eg dziennik`)

`eg asystent KATALOG` czyta widok sprawy i zwraca JSON: **porządek** (osoby, nazwy od operatora i hipotezy ze wzorców osobno, twierdzenia wg decyzji, kandydaci bez decyzji, przebiegi źródeł wg statusu, źródła), **sprzeczności** (sprzeczne twierdzenia o relacjach, profil potwierdzony dla kilku osób, sprzeczne obserwacje) i **kroki** wyłącznie z zamkniętej listy `ALLOWED_STEPS` (decyzja o profilu lub relacji, wyjaśnienie sprzeczności u źródła, powtórzenie po błędzie, runda kandydatów, plan numeracyjny, dodanie źródła). Reguły nie zmieniają sprawy.

`--ai` dodaje uporządkowanie przez lokalny model Ollama (`EG_AI_MODEL`, domyślnie `qwen3.5:9b`; `EG_AI_URL`, domyślnie `http://127.0.0.1:11434`). Zasady: adres tylko http na tym komputerze (inny host, dane logowania w adresie lub zły port = błąd), bez proxy i bez przekierowań; model dostaje wyłącznie liczby, rodzaje sprzeczności i numerowane kroki z listy (`ai_payload`): bez imion, adresów, numerów, wartości obserwacji z cudzych profili, opisów operatora, materiałów i plików dowodów; zasady są powtórzone po danych. Linie z twierdzeniem o tożsamości („ta sama osoba”, „należy do…”, „potwierdzono istnienie…”) albo z krokiem poza granicami (logowanie, CAPTCHA, lokalizacja, twarze, wycieki, podszywanie) są usuwane i liczone, także gdy twierdzenie jest rozbite na dwie linie (normalizacja NFKC, bez znaków zerowej szerokości i markdown). Filtr to czarna lista, więc nie jest gwarancją: odpowiedź jest zawsze oznaczona jako niezweryfikowana i nie trafia do grafu. W dzienniku audytu są dwa wpisy `asystent_ai`: `przed` (model, adres, SHA-256 wysyłanych danych) i `po` (status, SHA-256 tekstu, liczba usuniętych linii; bez treści). Status: `FOUND` (jest tekst), `UNKNOWN` (Ollama niedostępna), `ERROR` (błąd lub limit czasu).

`eg dziennik KATALOG [--limit N]` zwraca spójność łańcucha skrótów i ostatnie wpisy dziennika (bez pola `prev`); panel pokazuje to jako „Dziennik audytu”.

## Zależności od narzędzi siostrzanych

`username-engine`, `dns-audit` i `phone-check` są uruchamiane jako podprocesy w ich własnych środowiskach (`.venv` narzędzia, jeśli istnieje; inaczej bieżący interpreter z `PYTHONPATH` na `src` narzędzia). `hibp-monitor` i `osint-connectors` (konektor `brave_search`) są importowane (sama stdlib). Folder z narzędziami: domyślnie rodzic `entity-graph`, zmiana: zmienna `ENTITY_GRAPH_TOOLS_DIR`. Brak narzędzia = UNKNOWN z komunikatem, reszta badania idzie dalej. Baza `username-engine` musi być zbudowana (`scripts/build_db.py`).

## Ograniczenia

- Wynik zależy od dostępności i limitów publicznych API (`rdap.org`, `crt.sh` bywa przeciążony, RIPEstat, InternetDB). Przy błędzie dostajesz ERROR, nie zgadywanie.
- `rdap.org` nie obejmuje końcówek bez serwera RDAP w bootstrapie IANA: `domain_rdap` zwróci wtedy UNKNOWN (`.pl` działał przy ręcznym sprawdzeniu 2026-10-03).
- Dane Shodan InternetDB i CVE z niego to cudze, możliwe nieaktualne skany.
- Skan `username-engine` bez `--ue-tags` trwa kilka minut na jedną nazwę; każdy kandydat z `--expand-candidates` to pełny skan.
- Korelacja jest ostrożna i mało czuła: brak sygnału nie znaczy, że konta należą do różnych osób.
- Wykrycie Gravatara ujawnia tylko, że dla adresu istnieje awatar.
- Raport i graf nie zastępują oceny prawnej celu badania; operator odpowiada za podstawę przetwarzania.
- Windows: ścieżki i `.cmd` sprawdzone na Windows 11; na innych systemach `START_ENTITY_GRAPH.cmd` nie działa, reszta tak.

## Testy

`py -m pytest -q` (około 370 testów, bez internetu; w tym symulowane rozszerzanie rekordów `tests/test_expand.py` i spójność oceny z username-engine `tests/test_evidence_consistency.py`): normalizacja i model, klient HTTP wobec lokalnego serwera na 127.0.0.1, wszystkie transformacje na fixture'ach z atrapami fetchera i podprocesów, korelacja i jej limity, importery plików i reguły łączenia kropek (fixture'y w `tests/fixtures/import/`, syntetyczne wartości), podkomenda `polacz`, silnik (głębokość, limity, wyjątki jako ERROR, tryb offline), zabezpieczenia i dziennik audytu (w tym wykrywanie manipulacji), eksport GraphML i HTML z wrogimi danymi, CLI, test end-to-end przez lokalny serwer oraz jeden test uruchamiający prawdziwy `phone-check` (offline; pomijany, gdy brak jego `.venv`).

Test **sieciowy** jest osobny i domyślnie pomijany: `EG_NETWORK_TESTS=1 py -m pytest -q tests/test_expand_network.py` (prawdziwy `username-engine`, publiczne konto organizacji `mozilla`, 30 serwisów z kategorii coding, jedna runda). Sprawdza kontrakt na prawdziwych odpowiedziach, nie skuteczność dopasowania.

## Import z org-intel (`eg import-org-intel`)

Wczytuje do sprawy rejestr firm, domen i incydentów z pakietu `org-intel` (offline, bez sieci, bez zależności). Wejście: plik JSON z `org-intel export --format json` albo lokalny `store.json` (format rozpoznawany po zawartości: `schema_version` 1, sekcje `sources/organizations/domains/persons/incidents/observations` oraz `exported_at` albo `verifications`). Ten sam format rozumie też `polacz` (bez rankingu, deduplikacji i wykrywania kolizji względem sprawy, patrz Ograniczenia).

```
entity-graph import-org-intel --input eksport.json --case KATALOG_SPRAWY [--dry-run] [--strict]
                              [--format text|json | --json] [--report raport.json] [--operator ...]
```

Sprawa jest otwierana jak w pozostałych poleceniach (dziennik audytu musi być spójny), a scalenie idzie przez `sprawa.audited` (wpisy `org_intel_import` przed/po: nazwa pliku, SHA-256, `import_id`, liczby; nigdy treść rekordów ani adresy e-mail). `--dry-run` liczy to samo na kopii grafu w pamięci i nie zapisuje niczego (ani plików sprawy, ani dziennika); raport zaczyna się od `DRY-RUN: nic nie zapisano`.

**Opcje raportu i trybu**
- `--format text|json`: format raportu na ekranie (domyślnie `text`); `--json` to alias `--format json`. Jednoczesne `--json --format text` to błąd użycia (kod 2).
- `--report ŚCIEŻKA`: zapis raportu JSON wyłącznie do NOWEGO pliku (plik tymczasowy + `os.link`, które nie nadpisuje istniejącego celu); istniejący plik nie jest nigdy nadpisywany. Katalog docelowy musi istnieć. Kodem 2, przed czymkolwiek innym i również przy `--dry-run`, odrzucane są: nazwy zastrzeżone dla plików sprawy (`graph.json`, `audit.jsonl`, `graph.graphml`, `maltego.csv`, `report.html`, `kropki.svg`) w dowolnym katalogu, bez względu na wielkość liter, kropki/spacje na końcu i strumień `:x`; ścieżka w katalogu bieżącej sprawy oraz w katalogu DOWOLNEJ sprawy albo jego podkatalogu (katalog z `graph.json` lub `audit.jsonl`); plik `--input`; każdy istniejący plik (także symlink lub twarde dowiązanie). Ścieżki są sprawdzane po rozwiązaniu `..`, ścieżek względnych, symlinków i junctionów. Raport zawiera liczby, etykiety odrzuconych rekordów (rodzaj + identyfikator org-intel + nazwa tylko, gdy nie wygląda na sekret ani e-mail) i powody, bez danych osobowych. Zapisywany także przy `--dry-run` i przy odmowie `--strict`.
- `--strict`: pierwsze odrzucenie (także nieznane pole rekordu, patrz niżej) = odmowa: kod 5, nic nie zapisano. Decyzja zapada PRZED `sprawa.audited`, więc w dzienniku nie ma żadnego wpisu (`graph.json` i `audit.jsonl` zostają bajtowo takie same). Świadoma decyzja: dziennik audytu notuje zmiany sprawy, a odmowa jej nie zmienia; zapis do łańcucha skrótów byłby sam w sobie zapisem, którego `--strict` ma nie robić. Ślad odmowy to kod 5, raport na ekranie i w `--report` (z `import_id`).

**Mapowanie** (bez nowych typów encji):

| org-intel | graf | atrybuty |
|---|---|---|
| organizacja | Organization (wartość = nazwa prawna) | `kind=company`, `krs`, `nip`, `regon`, `previous_names`, `country`, `status` (znormalizowany: `aktywna`, `zawieszona`, `w_likwidacji`, `w_upadlosci`, `w_restrukturyzacji`, `wykreslona`, `inny`), `status_raw`, `registered_address` (adres siedziby osoby prawnej; maskowanie e-maili jak w innych polach tekstowych; opcjonalne, nowsze eksporty org-intel), `org_intel_id`, `provenance` |
| domena | Domain | `verification_status`, `verified_at` (tylko z `verified`), `org_intel_id`, `provenance` |
| incydent | Organization `kind=breach` (wartość = tytuł, a bez niego nazwa: ten sam klucz co import hibp-monitor) | `breach_name`, `incident_date`, `published_date`, `affected_domain`, `affected_accounts_count`, `data_classes`, flagi `is_verified/is_fabricated/is_spam_list/is_sensitive/is_retired/is_malware/is_stealer_log` (tylko prawdziwe), `description` (bez HTML, do 2000 znaków), `org_intel_id`, `provenance` |
| źródło | URL `kind=source` (nie `profile`) | `source_url_original`, `source_category`, `source_type`, `retrieved_at`, `reliability`, `license`, `content_hash`, `quality` |
| osoba | **pomijana** | licznik „pominięte: osoba – poza zakresem importu” |

**Relacje**: `owns_domain` (Organization → Domain, z `organization_id` domeny), `associated_with_incident` (Domain → Incydent: ta sama domena = `direct`, incydent na subdomenie domeny znanej w eksporcie = `inferred`, jak w `org-intel/correlate.py`), `has_source` (Organization/Domain/Incydent → URL źródła). Nie powstaje żadna krawędź z ani do Person, Email, Username i Phone (twarda asercja w importerze i testy). `Edge.source` = `org-intel:<znormalizowany URL źródła>`; pewność: high 0,9, medium 0,6, low 0,3, a `inferred` najwyżej 0,6; dowód: `direct|inferred; typ źródła; czas; URL oryginalny; evidence_hash=<12 znaków>`; znacznik czasu = najwcześniejsza obserwacja z tego źródła.

**Proweniencja** (`provenance` w atrybutach): lista `{source_url_original, source_url_normalized, source_name, source_type, source_category, retrieved_at, confidence, derivation, evidence_hash, quality, import_id}` bez duplikatów po `(source_url_normalized, derivation)`. `source_url_original` to adres dokładnie w postaci zapisanej przez org-intel; org-intel w `store.json` i eksporcie przechowuje już własną normalizację (bez `#fragmentu`, parametrów `utm_*` i końcowego `/`), więc „oryginał” oznacza ten zapisany adres, nie wejście sprzed `org-intel ingest`. `source_url_normalized` to klucz entity-graph (bez schematu i `www.`), służy tylko do deduplikacji i identyfikacji węzła URL. GraphML, Maltego CSV i HTML zachowują URL, czas, pewność i `direct/inferred` w krawędziach, a GraphML także całą listę `provenance` w atrybutach węzła.

**Identyfikator importu (`import_id`)**: `imp_<12 hex z sha256(skrót pliku + czas importu)>`, stabilny w obrębie jednego uruchomienia; jest w raporcie, we wpisach audytu (przed i po) i w każdym nowo wnoszonym wpisie `provenance`. Żeby nie łamać idempotencji, wpis `provenance` zostaje z `import_id` PIERWSZEGO importu, który go wniósł: przy ponownym imporcie istniejący wpis wygrywa (ta sama pewność), więc graf się nie zmienia, a raport pokazuje nowy `import_id` z liczbami „bez zmian”. Wpis z wyższą pewnością zastępuje starszy razem z jego `import_id`.

**Idempotencja i „nie nadpisuj lepszego gorszym”**: ponowny import tego samego pliku (także pod inną nazwą) nie zmienia węzłów, krawędzi ani atrybutów; raport pokazuje wtedy „bez zmian”, a plików sprawy się nie przepisuje. Wyjątkiem jest `RunRecord` dopisywany przez `merge_into_graph` do `graph.runs` przy imporcie, który coś zmienia: to dziennik przebiegów, nie dane (dziennik audytu notuje każdy import). Skalary scala `merge_value` (pierwsza niepusta wartość), więc pola z rankingiem ustawia importer przed scaleniem: `verification_status` verified > pending > unverified > failed (`verified_at` tylko razem z `verified`), `affected_accounts_count` = maksimum, flagi `is_*` = OR, pewność krawędzi = maksimum (`_merge_edges`).

**Organizacje: identyfikatory i duplikaty**: KRS, NIP i REGON muszą mieć poprawny format i sumę kontrolną (NIP, REGON 9/14); niepoprawny identyfikator odrzuca organizację, nie jest wycinany. Firma jest dopasowywana po `krs`, potem `nip`, potem `regon` do organizacji istniejącej w sprawie ORAZ do wcześniejszych rekordów z tego samego pliku: powstaje jeden węzeł (zostaje dotychczasowa nazwa, nowa trafia do `previous_names`, brakujące identyfikatory są uzupełniane). Ten sam identyfikator przy sprzecznym innym (np. ten sam KRS, inny NIP) odrzuca późniejszy rekord z powodem. Dopiero potem działa klucz po nazwie.

**Odrzucenia** (rekord odrzucony nie blokuje reszty, chyba że `--strict`; raport podaje etykietę i powód):
- proweniencja: brak `source_ids`, nieistniejące źródło, brak obserwacji, brak `derivation`/`confidence`/`reliability`/`verification_status` albo wartość spoza enuma (bez wartości domyślnych, wielkość liter ma znaczenie), źródło bez nazwy, typu z listy, adresu http/https, `retrieved_at`;
- sekrety: klucze `password/token/...`, JWT, Bearer, bcrypt, para `e-mail:hasło`, klucz prywatny, hex 32/40/64 poza `content_hash`/`evidence_hash`/URL;
- **URL**: dane logowania (`user:hasło@`, `user@`) i w ogóle `@` w URL źródła oraz `evidence_url`, także zakodowane jako `%40` (również podwójnie, `%2540`), powodują ODRZUCENIE rekordu (sprawdzany jest surowy napis przed normalizacją; dane logowania nigdy nie są po cichu usuwane). Przyjmowany jest wyłącznie HTTPS na porcie 443: `http://` albo inny port = odrzucenie;
- **hosty**: adresy IP w każdej postaci (IPv4, dziesiętny `http://2130706433/`, szesnastkowy/ósemkowy, IPv6 `[::1]`), `localhost`, `*.localhost`, `*.local`, `*.internal`, `.onion`, `.i2p`, host bez kropki oraz znane fora i rynki wycieków (raidforums, breachforums, xss.is, exploit.in, nulled, cracked.io, leakbase, dread; host, subdomeny i słowa w hoście; `LOCAL_SUFFIXES` i `FORUM_*` w module); do tego dotychczasowe reguły wycieków (dla `cert_advisory`, `official_document` i `hibp_catalog` słowa sprawdza się tylko w hoście, więc `https://cert.pl/posts/2026/10/demo-wyciek-stealer/` przechodzi, a `https://t.me/x` nie). `evidence_url` przechodzi przez te same blokady hostów i sygnały wycieku co URL źródła (pastebin, t.me, słowa dump/leak/stealer w hoście, .onion, IP, localhost, sieci prywatne); słowa sprawdza się w całym adresie, chyba że źródło jest typu opisującego wycieki albo host `evidence_url` należy do allowlist instytucji (rejestry, CERT/CSIRT/NASK, urzędy, HIBP) - wtedy tylko w hoście;
- **domeny**: `domain`, `affected_domain` i `official_domain` z adresem IP w dowolnej postaci albo z `@` odrzucają rekord;
- **daty**: `incident_date`, `published_date`, `retrieved_at`, `observed_at`, `verified_at` muszą być istniejącymi datami ISO 8601 (nie `2026-02-30`), od 1990 roku i nie później niż doba po czasie importu; `verified` bez poprawnej `verified_at` odrzuca domenę (puste opcjonalne daty są dozwolone);
- relacje zakazane (incydent z osobami/e-mailami/kontami), kolizja klucza Organization (poniżej) i **kolizja URL źródła (fail-closed)**: jeśli w grafie sprawy istnieje węzeł URL o tym samym id z `kind` innym niż `source` (`profile`, `gravatar`, brak `kind`), źródło jest odrzucane z powodem „kolizja: URL źródła istnieje w grafie jako <kind>”, rekordy oparte wyłącznie na nim też; rekordy z innymi poprawnymi źródłami zostają bez `has_source` do tego URL, a istniejący węzeł nie jest zmieniany. `has_source` nigdy nie wskazuje węzła o `kind` innym niż `source` (sprawdza to importer przed scaleniem w grafie docelowym).

**Zgodność hosta z typem źródła (allowlisty, fail-closed)** i jawne mapowanie typów org-intel na kategorie importera (`SOURCE_TYPE_TABLE`, `HostRules` w module; kategoria trafia do `provenance.source_category` i do węzła źródła; typ bez reguły jest odrzucany):

| typ org-intel | kategoria importera | reguła hosta | baza jakości |
|---|---|---|---|
| `official_registry` | `official_registry` | tylko rejestry: `ekrs.ms.gov.pl`, `prs.ms.gov.pl`, `api-krs.ms.gov.pl`, `wyszukiwarkaregon.stat.gov.pl`, `api.stat.gov.pl`, `biznes.gov.pl/ceidg`, `dane.biznes.gov.pl`, `wl-api.mf.gov.pl` i ich subdomeny (lista wg tego, czego używa osint-poland) | high |
| `company_website` | `official_company` | host = domena oficjalna organizacji z tego samego importu (`official_domain`) lub jej subdomena | low (domena oficjalna z pliku jest niezweryfikowana) |
| `cert_advisory` | `cert` (`cert.pl`, `cert.europa.eu`, `enisa.europa.eu`) / `nask` (`nask.pl`) / `csirt` (`csirt.gov.pl`, `gov.pl`) / `vendor_advisory` (domena oficjalna organizacji z importu) | host CERT/CSIRT/NASK z subdomenami albo domena producenta (organizacji) | high; `vendor_advisory` low (domena z pliku) |
| `official_document` | `public_report` | `*.gov.pl`, `*.europa.eu` albo domena oficjalna organizacji | medium (high dla hostów urzędowych; low, gdy uznane tylko przez domenę oficjalną z pliku) |
| `hibp_catalog` | `hibp_catalog` | dokładnie `haveibeenpwned.com` i `api.haveibeenpwned.com` | medium |
| `ct_log` | `ct_log` | znane logi CT: `crt.sh`, `ct.googleapis.com`, `ct.cloudflare.com`, `ct.letsencrypt.org`, `ct.digicert.com`, `ct.sectigo.com` | medium |
| `passive_dns` | `passive_dns` | dowolny host publiczny (obowiązują blokady IP/lokalne/fora) | low |
| `manual` | `manual` | dowolny host publiczny (jw.) | low |

Jakość źródła = min(baza kategorii, `reliability`); źródło przyjęte wyłącznie dlatego, że jego host to `official_domain` z tego samego, niezaufanego pliku, ma jakość najwyżej low (`OFFICIAL_DOMAIN_QUALITY`): plik mógł wskazać dowolną domenę, np. hosting współdzielony. Allowlisty to stałe produkcyjne (nie ma w nich `example.test`); testy wstrzykują własne obiektem `HostRules` jako parametr `parse(..., rules=...)`, a CLI zawsze używa wartości produkcyjnych. Domeny oficjalne bierze się z rekordów organizacji tego samego pliku, które przechodzą wstępną walidację (nazwa, identyfikatory, domena, brak sekretów); organizacja odrzucona nie uprawnia źródeł `company_website`/`vendor_advisory`.

**E-maile**: w KAŻDYM polu tekstowym zapisywanym do grafu (nazwa prawna i dawne nazwy, nazwa i tytuł incydentu, opis, klasy danych, nazwa i licencja źródła) adres e-mail jest zastępowany w całości znacznikiem `[e-mail ukryty]` (bez pierwszej litery i bez domeny). Raport podaje liczbę zamaskowanych pól (`masked_fields`, liczone tylko dla przyjętych rekordów). Eksport org-intel ma pole `emails_masked`: gdy nie jest `true` albo go brak, a także dla `store.json` (który go nie ma i trzyma pełne adresy osób), importer maskuje tak samo i dopisuje ostrzeżenie do raportu. Osoby są pomijane, `notes` źródeł i obserwacji nie są zapisywane do grafu.

**Nieznane pola**: pola rekordów spoza schematu eksportu/store org-intel (osobno dla źródła, organizacji, domeny, incydentu i obserwacji) są domyślnie ignorowane, ale liczone w raporcie (`unknown_fields`, także nieznane klucze najwyższego poziomu); w `--strict` odrzucają rekord, a nieznany klucz najwyższego poziomu pliku odrzuca cały plik (odmowa, kod 5).

**Kody wyjścia**: 0 = wszystkie rekordy przyjęte (także gdy import niczego nie zmienił); 2 = błąd użycia albo pliku (zły plik, CSV, nierozpoznany format, wersja schematu, sprzeczne `--json`/`--format`, zła ścieżka `--report`, w tym wskazująca katalog sprawy albo plik `--input`, uszkodzony dziennik audytu), nic nie zapisano; 4 = część rekordów odrzucona, reszta zaimportowana (tak samo w `--dry-run`; ten sam kod co w `org-intel ingest`); 5 = `--strict`: odmowa, nic nie zapisano i brak wpisu w dzienniku.

**Ograniczenia i ryzyka**:
- Brak CSV: eksport CSV org-intel to wiele plików z rozbitą proweniencją i zamaskowanymi e-mailami; polecenie odmawia z komunikatem. Brak pobierania KRS/HIBP na żywo (to robi `org-intel` lub `hibp-monitor`).
- Osoby są pomijane w całości: żadnych węzłów Person/Email, nawet publicznych osób z rejestru.
- Incydent i firma dzielą w grafie przestrzeń kluczy Organization (po znormalizowanej nazwie): tytuł incydentu równy nazwie firmy (np. wyciek „Adobe” i firma Adobe) zlałby ich atrybuty w jeden węzeł. Importer odrzuca wtedy rekord z powodem „kolizja klucza” zamiast scalać; sam import hibp-monitor takiej ochrony nie ma.
- Incydent scala się z wyciekiem z hibp-monitor tylko przy tym samym kluczu (tytuł). Wycieki o różnych tytułach, ale tej samej `breach_name`, scala dopiero `polacz` (`links.merge_identifiers`).
- Wartość węzła URL źródła przechodzi przez normalizację entity-graph (bez `www.` i fragmentu; URL z danymi logowania nie dociera do tego etapu, bo jest wcześniej odrzucany): `https://www.x/..` jest węzłem `https://x/..`; adres oryginalny zostaje w `source_url_original`.
- Dopasowanie domeny do firmy po nazwie (bez `organization_id`) z `org-intel/correlate.py` nie jest odtwarzane: krawędź `owns_domain` powstaje tylko dla domen z `organization_id`.
- „Odrzucone krawędzie” w raporcie to krawędzie, które powstałyby z rekordów pliku (`has_source`, `owns_domain`, `associated_with_incident`, także `inferred` od domeny nadrzędnej), a nie powstały, bo odrzucono organizację, domenę, incydent albo źródło; każda liczona raz.
- `polacz` używa tego samego parsera, ale bez rankingu, deduplikacji i wykrywania kolizji URL względem sprawy (buduje świeży graf, więc URL z innego pliku, np. profil, może się tam zlać z węzłem źródła), a wpisy `provenance` z różnych plików różnią się `import_id`, więc mogą się powtarzać po `(source_url_normalized, derivation)`; firmy o tym samym KRS/NIP/REGON scala tam `links.merge_identifiers`.
- Allowlisty hostów są celowo wąskie: źródło z prawdziwego, ale niewymienionego hosta (np. inny CERT krajowy) jest odrzucane, dopóki lista w `HostRules` nie zostanie świadomie rozszerzona w kodzie.
- Testy: `tests/test_import_org_intel.py`, fixture'y w `tests/fixtures/org_intel/` (wygenerowane prawdziwym `org-intel ingest` + `export --format json`, z dozwolonymi hostami i fikcyjnymi ścieżkami; wyłącznie dane syntetyczne).
