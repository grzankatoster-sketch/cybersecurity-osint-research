# Net Intel

Pasywny wywiad o jawnej infrastrukturze sieciowej: **adres IP**, **RDAP domeny**, **subdomeny**. Własny, mały moduł bez zależności uruchomieniowych (HTTP przez `urllib` ze stdlib). Legalny i defensywny: pyta wyłącznie publiczne bazy o **adresy IP i domeny**, nie o osoby. Nie zbiera adresów e-mail, nie szuka kont, nie dotyka badanej infrastruktury (zapytania idą do cudzych publicznych baz). Używaj na zasobach własnych, klientów (za zgodą) lub publicznych.

```bash
py -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m net_intel ip 8.8.8.8
.venv\Scripts\python -m pytest -q            # testy bez internetu
```

Najprościej: dwuklik `START_NET_INTEL.cmd` (tworzy `.venv` przy pierwszym uruchomieniu), potem `ni podkomenda cel [opcje]`.

## Użycie

```
python -m net_intel ip IP            [--json] [--html plik] [--timeout 20]
python -m net_intel rdap domena      [--json] [--html plik] [--timeout 20]
python -m net_intel subdomains domena [--resolve] [--concurrency 10] [--json] [--html plik] [--timeout 20]
```

Zainstalowany skrypt: `net-intel ...` (to samo). Domenę można podać jako URL lub adres e-mail (zostanie wyciągnięta sama nazwa), IDN jest zamieniany na punycode (ta sama normalizacja co w dns-audit; kod skopiowany, moduły są niezależne).

### `ip`
- **ipinfo.io** (`/<ip>/json`, bez tokenu; opcjonalny token ze zmiennej środowiskowej `IPINFO_TOKEN`, wysyłany tylko w nagłówku i nigdy nie wypisywany ani nie logowany). Pola: ip, hostname, ASN i nazwa organizacji (`AS15169 Google LLC` jest dzielone), miasto, region, kraj, strefa czasowa, anycast, bogon. Współrzędnych i kodu pocztowego nie pokazujemy.
- **Odwrotny DNS** (`gethostbyaddr`, z limitem czasu) jako drugie, niezależne źródło. Brak PTR to poprawna odpowiedź, a nie błąd.
- Adres **prywatny, loopback, link-local, multicast, zarezerwowany** jest opisywany lokalnie: **żadnego zapytania** (ani do ipinfo, ani do DNS).
- Gdy zawiodło jedno źródło, wynik ma status `partial`; gdy oba: `failed`, komunikat „nie udało się sprawdzić (wszystkie źródła zawiodły)” i kod 1.

### `rdap`
- RDAP przez **bootstrap IANA** (`data.iana.org/rdap/dns.json`, pobierany raz na uruchomienie), a gdy to zawiedzie lub TLD jest nieznany: fallback `rdap.org`. Odpowiedź 404 z rejestru jest rzetelnym „nie znam tej nazwy” (WARN), nie powodem do fallbacku.
- Wynik: rejestrator, daty utworzenia / zmiany / wygaśnięcia, statusy, serwery nazw, DNSSEC (`delegationSigned`), liczba dni do wygaśnięcia.
- **Dane osobowe**: z odpowiedzi czytamy tylko nazwę rejestratora (i jego publiczny numer IANA). Dane kontaktowe rejestrującego, administracyjnego, technicznego i abuse (vcard) **nie są nigdzie odczytywane**; testy pilnują, że nie trafiają do tekstu, JSON ani HTML.

| Ustalenie | Waga |
|---|---|
| domena wygasła | FAIL |
| wygasa za < 7 dni | FAIL |
| wygasa za < 30 dni | WARN |
| status `clientHold` / `serverHold` | WARN |
| `pendingDelete` / `redemptionPeriod` | WARN |
| RDAP nie zna nazwy (niezarejestrowana albo subdomena) | WARN |
| brak blokady transferu, brak DNSSEC, brak daty wygaśnięcia | INFO |
| wygasa za >= 30 dni, statusy bez wstrzymania, DNSSEC włączony | OK |

### `subdomains`
Trzy niezależne źródła pasywne: **HackerTarget** (`hostsearch`, tekst `host,ip`), **Cert Spotter** (`/v1/issuances`, do 2 stron) i **crt.sh** (`output=json`). Nazwy są zamieniane na małe litery, bez prefiksu `*.`, zostają tylko równe domenie lub kończące się na `.domena` (adresy e-mail z certyfikatów, obce domeny i śmieci są odrzucane), bez duplikatów, posortowane; każda nazwa ma listę źródeł, które ją zgłosiły. Apex (`domena`) też jest nazwą na liście.

**Zasada nr 1: porażka nigdy nie jest „0 wyników”.**
- Każde źródło ma status `OK(n)` albo `ERROR(powód)`. Komunikaty o limicie z HTTP 200 (HackerTarget: „API count exceeded…”, „error check your search parameter”), pusta odpowiedź, HTML zamiast JSON-a (crt.sh często zwraca 502/503), HTTP 429 (z `Retry-After`), timeout: wszystko to `ERROR`.
- Rzetelne „0” to: wszystkie źródła `OK`, żadne nic nie znalazło (HackerTarget odpowiada wtedy `No records found`, pozostałe `[]`).
- **Wszystkie źródła zawiodły** = wynik „nie udało się sprawdzić (wszystkie źródła zawiodły)”, `status: failed`, `count: null` w JSON i **kod wyjścia 1**. Genuine „0 subdomen” to kod 0.
- Część źródeł zawiodła = `status: partial`, wynik niepełny jest wprost opisany (INFO), kod 0.

`--resolve` rozwiązuje A/AAAA znalezionych nazw przez resolver systemowy (współbieżność `--concurrency`, domyślnie 10, max 50; najwyżej 1000 nazw na przebieg). To jedyna opcja, która wysyła zapytania DNS dotyczące znalezionych nazw. Rozróżnia „brak adresu” od „nie udało się sprawdzić”.

## Raporty i kody wyjścia
- Domyślnie tabela tekstowa (znaki sterujące z cudzych danych są zamieniane na widoczne `\xNN`), `--json` daje pełny wynik (`status`, `headline`, `counts`, `result`, `findings`), `--html plik` samodzielny raport (jasny/ciemny motyw). Zapis HTML jest atomowy (plik tymczasowy + `os.replace`).
- Każde zapytanie ma nagłówek `User-Agent: net-intel/<wersja> (...)`; przekierowania tylko na https, a nagłówek `Authorization` nie jedzie pod inny host.

| Kod | Znaczenie |
|---|---|
| 0 | sprawdzono; brak ustaleń WARN/FAIL (także rzetelne „0 subdomen” i wynik częściowy) |
| 1 | są ustalenia WARN/FAIL, **albo nie udało się sprawdzić (wszystkie źródła zawiodły)**, albo błąd zapisu `--html` (pełny raport nadal na stdout) |
| 2 | błąd użycia: zły adres IP lub domena, nieznana podkomenda/opcja, `--timeout` <= 0 |

Odróżnienie „nie udało się sprawdzić” od ustaleń WARN/FAIL: pole `status` w JSON (`ok` / `partial` / `failed`).

## Struktura
- `http.py`: jedna funkcja `urllib_fetch(url, headers, timeout) -> Response` (wstrzykiwana; testy używają `FakeFetch` z `tests/conftest.py`)
- `ipinfo.py`, `rdap.py`, `subdomains.py`: źródła i parsery (czyste funkcje bez sieci + cienkie funkcje pobierające)
- `report.py` (budowa raportu + tekst / JSON / HTML), `cli.py`, `domain.py`, `models.py`

## Znane ograniczenia
- **Cert Spotter bez klucza** ma niski limit (rzędu 10 zapytań na godzinę); częste uruchamianie kończy się `ERROR(limit zapytań (HTTP 429, ponów za N s))`. Pobieramy najwyżej 2 strony; przy ucięciu wynik ma adnotację „niepełne”.
- **crt.sh** bywa przeciążony (502/503/timeout); to normalne i raportowane jako `ERROR`. Duże domeny dają wielomegabajtowe odpowiedzi (limit 30 MB).
- **HackerTarget** bez klucza ma dzienny limit zapytań z jednego adresu IP.
- Źródła pasywne nie są wyczerpujące: brak subdomeny na liście nie dowodzi, że nie istnieje; obecność nie dowodzi, że działa (`--resolve` sprawdza tylko DNS).
- RDAP różni się między rejestrami (niektóre ccTLD nie podają dat ani statusów, część nie ma RDAP w bootstrapie IANA; wtedy próbujemy `rdap.org`).
- Dane ipinfo.io bez tokenu są przybliżone (geolokalizacja IP to nie adres fizycznej infrastruktury).
- `gethostbyaddr` używa resolvera systemowego; przy wiszącym resolverze po limicie czasu wynik to `nie udało się sprawdzić`, a wątek roboczy kończy się sam.
