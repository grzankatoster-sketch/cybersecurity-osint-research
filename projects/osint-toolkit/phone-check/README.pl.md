# Phone Check

Offline walidator numeru telefonu oparty na bibliotece `phonenumbers` (port libphonenumber Google). Sekcja 6 audytu: `../AUDYT_OSINT_NOTATKI_2026-10-03.md`.

**Zakres jest wąski i jawny:** parsowanie numeru i metadane z planu numeracji. Narzędzie **nie wysyła żadnych zapytań** do sieci, nie sprawdza kont w serwisach (ignorant), nie używa HLR, nie wiąże numeru z osobą i niczego nie scrapuje.

**Przeznaczenie:** numery własne, firmowe lub sprawdzane w ramach zlecenia. Nie służy do ustalania, do kogo należy cudzy numer.

```bash
py -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m phone_check "603 123 456"               # region domyślny PL
.venv\Scripts\python -m phone_check "+49 30 901820" --region DE
.venv\Scripts\python -m phone_check 603123456 --dorks
.venv\Scripts\python -m phone_check --file numery.txt --csv wyniki.csv --json wyniki.json
.venv\Scripts\python -m pytest -q                               # testy bez internetu
```

Najprościej: dwuklik `START_PHONE_CHECK.cmd` (tworzy `.venv` przy pierwszym uruchomieniu), potem `pc NUMER [opcje]`.

## Co zwraca
- Poprawny (zgodny z planem numeracji) i możliwy (zgodna długość).
- Kraj, region geograficzny (geocoder, opis po polsku, jeśli jest w danych), typ linii (komórkowy, stacjonarny, VoIP, premium, bezpłatny...).
- Operator z planu numeracji wraz z adnotacją o ograniczeniach (patrz niżej).
- Strefy czasowe oraz formaty: E.164, międzynarodowy, krajowy, RFC3966.
- Kod wyjścia: 0 = wszystkie numery poprawne, 1 = co najmniej jeden niepoprawny, 2 = błąd użycia lub I/O (zły argument, kolizja ścieżek, pusty/nieczytelny plik, nieudany zapis).

## Tryb wsadowy
`--file numery.txt`: jeden numer na linię (puste linie i linie z `#` są pomijane). Wynik do `--csv` (separator `;`, UTF-8 z BOM, otwiera się w Excelu) i/lub `--json`.

- **Numer pozycyjny i `--file` wykluczają się** (błąd, kod 2).
- **Plik wejściowy musi być w UTF-8** (BOM dozwolony). Inne kodowanie (np. cp1250) = czytelny komunikat i kod 2, bez tracebacku.
- **Pusty plik lub same komentarze = błąd** (kod 2), nie sukces.
- **Kolizje ścieżek**: `--file X --json X`, `--json Y --csv Y` itp. są odrzucane przed jakimkolwiek zapisem (porównanie ścieżek rozwiązanych oraz tożsamości istniejących plików, także twardych linków), kod 2. Plik wejściowy nie zostanie nadpisany.
- **Zapis atomowy**: JSON i CSV trafiają najpierw do pliku tymczasowego w tym samym katalogu, potem `os.replace`; awaria nie zostawia uciętego pliku ani nie niszczy poprzedniej wersji. Przy błędzie zapisu (`OSError`) komunikat podaje, który eksport się udał, a który nie (kod 2).
- **Limit praktyczny**: narzędzie przeznaczone do dziesiątek, najwyżej setek numerów. Plik jest czytany w całości, wyniki trzymane w pamięci (bez strumieniowania), więc nie służy do dużych list.

### CSV: kolumny i neutralizacja formuł
Kolumny: `input, valid, possible, region, country_name, country_code, geo_description, line_type, carrier, carrier_note, carrier_check_url, timezones, e164, international, national, rfc3966, error`. `carrier_note` niesie ostrzeżenie o przenoszeniu numerów (operator z planu numeracji to nie aktualny operator). Pola techniczne `region_hint`, `parsed`, `line_type_code` są tylko w JSON.

Ochrona przed wstrzykiwaniem formuł (CSV injection): każda wartość tekstowa zaczynająca się od `=`, `+`, `-`, `@`, tabulatora lub CR dostaje **prefiks apostrofu `'`**. Dotyczy to też numerów: **w CSV numery w formacie `+48...` mają prefiks `'`** (np. `'+48603123456`), bo Excel interpretuje `+48 12...` jako formułę. Excel ukrywa apostrof i pokazuje sam tekst; przy dalszym przetwarzaniu programistycznym CSV usuń pierwszy `'`. **JSON nie jest zmieniany** i zawiera wartości surowe.

## Dorki (`--dorks`)
Wypisuje warianty zapisu numeru jako frazy w cudzysłowie, do ręcznego wklejenia w wyszukiwarkę: z i bez `+48`, `0048`, spacje, myślniki, kropki, grupowanie 3-3-3 (oraz 2-3-2-2 dla zapisu stacjonarnego). Tylko tekst na ekranie: nic nie jest wysyłane ani otwierane. Gdy wariantów brak, komunikat odróżnia „numer nie do sparsowania” od „niemożliwa długość”.

Domyślny region (`PL`) i język (`pl`) mają jedno źródło: stałe `DEFAULT_REGION` i `DEFAULT_LANG` w `core.py`.

## Ograniczenia
- **Operator z planu numeracji nie oznacza aktualnego operatora.** To pierwotny przydział puli numerów. W Polsce numery można przenosić między sieciami, więc rzeczywisty operator może być inny. Aktualny operator: baza UKE, https://numeracja.uke.gov.pl/ (ręczna weryfikacja; narzędzie jej nie odpytuje). Dla numerów bezpłatnych i części innych typów operatora brak.
- Region geograficzny dla polskich numerów komórkowych to cały kraj (numer komórkowy nie wskazuje miasta). Lokalizacja stacjonarnego wynika z kierunkowego, nie z miejsca użytkownika.
- „Poprawny” znaczy zgodny z planem numeracji w danych bibliotek, nie że numer jest aktywny ani do kogo należy.
- Dane zależą od wersji `phonenumbers`; aktualizuj ją (`pip install -U phonenumbers`).
- Brak informacji o aktywności numeru, roamingu, właścicielu: to poza zakresem z założenia.
