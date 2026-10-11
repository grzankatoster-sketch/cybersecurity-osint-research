# Username Engine

Wyszukiwanie kont po nazwie użytkownika. Następca Blackbirda i Maigreta: korzysta z ich baz (WhatsMyName CC BY-SA 4.0, Maigret MIT), ale ma własną, ostrzejszą decyzję „konto istnieje”. Plan: `../PLAN_USERNAME_ENGINE_2026-10-03.md`, analiza: `../ANALIZA_KODU_BLACKBIRD_MAIGRET_2026-10-03.md`.

```bash
py -m pip install aiohttp pytest
py scripts/build_db.py                       # pobiera i scala bazy -> data/sites.json
set PYTHONPATH=src && py -m username_engine <nazwa> [--tags social,pl] [--json wynik.json] [--all] [--strict-tls] [--details]
py -m pytest -q                              # testy bez internetu
```

Najprościej: dwuklik `START_USERNAME_ENGINE.cmd`, potem `ue NAZWA [opcje]` (ściąga wyświetla się na starcie).

## Funkcje
- Skan ~5800 serwisów (`--tags`, `--limit`, `--sites GitHub,Reddit` — dokładne nazwy, filtr przed `--limit`; nieznana nazwa to błąd z kodem 2), raport HTML (`--report`), CSV dla Excela (`--csv`), JSON (`--json`). Nazwy plików podaje się bez katalogu (patrz Retencja).
- Facebook, Instagram i Threads nie mają reguł: działały tylko dzięki podszywaniu się pod robota podglądu linków (User-Agent `facebookexternalhit`), czego nie robimy. `--sites Facebook,...` kończy się czytelnym błędem; te profile sprawdza się ręcznie (linki wyszukiwarek: `--dorks`, zawsze w raporcie HTML). Nagłówki per serwis (`headers` w bazie) zostają: używają ich inne reguły.
- Warianty nazwy z imienia i nazwiska lub jednej nazwy (`--variants`, `--show-variants`, `--years`, `--leet`, limit `--max-variants`).
- Dorki wyszukiwarek (`--dorks`, zawsze w raporcie HTML): wzmianki i podobne nazwy poza samymi profilami. `--dorks-only` tylko przygotowuje linki i kończy działanie bez wczytywania bazy, sieci oraz skanu serwisów.
- Wayback (`--wayback`): profile, których dziś nie ma, ale są w archiwum (usunięte konta).

## Co robi inaczej
- 4 stany: FOUND (z pewnością 0–1) / NOT_FOUND / ERROR (z przyczyną) / UNSUPPORTED. Błąd nigdy nie udaje braku konta.
- Słabe reguły („sam kod 2xx”) są porównywane z zapytaniem kontrolnym na losową nazwę (soft-404).
- Reguła pasująca także do losowej nazwy jest oznaczana jako niewiarygodna.
- Przekierowanie poza profil = brak konta. Puste teksty reguł są ignorowane (błąd Blackbirda).
- Korelacja „ta sama osoba” pomija szum: to samo konto pod dwoma szablonami adresu (Venmo / Venmo [maigret]), avatar domyślny, generowany z nazwy albo wspólny dla ≥3 serwisów (rodzina Envato) i tytuł strony zamiast nazwy („profile on X”, nazwa serwisu w nazwie). Pomiar `mozilla`: 15 par → 2. Ocena to poziom dowodów (brak / słabe / umiarkowane / mocne), nie procent: pola, które da się skopiować (strona www, avatar, nazwa, bio, lokalizacja, link w jedną stronę), liczą się jako jedna grupa i dają najwyżej „umiarkowane”; „mocne” tylko z linków wzajemnych. Ta sama reguła co w entity-graph (`evidence.py`).
- Systemowy DNS (bez aiodns), limit 2 połączeń na domenę, retry z backoffem. `Retry-After` (sekundy albo data) to minimum
  czekania; powyżej 60 s nie czekamy, serwis dostaje ERROR „limit zapytań”. Jitter tylko w górę.
- Odpowiedź 429 (np. Reddit) dostaje dokładnie jedną ponowną próbę po `Retry-After` (do 30 s; dłuższe żądanie = bez czekania i bez ponowienia). Potem wynik to ERROR „limit zapytań (429, Retry-After N s): serwis ograniczył zapytania, to nie dowodzi braku konta” — nigdy „brak konta”.
- NXDOMAIN (trwały brak domeny) jest rozróżniany od przejściowych błędów DNS: te drugie są ponawiane i nie oznaczają
  serwisu jako martwego.
- Nierozpoznany kod HTTP (400, 405, 5xx...) to ERROR, nie „brak konta”; NOT_FOUND dają tylko jawne reguły (m_code,
  teksty braku konta) oraz 404/410. Odpowiedź obcięta limitem rozmiaru (2 MB) nigdy nie dowodzi braku konta
  (znacznik `truncated`). Kontrola z ERROR (np. strona logowania) nie podnosi pewności; soft-404 wymaga zgodnej
  długości ORAZ treści/tytułu strony.

## OPSEC: Tor, poziomy skanu, bezpiecznik (04.10.2026)

Szczegóły i pomiary: `AUDYT_OPSEC_2026-10-04.md` i `AUDYT_POLACZENIE_OPSEC_2026-10-04.md` w katalogu głównym repo.

```
ue nazwa --proxy socks5h://127.0.0.1:9150 --level standard   # Tor Browser; albo zmienna OSINT_PROXY
ue nazwa --level quick                                        # tylko archiwum Wayback + linki do wyszukiwarek
ue nazwa --direct                                             # jawnie bez proxy (serwisy widzą Twoje IP)
```

- `--proxy` / `OSINT_PROXY`: tylko SOCKS5 (`socks5://`, `socks5h://`), nazwy rozwiązuje proxy (0 lokalnych zapytań DNS), każdy skan na osobnym obwodzie Tora. Przed skanem kontrola (`check.torproject.org`); proxy nie działa → kod 3, zero ruchu bezpośredniego.
- `--proxy-fallback` / `OSINT_PROXY_FALLBACK`: drugie proxy (np. SOCKS Mullvada) tylko dla serwisów, które zablokowały Tora. Nigdy powrót do połączenia bezpośredniego.
- Błędy przez proxy: do 2 ponowień na nowym obwodzie (`--proxy-retries`). Pole `channel` w wynikach: `direct`, `proxy`, `proxy-retry`, `fallback`.
- **Bezpiecznik:** 15 kolejnych „brak połączenia z proxy” (np. zamknięty Tor Browser) → skan przerwany, pozostałe serwisy jako ERROR „przerwano: proxy przestało działać” (nigdy NOT_FOUND), raport częściowy, kod 3.
- `--level`: `quick` (tylko Wayback, zero zapytań do serwisów; przez Tora ok. 9 min), `standard` (serwisy z tagami `social` i `pl` plus `--tags`, ok. 800, przez Tora ok. 20 min, archiwum włączone), `full` (domyślnie, cała baza, przez Tora ok. 90 min).
- Archiwum przez Tora: każde zapytanie CDX na nowym obwodzie, limit 60 s, do 3 prób (archive.org dławi wyjścia Tora kodem 503; pomiar 05.10.2026: 23 z 25 błędów → 4 z 25).
- Raport i terminal: lista **„Do ręcznego sprawdzenia”** (błędy skanu i serwisy z góry oznaczone jako blokujące automaty) z instrukcją, by otworzyć je w Tor Browserze. Błąd to nie brak konta.

## Retencja raportów (model biura: raport ważny 12 h)
- Każdy skan z eksportem (`--report`, `--csv`, `--json`) dostaje katalog `<wyniki>/<id skanu>/` (id = czas UTC + losowy sufiks) z plikami raportu i `manifest.json`: `created_at`, `expires_at`, `ttl_hours`, lista plików z rozmiarem i SHA-256. Manifest nie zawiera nazwy użytkownika.
- `--ttl-hours N` (domyślnie 12). `0` = bez wygasania, tylko jawnie. `--results-dir` zmienia katalog wyników (domyślnie `wyniki/` w repo). Raport HTML pokazuje datę wygaśnięcia, a terminal wiersz „Katalog skanu”.
- `py -m username_engine purge [--results-dir DIR] [--dry-run]` usuwa wygasłe skany ze wszystkimi plikami (także tymczasowymi); to samo dzieje się automatycznie na starcie każdego skanu. W terminalu: `ue-purge`. Nazwę „purge” zeskanujesz przez `-- purge`.
- Rejestr usunięć `<wyniki>/usuniecia.jsonl` (tylko dopisywanie): id skanu, `created_at`, `deleted_at`, liczba plików, skróty SHA-256. Bez nazwy użytkownika i bez treści raportu.
- Bezpieczeństwo usuwania: tylko bezpośrednie podkatalogi katalogu wyników o nazwie będącej id skanu, z manifestem tego samego id i terminem, który minął. Dowiązania symboliczne i junctiony są pomijane (nie podążamy za nimi), podkatalog w skanie blokuje usunięcie, obce pliki i katalogi nie są ruszane. Katalog jest najpierw atomowo przemianowywany (`.usuwanie-...`), więc równoległe purge nie kolidują, a przerwane usuwanie dokończy następne. Plik otwarty w przeglądarce (Windows) opóźnia usunięcie do kolejnego purge. Manifest i eksporty zapisujemy atomowo (`fsutil`).
- Kopia raportu zrobiona przez użytkownika (pobranie, zrzut) jest poza kontrolą retencji.

## Bezpieczeństwo (baza serwisów to niezaufane wejście)
- **Cele sieciowe**: tylko publiczne adresy. Żądania i przekierowania na loopback, sieci prywatne, link-local,
  multicast i zarezerwowane są blokowane (adres sprawdzany po rozwiązaniu DNS, w chwili łączenia, oraz dla hostów
  podanych jako literał IP). Dozwolone metody: GET, HEAD, POST; przekierowania obsługujemy sami (limit 5 skoków,
  kontrola celu na każdym). Wyjątek tylko dla testów: `Fetcher(allow_private=True)`.
- **TLS**: ok. 65 serwisów ma zepsute certyfikaty, więc po błędzie weryfikacji ponawiamy żądanie bez weryfikacji, ale
  wynik jest oznaczony (`insecure`, w raporcie „bez weryfikacji TLS”, w CSV kolumna `tls_niezweryfikowany`), jego
  pewność nie przekracza 0,6, a odpowiedź nie służy do ekstrakcji profilu, korelacji kont ani geolokalizacji.
  `--strict-tls` wyłącza ponowienie: błąd certyfikatu = ERROR.
- **Wyrażenia regularne z bazy**: wzorzec dłuższy niż 500 znaków albo z zagnieżdżonymi kwantyfikatorami
  (`(a+)+`, `(a*)*`, `(a+)*`; grupy zaczynające się jednoznacznym separatorem, np. `(-[a-z0-9]+)*`, są dopuszczone)
  oraz nazwa dłuższa niż 128 znaków dają UNSUPPORTED bez zapytania. Nie ma zależności od modułu `regex`.
- **Raport i eksporty**: wszystko w HTML przechodzi przez escape, linki tylko http/https (inne schematy to zwykły
  tekst), data zrzutu z Wayback i odpowiedź CDX są walidowane (timestamp = 14 cyfr, pełny schemat, błąd =
  kontrolowany ValueError). CSV neutralizuje formuły (`= + - @` i tabulator/CR na początku pola dostają prefiks `'`).
  Zapisy są atomowe (plik tymczasowy + `os.replace`), a analiza i każdy eksport (HTML, CSV, JSON) są izolowane: błąd
  jednego nie blokuje reszty, kod wyjścia to 1.
- **Terminal**: znaki sterujące z niezaufanych pól (nazwa serwisu, URL, powód) są wypisywane jako `\xNN`. Surowe dane
  osobowe z profili (lokalizacja, narodowość, nazwy, strony www) trafiają do stdout tylko z `--details`; bez niej
  widać wnioski (kraj, siła dowodów, powiązania), a pełne uzasadnienia są w raporcie HTML i JSON.
- **Baza**: wpis z błędnym typem pola jest pomijany z ostrzeżeniem (stderr). Stan zdrowia bazy
  (`data/health.json`) starszy niż 30 dni jest ignorowany (odśwież: `scripts/health_check.py`).
- Nazwy serwisów są unikalne (`X`, `X [wmn]`, `X [wmn 2]`...); normalizacja URL do scalania serwisów i porównań
  linków jest wspólna (`urlnorm.py`): zachowuje wielkość liter ścieżki i query.

## Pomiar 03.10.2026 (5794 serwisy, próg pewności 0,6)
| Nazwa | Username Engine | Maigret | Blackbird | Sherlock |
|---|---|---|---|---|
| losowa (fałszywe trafienia) | 1 | 1 | 0 | 3 |
| `mozilla` (znalezione) | 309 | 178 | 155 | 127 |

Błędy (blokady anty-bot, DNS, timeout) w ok. 13% serwisów są raportowane jawnie.
