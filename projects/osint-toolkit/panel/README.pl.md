# Panel OSINT

Lokalny widok w przeglądarce nad narzędziami z repo. Zakładki (w tej kolejności):

1. **Nazwa użytkownika** (domyślna): `username-engine` (osobne repo obok). Nazwa albo „Imię Nazwisko”, tagi (`social,pl`), „tylko ta nazwa” (`--no-variants`), archiwum Wayback, rok (`--years`). Raport HTML w ramce. **Kanał** (OPSEC, patrz `AUDYT_OPSEC_2026-10-04.md`): domyślnie **Tor** (`--proxy`, `OSINT_PROXY` albo SOCKS Tor Browsera `socks5h://127.0.0.1:9150`; bez działającego Tora skan się nie zaczyna, zero ruchu bezpośredniego; zapas np. Mullvad w `OSINT_PROXY_FALLBACK`), **Poziom** (`--level`): szybki (tylko archiwum, przez Tora ok. 9 min), standard (domyślnie, ok. 800 serwisów, przez Tora ok. 20 min, limit 45 min), pełny (cała baza, przez Tora ok. 90 min, limit 2 h). „Bezpośrednio” (`--direct`) ~4 min, limit 15 min, ale serwisy widzą Twoje IP. Ten sam kanał dostaje username-engine uruchamiany z entity-graph (zmienna `OSINT_PROXY` w środowisku podprocesu). meta-search ma osobne `META_PROXY`. Linki z raportu otwieraj w Tor Browserze. Raporty (poza mapą EXIF) mają CSP `default-src 'none'`: nic nie ładuje się z sieci.
2. **E-mail i domena**: theHarvester (`narzedzia/theharvester-venv`, tylko źródła bez klucza API: crtsh, certspotter, rapiddns, otx, urlscan, hackertarget, subdomaincenter, thc, duckduckgo, yahoo, waybackarchive, hudsonrock, commoncrawl; domyślnie crtsh + certspotter + hackertarget, bo samo crt.sh często zwraca 502/503). theHarvester startuje z poprawką DNS (ThreadedResolver) i z `-v`, więc status każdego źródła jest w wyniku: bez poprawki każde źródło kończyło się `transport-error` i raport pokazywał „No hosts found” oraz HIBP: wycieki domeny, hasło, katalog wycieków.
3. **Domena (DNS)**: dns-audit.
4. **Telefon**: phone-check.
5. **Zdjęcia (EXIF)**: exif-map.

Zakładka **Laboratorium** pokazuje datowany, lokalny skrót ustaleń z audytów: elementy gotowe, znaleziska, blokery wdrożenia i granice bezpieczeństwa. Endpoint `/api/lab` wymaga tokenu panelu; treść nie zawiera sekretów ani danych spraw.

Start: dwuklik `START_OSINT_OSOBY.cmd` dla głównego przepływu osób albo `panel\START_PANEL.cmd` (launcher `py -3` nie jest wymagany) → otwiera `http://127.0.0.1:8765/` (`--no-browser` pomija przeglądarkę).
Port: zmienna `OSINT_PANEL_PORT`. Raporty HTML (nazwa użytkownika, DNS) i mapy (EXIF) trafiają do `panel/wyniki/`.

- Zero zależności (stdlib). dns-audit, phone-check, hibp-monitor i exif-map uruchamiane są z własnego `.venv` (brak → uruchom raz jego `START_*.cmd`); username-engine z Pythona 3.14 z `START_USERNAME_ENGINE.cmd` (brak → bieżący interpreter); theHarvester z venva w `narzedzia/`. Maigret wycofany (04.10.2026): zastępuje go własny username-engine.
- Naraz działa jeden długi skan nazwy użytkownika: kolejne żądanie dostaje 409 z komunikatem, bez kolejki.
- Kod wyjścia różny od 0 nie zawsze oznacza błąd, dlatego panel zawsze pokazuje stdout i stderr.
- Bezpieczeństwo: tylko `127.0.0.1`, sprawdzany nagłówek `Host`, każde POST wymaga tokenu sesji, treść POST musi być obiektem JSON (inaczej HTTP 400), pola muszą mieć właściwy typ: tekst, true/false dla pól wyboru, liczba całkowita albo tekst dla limitów (inaczej HTTP 422); w obu przypadkach narzędzie nie startuje, argumenty jako lista (bez powłoki), pola zaczynające się od `-` odrzucane, hasło HIBP idzie do podprocesu przez stdin, raporty serwowane tylko z `wyniki/` pod bezpieczną nazwą. Ramka raportu ma `sandbox` bez `allow-same-origin`; linki do zewnętrznych profili otwierają się w nowej karcie.
- Ukryte pole `limit` (1–10000) w formularzu nazwy użytkownika przekazuje `--limit` (do testów szybkiego skanu).
- Zakładka **Meta** (`meta-search`) jest opcjonalnym adapterem: Threads API (profil po nicku, posty po frazie), Instagram Business Discovery (konta profesjonalne) i publiczne dane Stron Facebooka. Jej działanie produkcyjne wymaga własnego tokena, zakresów i osobnego testu; nie jest fundamentem przepływu osób. Sprawdzanie stron HTML Facebooka/Instagrama/Threads zostało usunięte (reguły udawały bota podglądu linków). Bez tokenu wynik to „wymaga konfiguracji”. Obok raportu HTML zapisuje się JSON do importu w entity-graph.
- Zakładka **Sprawa** (entity-graph): wybór albo utworzenie sprawy, osoby, numery z kontekstem planu numeracyjnego, twierdzenia o relacjach i kandydaci profili, każde z trzema osobnymi informacjami: status źródła, pewność powiązania i decyzja operatora. Formularze: nowa sprawa (offline), twierdzenie o relacji ze źródłem i dowodem, potwierdzenie albo odrzucenie twierdzenia lub kandydata (z uzasadnieniem), kontekst numeru (phone-check), operator z ręcznej weryfikacji, runda kandydatów profili z widocznym budżetem. Panel tylko sprawdza kształt pól i uruchamia `python -m entity_graph ...` jako podproces (lista argumentów, środowisko bez zmiennych z sekretami). Reguły (cel, źródła, decyzje, limity, dziennik przed i po każdej zmianie) egzekwuje entity-graph, opis w jego README.
  - **Tylko sprawy z `panel/wyniki/sprawy/`**: pole `sprawa` to sama nazwa katalogu (litery, cyfry, `.`, `_`, `-`). Ścieżki, `..`, dyski, dowiązania i junction prowadzące poza ten katalog są odrzucane (HTTP 400), zanim cokolwiek się uruchomi. Źródło twierdzenia to adres `http(s)` albo `dokument:ŚCIEŻKA` pliku w katalogu sprawy. Dokument kopiujesz tam sam: panel nie przyjmuje ścieżek do plików.
  - Runda kandydatów to długi skan (jak nazwa użytkownika): naraz jeden, limit czasu 1900 s. Przycisk propozycji tylko wypełnia formularz, a rundę uruchamiasz osobno.
  - Raport sprawy jest dostępny pod `/wyniki/sprawy/NAZWA/report.html` (ta sama ramka sandbox co inne raporty). Lista spraw (`GET /api/sprawy`) wymaga tokenu.
  - Retencja: sprawy nie wygasają same (inaczej niż raporty skanów nazw). Usuń katalog sprawy ręcznie po zakończeniu celu.
- Testy (bez sieci): `py -3 -m pytest -q tests`

Tylko dane własne, firmowe lub jawne, w ramach zlecenia.

## Metryczka wyniku i statusy

Każdy wynik narzędzia badawczego (DNS, telefon, HIBP, EXIF, nazwa użytkownika, theHarvester, Meta) ma metryczkę:
źródło, identyfikator, czas pozyskania UTC, status, kanał sieciowy (Tor/proxy, bezpośrednio, offline), ograniczenia
interpretacji, SHA-256 wyjścia i raportu oraz decyzję operatora (zapisywaną w zakładce Sprawa). Statusy:
`znaleziono`, `brak wyniku`, `błąd`, `blokada źródła`, `wynik częściowy`. Awaria proxy/Tora, limit czasu z częścią
wyników, błędy i blokady serwisów nigdy nie są pokazywane jako „brak wyniku”. Telefon w panelu to wyłącznie format,
kraj, typ linii i plan numeracyjny (bez wariantów do wyszukiwania i bez lokalizacji).

## Sprawa: asystent, dziennik audytu, eksport

Po otwarciu sprawy: **Asystent: porządek i kroki** (reguły entity-graph, offline), **Asystent + lokalne AI**
(Ollama tylko na 127.0.0.1; odpowiedź filtrowana i oznaczona jako niezweryfikowana, nie zmienia sprawy),
**Dziennik audytu** (spójność łańcucha skrótów i wpisy przed/po każdej zmianie), **Pobierz GraphML** oraz
**Pobierz CSV (Maltego)**. Pobieranie idzie przez `GET /api/sprawa_plik` z tokenem panelu i tylko z katalogu sprawy.

## Laboratorium

Zakładka pokazuje datę aktualizacji, co gotowe, ustalenia z testów i audytów, blokery, decyzje biznesowe, granice
bezpieczeństwa, legendę statusów, stan przepływów oraz brakujące zależności i konfigurację (interpretery narzędzi,
osiągalność Tora i lokalnego AI, czy zmienne kluczy są ustawione — nigdy ich wartości). Wymaga tokenu panelu.

## Sprawa: szukaj profili po nazwisku

Zakładka **Sprawa** ma sekcję „Szukaj profili po nazwisku” (Brave Search API, `eg szukaj-profili`) i formularz
„Kandydat z Twoim materiałem” (`eg material-profilu`, bez sieci, działa bez klucza). Klucz `BRAVE_SEARCH_API_KEY`
ustawiasz w środowisku przed `START_PANEL.cmd` albo w `%USERPROFILE%\.osint\brave.env`; panel przekazuje go wyłącznie
podprocesowi tego wyszukiwania (inne narzędzia go nie dostają) i nigdy nie przyjmuje go z formularza. Brak klucza:
komunikat konfiguracji, nic nie jest wysyłane. Tekst materiału (do 20 000 znaków) idzie do entity-graph przez stdin,
nie w argumentach. Tekst nie jest zapisywany w sprawie (tylko skrót, ustalenia z dosłownym dowodem i pominięte adresy
z przyczyną). Każda karta dotyczy jednej osoby („Osoba: …”): ocena dopasowania i domyślny wybór w decyzji są dla niej.
Karty pokazują adres, rodzaj źródła, pochodzenie, ustalenia z dowodem, status analizy i decyzję;
potwierdzenie/odrzucenie używa istniejącego `eg potwierdz`. Szczegóły i ograniczenia: `entity-graph/README.md`.
