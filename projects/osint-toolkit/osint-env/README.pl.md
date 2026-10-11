# osint-env: odtwarzalne, kasowalne środowisko OSINT w Dockerze

Realizacja sekcji 8 audytu (`../AUDYT_OSINT_NOTATKI_2026-10-03.md`): izolacja badacza (OPSEC), czysto defensywnie.
Wszystko da się zbudować od zera jednym poleceniem i skasować jednym plikiem.

## ZASADA NACZELNA (legalność)

Narzędzia uruchamiamy **tylko na własnych domenach/IP albo z pisemną zgodą właściciela**. Nie na osobach prywatnych
i nie na cudzej infrastrukturze „na próbę". Trafienie to trop, nie dowód (min. 2 niezależne korelacje).
Masowe zbieranie danych o konkretnej osobie = RODO + regulaminy platform; tego to środowisko nie służy.

## Co jest w środku

| Usługa (compose) | Zawartość | Profil |
|---|---|---|
| `toolbox` (obraz `osint-toolbox`, Python 3.14-slim, użytkownik `osint` uid 1000) | `username-engine`, `dns-audit`, `hibp-monitor`, `exif-map`, `phone-check`, theHarvester 5.0.0 (commit `49a38f8`, przypięty), `exiftool` (Perl, wersja z Debiana), `dig` (dnsutils), `git` | domyślny |
| `spiderfoot` | obraz `spiderfoot:local` (zbudowany wcześniej z `narzedzia/spiderfoot-src`), panel `http://127.0.0.1:5001` | `spiderfoot` |
| `bbot` | `blacklanternsecurity/bbot:stable`, dane w wolumenie `bbot-data` | `bbot` |
| `browser` | `kasmweb/firefox:1.16.0` (przeglądarka w kontenerze), `https://127.0.0.1:6901` | `browser` |
| `selftest` | pytest wszystkich 5 projektów w obrazie testowym | `test` |

Python 3.14 jest wymagany przez theHarvester; wszystkie 5 własnych projektów (`requires-python >=3.12`) działa na 3.14 (testy: patrz niżej).

## Uruchomienie

Wymagany Docker Desktop. Wszystkie polecenia z katalogu `osint-env/`.

```
START_OSINT_ENV.cmd                  rem build + powłoka w kontenerze toolbox (dwuklik)
RESET_OSINT_ENV.cmd                  rem kasowanie środowiska (pyta o potwierdzenie)
```

Ręcznie:

```
docker compose build toolbox
docker compose run --rm toolbox      # powłoka bash, /work = osint-env\work\
```

Klucz HIBP (tylko ze zmiennej środowiska hosta, nigdy w plikach):

```
set HIBP_API_KEY=twoj_klucz          rem cmd;  w PowerShell: $env:HIBP_API_KEY="..."
docker compose run --rm toolbox
```

### Narzędzia w toolboxie

```
username-engine --help                       # = python -m username_engine; tylko własne nicki
python -m dns_audit TWOJADOMENA.pl           # SPF/DMARC/DKIM/DNSSEC/MTA-STS/CAA
python -m hibp_monitor --help                # breaches / password / domain-search (klucz z HIBP_API_KEY)
python -m exif_map /work/zdjecia --map /work/mapa.html
python -m phone_check +48123456789
exiftool plik.jpg
dig TWOJADOMENA.pl MX +short
theHarvester -d TWOJADOMENA.pl -b duckduckgo -l 50
```

`hibp-monitor` czyta `config.toml` i `state.json` z bieżącego katalogu, czyli z `/work` (utwórz tam `config.toml` wg `config.example.toml`).
Zapisuj wszystkie wyniki w `/work`, bo reszta systemu plików kontenera jest tylko do odczytu.
Klucze API theHarvestera: `~/.theHarvester/api-keys.yaml` leży w tmpfs i znika po wyjściu; jeśli ich używasz, trzymaj plik w `/work` i po starcie skopiuj: `mkdir -p ~/.theHarvester && cp /work/api-keys.yaml ~/.theHarvester/`.

### SpiderFoot, bbot, przeglądarka

```
docker compose --profile spiderfoot up -d spiderfoot    # panel http://127.0.0.1:5001 (bez logowania!)
docker compose --profile spiderfoot stop spiderfoot

docker compose --profile bbot run --rm bbot -t TWOJADOMENA.pl -f subdomain-enum -rf passive
docker compose --profile bbot run --rm bbot --help

set KASM_VNC_PW=wymysl_haslo
docker compose --profile browser up -d browser          # https://127.0.0.1:6901 , login kasm_user
```

Uwaga: `docker compose up` bez nazwy usługi startuje też `toolbox`; podawaj nazwę usługi.
SpiderFoot to nieutrzymywany od 2023 projekt ze starymi zależnościami: panel tylko na 127.0.0.1, bez logowania, nie wystawiaj portu na sieć.
Aktywne presety bbot wysyłają ruch do celu; do bezpiecznego startu użyj `-rf passive`.

### Testy

```
docker compose --profile test run --rm selftest         # pytest 5 projektów (obraz osint-toolbox:tests)
```

## Licencja KASM (przeglądarka)

Profil `browser` używa obrazu `kasmweb/firefox`. **Kasm Workspaces Community Edition jest darmowy tylko do testów,
użytku non-profit i niekomercyjnego** (limit 5 równoczesnych sesji, wsparcie przez publiczny issue tracker).
Użycie komercyjne wymaga płatnej licencji. Sprawdź aktualne warunki: https://docs.kasm.com/docs/reference/license .
Obraz jest duży i **nie był pobierany ani uruchamiany podczas budowy tego środowiska** (zdefiniowany tylko w compose; konfiguracja zwalidowana poleceniem `config`, działanie samej przeglądarki NIE zostało przetestowane).
Obraz kasmweb wymaga zapisywalnego rootfs, więc ta usługa ma mniej restrykcji niż `toolbox` (zostaje `cap_drop: ALL` i `no-new-privileges`).

## OPSEC: co izoluje kontener, a czego NIE

Izoluje:
- narzędzia i ich zależności są oddzielone od systemu hosta (brak mieszania z życiem prywatnym, brak śmieci w Windows);
- toolbox: użytkownik nie-root, `read_only` rootfs, `cap_drop: ALL`, `no-new-privileges`, limity pamięci i procesów;
- jedyny zapisywalny katalog hosta to `osint-env\work\`; `/tmp` i HOME to tmpfs, znikają po wyjściu;
- nie ma montowania dysku C:, profilu użytkownika, przeglądarki ani menedżera haseł hosta;
- porty SpiderFoot i przeglądarki są związane z `127.0.0.1` (nie z siecią lokalną);
- całość kasowalna: `RESET_OSINT_ENV.cmd`.

NIE izoluje (nie zakładaj anonimowości):
- **adres IP wychodzi tym samym łączem co reszta komputera**; cel i dostawcy API widzą Twoje IP. Jeśli potrzebujesz innego wyjścia, uruchom VPN po stronie hosta (Docker Desktop kieruje ruch przez host);
- resolver DNS: kontener używa DNS Docker Desktop, czyli tego co host;
- konta, klucze API i zapytania (np. HIBP, theHarvester) są powiązane z Tobą;
- kontener nie chroni przed błędem operatora (logowanie się prywatnym kontem w przeglądarce kontenera zdradza tożsamość);
- to nie jest sandbox przed złośliwym kodem (kernel jest współdzielony przez WSL2; SpiderFoot i bbot to większe powierzchnie ataku niż toolbox: `bbot` działa jako root w kontenerze, `spiderfoot` ma stare zależności);
- pliki w `work/` są zwykłymi plikami hosta (zdjęcia z EXIF, wyniki) i nie są szyfrowane.

## Struktura i budowanie

- `Dockerfile` (cele: `runtime` = obraz `osint-toolbox`, `tests` = z pytestem i kopią testów),
- `docker-compose.yml` (build context `..`, czyli katalog `OSINT/`),
- `../.dockerignore`: allowlista 5 projektów + wykluczenia (`.venv`, `__pycache__`, `wyniki`, `.git`, PDF, `.env*`, `config.toml`, `state.json`, `narzedzia/*-venv`, `exiftool`, `spiderfoot-src`, `osint-poland`, `audit`). Wartości sekretów nigdy nie trafiają do obrazu;
- `work/`: katalog roboczy (jedyny zapisywalny z hosta).

Build wymaga internetu (apt, PyPI, GitHub: theHarvester pobierany z przypiętego commita `49a38f8d33c32336bbf6a111ea723ea223116265`).
Aktualizacja theHarvestera: zmień `THEHARVESTER_REF` w `Dockerfile` (lub `--build-arg`) i przebuduj.
`username-engine` jest instalowany w trybie edytowalnym z `/opt/username-engine`, bo szuka `data/sites.json` obok źródeł.

## Znane ograniczenia

- exiftool z Debiana to starsza wersja (13.25) niż przenośny na hoście (13.59).
- Obraz ma ok. 0,9 GB (system Debiana + Python ok. 0,25 GB, venv ok. 0,4 GB: playwright 138 MB, numpy/pandas, folium, phonenumbers).
- Nie przypięto wersji pakietów własnych projektów (`>=` w pyproject), tylko theHarvestera (commit i jego zależności `==`) oraz obraz bazowy po tagu `python:3.14-slim`.
- `kasmweb/firefox` jest przypięty do tagu `1.16.0`; istnienie tagu sprawdzono przez `docker manifest inspect` (bez pobierania obrazu).
