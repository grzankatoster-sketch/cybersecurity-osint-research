# Narzędzia OSINT (lokalne)

Zainstalowano 2026-10-03 wg sekcji 5 i 10 audytu (`../AUDYT_OSINT_NOTATKI_2026-10-03.md`).
Każde narzędzie ma launcher `START_<NAZWA>.cmd` (dwuklik otwiera terminal z gotowym środowiskiem i ściągawką komend).

## ZASADA NACZELNA

**Frameworki (theHarvester, bbot, SpiderFoot) uruchamiamy TYLKO na własnych domenach/IP albo z pisemną zgodą właściciela.**
Nie na osobach prywatnych i nie na cudzej infrastrukturze „na próbę". Trafienie to trop, nie dowód:
ten sam identyfikator != ta sama osoba (min. 2 niezależne korelacje).

## Narzędzia

| Narzędzie | Co robi | Uruchomienie | Jak działa |
|---|---|---|---|
| Maigret | username -> profile | `START_MAIGRET.cmd` | venv `maigret-venv` (wcześniej zainstalowany) |
| ExifTool 13.59 | metadane plików (EXIF, GPS) | `START_EXIFTOOL.cmd` | przenośny, folder `exiftool\` |
| theHarvester 5.0.0 | subdomeny, e-maile, hosty dla domeny | `START_THEHARVESTER.cmd` | venv `theharvester-venv` (Python 3.14, wymagany przez projekt); źródła w `theharvester-src\` |
| bbot 3.0.2 | rozpoznanie powierzchni domeny | `START_BBOT.cmd` | Docker `blacklanternsecurity/bbot:stable` (oficjalnie tylko Linux); wyniki: `wyniki\bbot-data\` |
| SpiderFoot 4.0.0 | automat OSINT z panelem WWW | `START_SPIDERFOOT.cmd` | Docker, obraz `spiderfoot:local` zbudowany z `spiderfoot-src\`; panel http://127.0.0.1:5001; dane w wolumenie `spiderfoot-data` |
| dig (BIND 9.18) | zapytania DNS | `START_DIG.cmd` | Docker `dig-tools:local` (Alpine + bind-tools, `dig\Dockerfile`); zapas: `nslookup` |

Skróty `bin\bbot.cmd` i `bin\dig.cmd` pozwalają wpisywać `bbot ...` / `dig ...` jak zwykłe komendy (launchery dodają `bin` do PATH).

## Wymagania i uwagi

- bbot, SpiderFoot i dig wymagają działającego Docker Desktop.
- SpiderFoot: upstream nieaktywny od 2023 i ma stare zależności (m.in. cryptography 3.4.8). Panel nasłuchuje tylko na 127.0.0.1 i jest BEZ logowania. Nie wystawiaj portu 5001 na sieć. Brak oficjalnego obrazu w Docker Hub, stąd build lokalny.
- SpiderFoot zatrzymanie: dowolny klawisz w oknie launchera (lub `docker stop spiderfoot`).
- bbot: aktywne presety wysyłają ruch do celu; do bezpiecznego startu użyj trybu pasywnego (`-rf passive`).
- theHarvester: część źródeł wymaga kluczy API (nie dodawaj ich do repozytoriów).
- dig: ISC nie publikuje już binarek Windows dla BIND 9.18+ (winget ma tylko stare 9.17.12 jako usługę), dlatego wersja kontenerowa.
- Aktualizacja: `docker pull blacklanternsecurity/bbot:stable`; theHarvester: `git -C theharvester-src pull` i `theharvester-venv\Scripts\python -m pip install --upgrade .\theharvester-src`; exiftool: nowy zip z exiftool.org (SourceForge) do `exiftool\`.
