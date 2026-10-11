@echo off
rem Kasuje srodowisko: kontenery, siec i wolumeny projektu osint-env oraz obraz osint-toolbox.
rem NIE kasuje katalogu work\ (Twoje dane) - tylko wyswietla komunikat.
chcp 65001 >nul
cd /d "%~dp0"
echo.
echo  RESET: zostana usuniete kontenery, siec i WOLUMENY osint-env (dane SpiderFoot i bbot)
echo  oraz obrazy osint-toolbox:latest i osint-toolbox:tests.
echo  Nie ruszam innych obrazow ani wolumenow (np. spiderfoot-data, spiderfoot:local).
echo.
set /p CONFIRM=  Kontynuowac? [T/N]: 
if /i not "%CONFIRM%"=="T" (
  echo  Anulowano.
  exit /b 0
)
docker compose --profile "*" down -v --remove-orphans
docker image rm osint-toolbox:latest osint-toolbox:tests 2>nul
echo.
echo  Gotowe. Katalog "%~dp0work" NIE zostal usuniety - zawiera Twoje wyniki.
echo  Jesli chcesz go skasowac, zrob to recznie (po sprawdzeniu zawartosci).
echo  Odtworzenie srodowiska: START_OSINT_ENV.cmd
pause
