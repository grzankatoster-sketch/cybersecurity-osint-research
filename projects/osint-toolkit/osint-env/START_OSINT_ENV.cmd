@echo off
rem Buduje obraz osint-toolbox i otwiera powloke w kontenerze (toolbox). Wymaga Docker Desktop.
chcp 65001 >nul
cd /d "%~dp0"
if not exist work mkdir work
docker info >nul 2>&1
if errorlevel 1 (
  echo.
  echo  BLAD: Docker Desktop nie dziala. Uruchom go i sprobuj ponownie.
  pause
  exit /b 1
)
echo.
echo  Buduje obraz osint-toolbox (pierwszy raz kilka minut, potem z cache)...
docker compose build toolbox
if errorlevel 1 (
  echo.
  echo  BLAD: build nie powiodl sie. Czy jest dostep do internetu (pip, apt, GitHub)?
  pause
  exit /b 1
)
echo.
echo  Jedyny zapisywalny katalog hosta: %~dp0work   (w kontenerze: /work)
echo  Klucz HIBP tylko ze zmiennej hosta:  set HIBP_API_KEY=...   (przed uruchomieniem tego pliku)
echo.
echo  username-engine --help            python -m dns_audit TWOJADOMENA.pl
echo  python -m hibp_monitor --help     python -m exif_map /work/zdjecia
echo  python -m phone_check +48...      exiftool plik.jpg   dig TWOJADOMENA.pl MX +short
echo  theHarvester -d TWOJADOMENA.pl -b duckduckgo
echo.
echo  TYLKO WLASNE DOMENY/IP lub pisemna zgoda. IP wychodzi Twoim laczem - VPN po stronie hosta.
echo  Wyjscie z kontenera: exit  (kontener jest kasowany, /work zostaje).
echo.
docker compose run --rm toolbox
