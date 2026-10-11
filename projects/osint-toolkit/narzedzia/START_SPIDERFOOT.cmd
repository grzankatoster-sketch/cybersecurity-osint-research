@echo off
rem SpiderFoot 4.0 w Dockerze: panel WWW na http://127.0.0.1:5001 (tylko lokalnie). Wymaga Docker Desktop.
chcp 65001 >nul
echo.
echo  Uruchamiam SpiderFoot... (dane w wolumenie Dockera: spiderfoot-data)
docker rm -f spiderfoot >nul 2>&1
docker run -d --rm --name spiderfoot -p 127.0.0.1:5001:5001 --security-opt no-new-privileges -v spiderfoot-data:/var/lib/spiderfoot spiderfoot:local >nul
if errorlevel 1 (
  echo  BLAD: nie udalo sie uruchomic kontenera. Czy Docker Desktop dziala i obraz spiderfoot:local istnieje?
  pause
  exit /b 1
)
timeout /t 6 /nobreak >nul
start "" http://127.0.0.1:5001
echo.
echo  Panel: http://127.0.0.1:5001   (bez logowania - dostepny tylko z tego komputera)
echo  TYLKO WLASNE DOMENY/IP lub pisemna zgoda. Skan osoby = wysokie ryzyko prawne.
echo.
echo  Nacisnij dowolny klawisz, aby ZATRZYMAC SpiderFoot (wyniki zostaja w wolumenie).
pause >nul
docker stop spiderfoot >nul
echo  Zatrzymano.
