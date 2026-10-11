@echo off
rem Terminal z theHarvesterem (venv Python 3.14). Dwuklik, potem wpisuj np.: theHarvester -d twojadomena.pl -b crtsh
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0wyniki" 2>nul || (mkdir "%~dp0wyniki" & cd /d "%~dp0wyniki")
call "%~dp0theharvester-venv\Scripts\activate.bat"
echo.
echo  THEHARVESTER gotowy. Wyniki: %CD%
echo.
echo  theHarvester --help                lista opcji i zrodel
echo  theHarvester -d DOMENA -b crtsh    subdomeny z certyfikatow (zrodlo bez klucza API)
echo  theHarvester -d DOMENA -b all -f raport   wszystkie zrodla, zapis raport.json/.xml
echo  Klucze API zrodel: patrz dokumentacja (api-keys.yaml).
echo.
echo  TYLKO WLASNE DOMENY lub pisemna zgoda wlasciciela. Wynik to trop, nie dowod.
echo.
cmd /k
