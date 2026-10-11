@echo off
rem Terminal Net Intel. Dwuklik, potem wpisuj: ni ip|rdap|subdomains cel [opcje]
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Pierwsze uruchomienie: tworze srodowisko .venv i instaluje projekt...
  py -3 -m venv .venv
  if errorlevel 1 (
    echo Nie znaleziono Pythona ^(launcher "py"^). Zainstaluj Python 3.12+ i uruchom ponownie.
    pause
    exit /b 1
  )
  ".venv\Scripts\python.exe" -m pip install -q -e ".[dev]"
)
if not exist "wyniki" mkdir "wyniki"
cd /d "%~dp0wyniki"
doskey ni="%~dp0.venv\Scripts\python.exe" -m net_intel $*
doskey ni-testy="%~dp0.venv\Scripts\python.exe" -m pytest -q "%~dp0tests"
echo.
echo  NET INTEL - pasywny wywiad o infrastrukturze: IP, RDAP domeny, subdomeny. Raporty: %CD%
echo.
echo  ni ip 8.8.8.8                           ipinfo.io + odwrotny DNS ^(adresy prywatne: bez zapytan^)
echo  ni rdap example.com                     rejestrator, daty, statusy, serwery nazw, ustalenia
echo  ni subdomains example.com               subdomeny: HackerTarget + Cert Spotter + crt.sh
echo  ni subdomains example.com --resolve     j.w. + adresy A/AAAA znalezionych nazw
echo  ni rdap example.com --html raport.html  raport HTML ^(otworz: start raport.html^)
echo  ni ip 1.1.1.1 --json                    wynik JSON
echo  ni-testy                                testy bez internetu
echo.
echo  Opcjonalnie: set IPINFO_TOKEN=... ^(wyzszy limit ipinfo.io; token nigdy nie jest wypisywany^).
echo  Tylko publiczne dane jawnej infrastruktury. Uzywaj na zasobach wlasnych lub jawnych.
echo.
cmd /k
