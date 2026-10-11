@echo off
rem Terminal Site Audit. Dwuklik, potem wpisuj: sa adres [opcje]
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Pierwsze uruchomienie: tworze srodowisko .venv...
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
doskey sa="%~dp0.venv\Scripts\python.exe" -m site_audit $*
doskey sa-testy="%~dp0.venv\Scripts\python.exe" -m pytest -q "%~dp0tests"
echo.
echo  SITE AUDIT - audyt konfiguracji strony WWW. Raporty zapisuja sie w: %CD%
echo.
echo  sa example.com                          tabela: dane + ustalenia (OK/INFO/WARN/FAIL)
echo  sa example.com --html raport.html       raport HTML (otworz: start raport.html)
echo  sa https://example.com/sklep --json     wynik JSON
echo  sa example.com --no-extra               tylko strona glowna (bez robots/security.txt/sitemap)
echo  sa 192.168.1.10 --allow-private         wlasna siec lokalna (domyslnie blokowana)
echo  sa-testy                                testy bez internetu
echo.
echo  Uzywaj na stronach wlasnych lub za zgoda. DNS i poczte domeny sprawdza dns-audit.
echo.
cmd /k
