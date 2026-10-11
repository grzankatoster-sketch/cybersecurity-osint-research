@echo off
rem Terminal DNS Audit. Dwuklik, potem wpisuj: da domena [opcje]
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Pierwsze uruchomienie: tworze srodowisko .venv i instaluje zaleznosci...
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
doskey da="%~dp0.venv\Scripts\python.exe" -m dns_audit $*
doskey da-testy="%~dp0.venv\Scripts\python.exe" -m pytest -q "%~dp0tests"
echo.
echo  DNS AUDIT - audyt DNS i poczty domeny. Raporty zapisuja sie w: %CD%
echo.
echo  da example.com                          tabela: dane DNS + ustalenia (OK/INFO/WARN/FAIL)
echo  da example.com --html raport.html       raport HTML (otworz: start raport.html)
echo  da example.com --json                   wynik JSON
echo  da example.com --selectors moj,sel2     dodatkowe selektory DKIM (s= z naglowka DKIM-Signature)
echo  da example.com --resolver 1.1.1.1       wlasny resolver ^(walidujacy DNSSEC: flaga AD^)
echo  da-testy                                testy bez internetu
echo.
echo  Tylko publiczne rekordy DNS. Uzywaj na domenach wlasnych lub jawnych.
echo.
cmd /k
