@echo off
rem Terminal Entity Graph. Dwuklik, potem wpisuj: eg run --purpose "..." --domain example.com
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
set "BOOTSTRAP_PY=%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe"
if not exist "%BOOTSTRAP_PY%" set "BOOTSTRAP_PY=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if not exist "%BOOTSTRAP_PY%" set "BOOTSTRAP_PY="
if not defined BOOTSTRAP_PY for /f "delims=" %%P in ('where python 2^>nul') do if not defined BOOTSTRAP_PY set "BOOTSTRAP_PY=%%P"
if not exist "%BOOTSTRAP_PY%" (
  echo Blad: nie znaleziono interpretera Python 3.13+.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo Pierwsze uruchomienie: tworze srodowisko .venv i instaluje projekt ^(bez zaleznosci zewnetrznych^)...
  "%BOOTSTRAP_PY%" -m venv .venv
  if errorlevel 1 (
    echo Nie znaleziono Pythona ^(launcher "py"^). Zainstaluj Python 3.12+ i uruchom ponownie.
    pause
    exit /b 1
  )
  ".venv\Scripts\python.exe" -m pip install -q -e ".[dev]"
)
if not exist "wyniki" mkdir "wyniki"
cd /d "%~dp0wyniki"
doskey eg="%~dp0.venv\Scripts\python.exe" -m entity_graph $*
doskey eg-testy="%~dp0.venv\Scripts\python.exe" -m pytest -q "%~dp0tests"
echo.
echo  ENTITY GRAPH - graf powiazan OSINT dla zleconych, autoryzowanych badan. Wyniki: %CD%
echo.
echo  eg run --purpose "audyt wlasnej infrastruktury firmy X" --domain example.com
echo  eg run --purpose "..." --ip 203.0.113.7 --depth 0          sam adres, bez rozwijania
echo  eg run --purpose "..." --email jan@firma.pl --domain firma.pl
echo  eg run --purpose "..." --username jkowalski --ue-tags social,pl     skan username-engine (wolny bez --ue-tags)
echo  eg run --purpose "..." --person "Jan Kowalski" --max-usernames 8     kandydaci + dorki do recznego przegladu
echo  eg run --purpose "..." --phone "+48 603 123 456"                     tylko metadane z planu numeracji
echo  eg run --purpose "..." --domain example.com --offline                bez sieci (tylko transformacje offline)
echo  eg export graph.json --graphml g.graphml --html raport.html          eksport istniejacego grafu
echo  eg audit-verify KATALOG\audit.jsonl                                  kontrola lancucha dziennika audytu
echo  eg transforms                                                        lista transformacji
echo  eg rozszerz --help                                                    rundy kandydatow, kotwice i limity
echo  eg-testy                                                             testy bez internetu
echo.
echo  Kazde badanie wymaga --purpose i zapisuje graph.json, graph.graphml, report.html, audit.jsonl w nowym katalogu.
echo  Klucz HIBP: tylko WLASNY, tylko zmienna:  set HIBP_API_KEY=...   (nigdy w plikach)
echo  Brak wyszukiwania osoby po numerze telefonu, brak omijania blokad, brak geolokalizacji z IP.
echo  Trafienie to trop, nie dowod.
echo.
cmd /k
