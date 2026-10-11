@echo off
rem Terminal Phone Check. Dwuklik, potem wpisuj: pc NUMER [opcje]
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo Pierwsze uruchomienie: tworze srodowisko .venv i instaluje zaleznosci...
  py -3 -m venv "%~dp0.venv"
  "%~dp0.venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
  "%~dp0.venv\Scripts\python.exe" -m pip install --quiet -e "%~dp0.[dev]"
)
set "PC_PY=%~dp0.venv\Scripts\python.exe"
if not exist "%~dp0wyniki" mkdir "%~dp0wyniki"
cd /d "%~dp0wyniki"
doskey pc="%PC_PY%" -m phone_check $*
echo.
echo  PHONE CHECK - offline walidator numeru telefonu (bez internetu, bez zapytan do serwisow)
echo  Wyniki zapisuja sie w: %CD%
echo.
echo  pc "603 123 456"                          numer w dowolnym formacie (domyslnie region PL)
echo  pc "+49 30 123456" --region DE            numer zagraniczny lub inny region domyslny
echo  pc 603123456 --dorks                      + warianty zapisu w cudzyslowie do recznego wyszukania
echo  pc --file numery.txt --csv wyniki.csv     wsadowo: jeden numer na linie, CSV dla Excela
echo  pc --file numery.txt --json wyniki.json   wsadowo, JSON
echo.
echo  Operator z planu numeracji to pierwotny przydzial; w PL numer mogl byc przeniesiony.
echo  Aktualny operator: https://numeracja.uke.gov.pl/ (reczna weryfikacja).
echo  Tylko numery wlasne/firmowe lub w ramach zlecenia.
echo.
cmd /k
