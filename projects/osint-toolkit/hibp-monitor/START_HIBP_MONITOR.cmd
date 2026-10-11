@echo off
rem Terminal HIBP Monitor. Dwuklik: tworzy .venv (pierwszy raz), potem wpisuj: hibp NAZWA_POLECENIA [opcje]
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Pierwsze uruchomienie: tworze .venv i instaluje projekt...
  py -3 -m venv .venv
  if errorlevel 1 (
    echo Nie udalo sie utworzyc .venv. Zainstaluj Pythona 3.12+ ^(py launcher^).
    pause
    exit /b 1
  )
  ".venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
  ".venv\Scripts\python.exe" -m pip install --quiet -e ".[dev]"
)
if not exist "config.toml" (
  if exist "config.example.toml" copy /y "config.example.toml" "config.toml" >nul
  echo Utworzono config.toml z szablonu: wpisz w nim WLASNE domeny.
)
doskey hibp="%~dp0.venv\Scripts\python.exe" -m hibp_monitor $*
doskey hibp-testy="%~dp0.venv\Scripts\python.exe" -m pytest -q
echo.
echo  HIBP MONITOR - defensywny, tylko oficjalne API Have I Been Pwned.
echo.
echo  hibp breaches                       nowe wycieki dla domen z config.toml (stan: state.json)
echo  hibp breaches --domain adobe.com    jedna domena zamiast listy z config.toml
echo  hibp breaches --no-save             podglad bez zapisu stanu
echo  hibp breaches --catalog --limit 10  pelny katalog wyciekow HIBP (najnowsze)
echo  hibp password                       czy haslo jest w wyciekach (pytanie o haslo bez echa)
echo  hibp domain-search domena.pl        [platne] konta Twojej zweryfikowanej domeny (wymaga HIBP_API_KEY)
echo  hibp domain-search domena.pl --show-addresses   dopiero jawnie pokazuje adresy
echo  dodaj --json do dowolnego polecenia dla wyniku maszynowego
echo  hibp-testy                          testy bez internetu
echo.
echo  Klucz API: tylko zmienna srodowiskowa:  set HIBP_API_KEY=...   (nigdy w plikach)
echo  Tylko WLASNE domeny i hasla. Do sieci idzie prefiks 5 znakow SHA-1, nigdy haslo.
echo.
cmd /k
