@echo off
rem Terminal testowy Username Engine. Dwuklik, potem wpisuj: ue NAZWA [opcje]
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
set "PYTHONPATH=%~dp0src"
set "UE_PY=%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe"
if not exist "%UE_PY%" set "UE_PY="
if not defined UE_PY for /f "delims=" %%P in ('where python 2^>nul') do if not defined UE_PY set "UE_PY=%%P"
if not defined UE_PY for /f "delims=" %%P in ('where py 2^>nul') do if not defined UE_PY set "UE_PY=%%P"
if not defined UE_PY (
  echo Blad: nie znaleziono interpretera Python. Zainstaluj Python 3.12+ albo ustaw sciezke w tym pliku.
  pause
  exit /b 1
)
echo Interpreter: %UE_PY%
if not exist "%~dp0data\sites.json" (
  echo Pierwsze uruchomienie: buduje baze serwisow WhatsMyName + Maigret...
  "%UE_PY%" "%~dp0scripts\build_db.py"
)
if not exist "%~dp0data\geo.json" (
  echo Buduje slownik miast i krajow GeoNames...
  "%UE_PY%" "%~dp0scripts\build_geo.py"
)
if not exist "%~dp0wyniki" mkdir "%~dp0wyniki"
cd /d "%~dp0wyniki"
doskey ue="%UE_PY%" -m username_engine $*
doskey ue-baza="%UE_PY%" "%~dp0scripts\build_db.py"
doskey ue-zdrowie="%UE_PY%" "%~dp0scripts\health_check.py"
doskey ue-purge="%UE_PY%" -m username_engine purge $*
echo.
echo  USERNAME ENGINE - nasza wersja. Wyniki i raporty zapisuja sie w: %CD%
echo.
echo  ue NAZWA                                  skan wszystkich ~5800 serwisow (~4 min)
echo  ue NAZWA --tags social,pl                 tylko wybrane kategorie (szybciej)
echo  ue NAZWA --report raport.html             raport HTML z linkami; laduje w podkatalogu skanu w wyniki (sciezka: wiersz Katalog skanu)
echo  ue NAZWA --wayback --report r.html        + archiwum: profile, ktore kiedys istnialy (usuniete)
echo  ue NAZWA --dorks                          linki do Google/Bing/DDG (wzmianki, podobne nazwy)
echo  ue "Jan Kowalski" --dorks-only             tylko linki; bez skanu i bez ruchu do serwisow
echo  ue Sampler51 --show-variants             pokaz warianty: sampler_51, sampler.51, sampler...
echo  ue Sampler51 --variants --report r.html   skan wariantow + ocena, czy to ta sama osoba
echo  ue "Jan Kowalski" --variants --max-variants 6 --years 1990
echo                                            warianty z imienia i nazwiska (+ rok)
echo  Po kazdym skanie: kraj z profili (lokalizacja, jezyk, domena) i powiazania kont.
echo  ue NAZWA --csv wyniki.csv                 eksport do Excela
echo  ue NAZWA --min-confidence 0 --all         pokaz wszystko: slabe trafienia, braki, bledy
echo  ue NAZWA --include-broken                 nie pomijaj martwych/zablokowanych serwisow
echo  ue NAZWA --strict-tls                    blad certyfikatu TLS = ERROR (bez ponowienia bez weryfikacji)
echo  ue NAZWA --details                       w terminalu tez surowe dane z profili (domyslnie tylko wnioski)
echo  Raporty (HTML/JSON/CSV) wygasaja po 12 h (--ttl-hours N, 0 = bez wygasania) i sa usuwane przy kolejnym skanie.
echo  ue-purge                                  usun wygasle raporty teraz (--dry-run: tylko policz)
echo  ue-baza                                   odswiez baze serwisow (potem: ue-zdrowie)
echo  ue-zdrowie                                kontrola bazy: oznacza martwe i zepsute wpisy (~6 min)
echo.
echo  Pewnosc: 0.97 = tekst profilu + kontrola, 0.90 = tekst profilu, 0.80 = kod vs losowa nazwa,
echo           ponizej 0.6 ukryte. Bledy (blokady, timeout) NIE oznaczaja braku konta.
echo  Ta sama nazwa != ta sama osoba. Trafienie to trop, nie dowod.
echo.
cmd /k
