@echo off
rem Terminal Exif Map. Dwuklik, potem wpisuj: em SCIEZKA [opcje]
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
set "PYTHONPATH=%~dp0src"
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo Pierwsze uruchomienie: tworze .venv i instaluje Pillow + folium...
  py -3 -m venv "%~dp0.venv"
  "%~dp0.venv\Scripts\python.exe" -m pip install --quiet "Pillow>=10" "folium>=0.17" pytest
)
set "EM_PY=%~dp0.venv\Scripts\python.exe"
if not exist "%~dp0wyniki" mkdir "%~dp0wyniki"
cd /d "%~dp0wyniki"
doskey em="%EM_PY%" -m exif_map $*
doskey em-testy="%EM_PY%" -m pytest -q "%~dp0tests"
echo.
echo  EXIF MAP - metadane i geotagi WLASNYCH zdjec. Wyniki zapisuja sie w: %CD%
echo  Analiza lokalna: nic nie jest wysylane do internetu, brak rozpoznawania twarzy.
echo.
echo  em C:\zdjecia                              tabela: czas, aparat, oprogramowanie, GPS, wysokosc, kierunek
echo  em C:\zdjecia\IMG_1.jpg                    jeden plik
echo  em C:\zdjecia --map mapa.html              mapa HTML ze znacznikami, miniaturami i trasa wg czasu
echo  em C:\zdjecia --json wynik.json            JSON  (samo --json: na ekran)
echo  em C:\zdjecia --csv wynik.csv              CSV do Excela
echo  em C:\zdjecia --strip C:\zdjecia_czyste    KOPIE bez metadanych (oryginaly nietkniete) - przed publikacja
echo  em-testy                                   testy (bez sieci)
echo.
echo  Ostrzezenie "ten plik ujawnia lokalizacje" = zdjecie ma GPS: nie publikuj go bez --strip.
echo  exiftool (jesli jest w PATH lub w OSINT\narzedzia) daje pelniejsze dane; bez niego dziala Pillow.
echo.
cmd /k
