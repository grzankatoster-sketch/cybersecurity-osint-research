@echo off
rem Terminal z ExifToolem (przenosny, folder exiftool\). Dwuklik, potem wpisuj np.: exiftool zdjecie.jpg
chcp 65001 >nul
set "PATH=%~dp0exiftool;%PATH%"
cd /d "%~dp0wyniki" 2>nul || (mkdir "%~dp0wyniki" & cd /d "%~dp0wyniki")
echo.
echo  EXIFTOOL gotowy. Katalog roboczy: %CD%
echo.
echo  exiftool plik.jpg                  wszystkie metadane
echo  exiftool -gps:all -n plik.jpg      tylko GPS (liczbowo)
echo  exiftool -csv -r FOLDER ^> out.csv   metadane calego folderu do CSV
echo  exiftool -all= kopia.jpg           USUN metadane (z kopii pliku!)
echo  exiftool -ver                      wersja
echo.
echo  Uzywaj na wlasnych plikach lub takich, do ktorych masz prawo.
echo.
cmd /k
