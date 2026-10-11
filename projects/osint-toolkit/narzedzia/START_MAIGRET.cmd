@echo off
rem Terminal z Maigretem (venv + poprawka DNS + UTF-8). Dwuklik, potem wpisuj np.: maigret nazwa
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0wyniki" 2>nul || (mkdir "%~dp0wyniki" & cd /d "%~dp0wyniki")
call "%~dp0maigret-venv\Scripts\activate.bat"
echo.
echo  MAIGRET gotowy. Wyniki zapisuja sie w: %CD%
echo.
echo  maigret NAZWA                      szybki skan (top ~500 serwisow)
echo  maigret NAZWA -a                   wszystkie serwisy (~3000+ aktywnych)
echo  maigret NAZWA --tags pl            tylko polskie serwisy
echo  maigret NAZWA -H                   raport HTML  (-P = PDF, -J simple = JSON)
echo  maigret NAZWA1 NAZWA2              kilka nazw naraz
echo  maigret NAZWA --no-recursion       bez szukania po znalezionych ID
echo  maigret --web 5000                 panel w przegladarce: http://127.0.0.1:5000
echo.
echo  Pamietaj: ta sama nazwa != ta sama osoba. Trafienie to trop, nie dowod.
echo.
cmd /k
