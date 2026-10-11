@echo off
rem Panel OSINT: dwuklik otwiera przegladarke z widokiem narzedzi (dns-audit, phone-check, hibp-monitor, exif-map).
chcp 65001 >nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"
rem Nie polegamy na launcherze py -3: na tym komputerze launcher nie widzi
rem instalacji, mimo ze interpreter jest dostepny po sciezce.
set "PANEL_PY=%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe"
if not exist "%PANEL_PY%" set "PANEL_PY=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
if not exist "%PANEL_PY%" set "PANEL_PY="
if not defined PANEL_PY for /f "delims=" %%P in ('where python 2^>nul') do if not defined PANEL_PY set "PANEL_PY=%%P"
if not exist "%PANEL_PY%" (
  echo Blad: nie znaleziono interpretera Python 3.13+.
  pause
  exit /b 1
)
echo Interpreter: %PANEL_PY%
echo Narzedzia bez .venv: uruchom raz ich START_*.cmd, zeby zainstalowac zaleznosci.
"%PANEL_PY%" "%~dp0app.py" %*
pause
