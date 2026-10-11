@echo off
rem OSINT MCP: tworzy .venv, instaluje serwer i pokazuje gotowe polecenia rejestracji w Claude. Niczego sam nie rejestruje.
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
echo.
echo  OSINT MCP - serwer MCP nad modulami repo ^(defensywnie, tylko infrastruktura^).
echo.
echo  Rejestracja w Claude Code ^(jednorazowo, w dowolnym terminalu^):
echo    claude mcp add osint -- "%~dp0.venv\Scripts\python.exe" -m osint_mcp
echo.
echo  Testy bez internetu:   "%~dp0.venv\Scripts\python.exe" -m pytest -q "%~dp0tests"
echo.
echo  Wymagane .venv modulow ^(brakujace utworz ich START_*.cmd^):
for %%M in (dns-audit phone-check hibp-monitor net-intel) do (
  if exist "%~dp0..\%%M\.venv\Scripts\python.exe" ( echo    [OK]    %%M ) else ( echo    [BRAK]  %%M  ^(uruchom %%M\START_*.cmd^) )
)
echo.
cmd /k
