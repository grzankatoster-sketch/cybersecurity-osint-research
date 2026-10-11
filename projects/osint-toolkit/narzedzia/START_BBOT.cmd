@echo off
rem Terminal z BBOT (Docker, bo bbot jest Linux-only). Wymaga uruchomionego Docker Desktop.
chcp 65001 >nul
set "PATH=%~dp0bin;%PATH%"
cd /d "%~dp0wyniki" 2>nul || (mkdir "%~dp0wyniki" & cd /d "%~dp0wyniki")
echo.
echo  BBOT gotowy (obraz blacklanternsecurity/bbot:stable). Wyniki: %~dp0wyniki\bbot-data\scans
echo.
echo  bbot --help
echo  bbot --version
echo  bbot -l                                       lista modulow
echo  bbot -t TWOJADOMENA.pl -p subdomain-enum      enumeracja subdomen (pasywna/aktywna wg presetu)
echo  bbot -t TWOJADOMENA.pl -f subdomain-enum -rf passive    tylko pasywnie
echo.
echo  TYLKO WLASNE DOMENY/IP lub pisemna zgoda. Presety aktywne wysylaja ruch do celu.
echo.
cmd /k
