@echo off
rem Terminal z dig (BIND 9.18 w kontenerze Alpine, bo Windows nie ma oficjalnych binarek). Wymaga Docker Desktop.
chcp 65001 >nul
set "PATH=%~dp0bin;%PATH%"
echo.
echo  DIG gotowy (Docker, obraz dig-tools:local). Przyklady:
echo.
echo  dig twojadomena.pl MX +short
echo  dig twojadomena.pl TXT +short           (SPF, weryfikacje)
echo  dig _dmarc.twojadomena.pl TXT +short
echo  dig twojadomena.pl DNSKEY +dnssec
echo  dig @1.1.1.1 twojadomena.pl ANY
echo.
echo  Zapytania DNS o cudze domeny sa publiczne i legalne, ale bez masowego skanowania.
echo  Zapasowo: nslookup dziala bez Dockera.
echo.
cmd /k
