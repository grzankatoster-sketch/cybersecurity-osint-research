@echo off
rem Shim: bbot w Dockerze (Linux-only). Wyniki/konfiguracja w narzedzia\wyniki\bbot-data
if not exist "%~dp0..\wyniki\bbot-data" mkdir "%~dp0..\wyniki\bbot-data"
docker run --rm -it -v "%~dp0..\wyniki\bbot-data:/root/.bbot" blacklanternsecurity/bbot:stable %*
