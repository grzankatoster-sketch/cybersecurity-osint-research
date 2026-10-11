@echo off
rem Shim: dig (BIND 9.18) w kontenerze Alpine. Windows nie ma oficjalnych binarek BIND 9.18+.
docker run --rm dig-tools:local %*
