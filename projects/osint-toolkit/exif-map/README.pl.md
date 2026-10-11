# Exif Map

Metadane i geotagi **własnych** zdjęć i plików: czas wykonania, aparat, oprogramowanie, GPS, wysokość, kierunek. Mapa HTML i usuwanie metadanych przed publikacją (OPSEC). Sekcja 4 audytu: `../AUDYT_OSINT_NOTATKI_2026-10-03.md`.

Zakres: tylko pliki lokalne. Nic nie jest pobierane z internetu, nie ma rozpoznawania twarzy ani identyfikacji osób. Narzędzie służy do sprawdzenia, co ujawniają Twoje własne zdjęcia (lub pliki ze zlecenia, do których masz prawo).

## Uruchomienie

Najprościej: dwuklik `START_EXIF_MAP.cmd` (przy pierwszym uruchomieniu tworzy `.venv`), potem `em SCIEZKA [opcje]`.

```bash
py -m venv .venv
.venv\Scripts\python -m pip install "Pillow>=10" "folium>=0.17" pytest
set PYTHONPATH=src && .venv\Scripts\python -m exif_map C:\zdjecia --map mapa.html
.venv\Scripts\python -m pytest -q          # testy bez internetu
```

## Opcje

| Opcja | Działanie |
|---|---|
| `SCIEZKA` | plik albo folder (rekurencyjnie): jpg, jpeg, png, tif, tiff, heic/heif |
| (domyślnie) | tabela tekstowa + ostrzeżenia o GPS + podsumowanie |
| `--json [PLIK]` | JSON; bez PLIK na stdout (wtedy komentarze idą na stderr) |
| `--csv [PLIK]` | CSV (UTF-8 z BOM, do Excela) |
| `--map PLIK.html` | mapa folium: znacznik na plik (miniatura, nazwa, czas, aparat), linia trasy w kolejności czasu |
| `--no-tiles` | mapa bez kafelków OpenStreetMap (same punkty i trasa); Leaflet nadal z CDN, patrz Ograniczenia |
| `--strip FOLDER` | zapis **kopii bez metadanych** do FOLDER; oryginały nigdy nie są nadpisywane |
| `--reverse` | instrukcja **ręcznego** wyszukiwania obrazem (TinEye, Google Lens, Bing, Yandex): skąd pochodzi zdjęcie, czy jest przerobione. Narzędzie nic nie wysyła. Bez `--strip` ostrzega o plikach z GPS; z udanym `--strip` wskazuje folder czystych kopii. Celowo bez wyszukiwarek twarzy (PimEyes): dane biometryczne, art. 9 RODO |
| `--no-exiftool` | wymuś Pillow |
| `--quiet` | bez tabeli |

Kod wyjścia: 0 ok, 1 brak plików, 2 brak ścieżki, 3 `--strip` nie wyczyścił któregoś pliku (w tym plik większy niż limit 200 MB, który jest pomijany z komunikatem).

## Przykład

```
Plik   Czas wykonania    Aparat        Oprogramowanie  GPS (lat, lon)       Wys. [m]  Kier. [deg]
-----  ----------------  ------------  --------------  -------------------  --------  -----------
a.jpg  2024-05-01 10:00  TestCam TC-1  Test 1.0        52.232278, 21.008583 110.5     90
c.png  2024-05-02 12:00  TestCam TC-1  Test 1.0        -                    -         -

UWAGA: 1 z 2 plikow ujawnia lokalizacje (GPS w metadanych):
  - a.jpg: Ten plik ujawnia lokalizacje (GPS w metadanych). (52.232278, 21.008583)
```

## Jak to działa

- **Pillow** (zawsze): EXIF (Make, Model, Software, DateTimeOriginal/Digitized/DateTime), GPS IFD. Konwersja DMS na stopnie dziesiętne z uwzględnieniem ref N/S/E/W (S i W ujemne), wysokość z AltitudeRef (1 = poniżej poziomu morza), kierunek z GPSImgDirection. Współrzędne (0, 0) i spoza zakresu są traktowane jako brak GPS.
- **exiftool** (opcjonalnie): jeśli jest w `PATH` albo w `../narzedzia/` (szukane rekurencyjnie `exiftool.exe` / `exiftool(-k).exe`), dane idą przez `exiftool -config "" -json -n ... -- <ścieżki absolutne>` (pusta konfiguracja; `--` oddziela nazwy plików od opcji, więc plik o nazwie `-overwrite_original.jpg` nie jest opcją) i obejmują m.in. obiektyw, numery seryjne, autora, formaty, których Pillow nie czyta. Gdy exiftool zawiedzie dla pliku, ten plik czyta Pillow. Narzędzie niczego nie instaluje.
- **Strip**: JPEG bez rotacji EXIF jest czyszczony **bezstratnie** parserem całego strumienia: usuwane są segmenty APP1 (Exif/XMP), APP3–13, APP15, COM, MPF/APP2 inne niż ICC, APP0 inne niż JFIF i APP14 inne niż Adobe, także gdy leżą **między skanami** (progressive JPEG); wszystko **za znacznikiem EOI** (np. doklejony ZIP lub tekst z GPS) jest odcinane. Zostają JFIF, ICC, Adobe APP14 i dane skanów bez zmian. Pozostałe formaty i JPEG z orientacją są kodowane ponownie z czystej kopii pikseli (orientacja zapiekana w obrazie; JPEG jakość 95). Po zapisie **cały** plik wynikowy jest weryfikowany ponownie (struktura JPEG, EXIF/GPS, XMP, komentarze, dane za EOI); nazwa kolidująca z istniejącym plikiem lub oryginałem dostaje przyrostek `_clean`, `_clean2`... Katalog `--strip` leżący wewnątrz skanowanego folderu jest pomijany przy skanie.

## Ograniczenia

- Czas EXIF jest lokalny dla aparatu, bez strefy (Pillow nie wyciąga offsetu). Trasa wg czasu zakłada jedną strefę.
- HEIC/HEIF: Pillow czyta je tylko z `pip install pillow-heif`; bez tego użyj exiftool (odczyt) — `--strip` dla HEIC wymaga pillow-heif.
- Strip usuwa metadane osadzone w pliku, nie usuwa informacji z samej treści obrazu (tablice, twarze, widoczne szyldy) ani nazwy pliku, ani metadanych systemu plików (daty pliku). Zachowuje profil ICC (kolor). Wielostronicowe TIFF: tylko pierwsza klatka.
- Mapa jest plikiem HTML z miniaturami i dokładnymi współrzędnymi: nie publikuj jej. **W trybie domyślnym przeglądarka przy otwarciu mapy łączy się z OpenStreetMap (kafelki) i z CDN (Leaflet i pochodne biblioteki), więc te serwery widzą Twoje IP i oglądany obszar** (samo narzędzie niczego nie pobiera; ostrzeżenie jest też w banerze mapy). `--no-tiles` usuwa kafelki OSM (zostaje siatka punktów i trasa), ale **biblioteki JS/CSS nadal ładują się z CDN** (celowo, bez wbudowywania ich w plik), więc przeglądarka dalej łączy się z siecią. Pełna praca offline wymagałaby własnej kopii bibliotek i nie jest zapewniana.
- Teksty w mapie (nazwa pliku, aparat) są escapowane także pod literały szablonowe JS folium (`$`, backtick, backslash jako encje HTML). W CSV tekst zaczynający się od `=`, `+`, `-`, `@`, TAB lub CR dostaje apostrof (liczby bez zmian); w tabeli tekstowej znaki sterujące są pokazywane jako `\xNN`.
- Strip wczytuje JPEG w całości do pamięci: pliki wejściowe powyżej 200 MB (`MAX_INPUT_BYTES` w `strip.py`) są pomijane z komunikatem i kodem wyjścia 3. Uszkodzony lub ucięty JPEG (bez EOI) kończy się błędem, a nie niepewną kopią. exiftool nie widzi metadanych ukrytych między skanami progressive ani za EOI, ale `--strip` je usuwa i weryfikuje.
- Pillow nie czyta metadanych wideo, RAW ani XMP-only; do tego służy exiftool.
