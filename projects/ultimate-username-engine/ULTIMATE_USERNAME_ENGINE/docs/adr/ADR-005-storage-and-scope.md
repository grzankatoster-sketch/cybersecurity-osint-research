# Problem

Nadpisanie pliku przed walidacją niszczy dobry snapshot; niepełny eksport ukrywa błędy.

# Rozważane rozwiązania

Pamięć wszystkich wyników; append-only plik bez indeksu; SQLite journal i atomowe eksporty.

# Wybrane rozwiązanie

SQLite zachowuje base i latest po task_id, JSON eksportuje wszystkie stany. Atomic write używa
unikalnego staging, fsync i replace. SnapshotStore waliduje hash oraz schema, ma exclusive lock i CAS.

# Dlaczego

Możliwy jest odczyt po przerwaniu oraz eksport bez przechowywania N wyników w Pythonie.

# Konsekwencje

Sink SQLite jest synchroniczny; pomiary schedulera wykluczają dysk. Błąd sinka daje jawny
INTERNAL_ERROR, licznik sink_errors i nie zawiesza strumienia. Brak internetowego updatera;
promocja dotyczy lokalnych danych. Lock po crash nie jest automatycznie przejmowany.
CLI/API nie mają browsera, AI, recursive discovery, GUI, PDF ani XLSX. Te różnice zakresu
są wymienione osobno w 92-elementowym manifest, bez udawania naprawienia kodu legacy.

# Źródło decyzji

Blueprint journal/export/MVP; maigret/report.py:874/927; db_updater.py:74/123;
Blackbird list_operations.py:34; MG21/26, BB05/15, WM05.
