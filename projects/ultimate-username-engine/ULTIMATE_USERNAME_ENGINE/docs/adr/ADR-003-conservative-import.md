# Problem

Historyczne reguły mają słabe sygnały, odmienne merge semantics i nieobsługiwane pola.

# Rozważane rozwiązania

Wierna emulacja błędów; automatyczne wzmacnianie reguł; jawna konwersja z kwarantanną.

# Wybrane rozwiązanie

Importer tworzy kanoniczne DTO, pełną mapę pól, surowy rekord i hash źródła. Nieznane
pola i niejednoznaczny merge są jawne. Definicje konfliktujące pozostają wariantami.
Nie dodaje się wymyślonego profile binding, więc pozytyw historyczny daje najwyżej PROBABLE.

# Dlaczego

Poprawna konwersja składni nie potwierdza jakości detekcji. Puste markery nie są dowodem.

# Konsekwencje

Nie wszystkie rekordy trafią do katalogu wykonywalnego. Placeholder hostname, fragment URL,
activation, nie-HTTP i obce typy identyfikatora wymagają innego adaptera lub korekty.
Maigret engine dict bez lokalnego odpowiednika jest przypisywany i opatrzony diagnostyką;
konflikt headerów nie wybiera aktywnego wariantu. `ignore403` nie wyłącza failure gate.

# Źródło decyzji

Blueprint registry/import; maigret/sites.py:299; Sherlock interpolate_string;
WMN schema/checker; MG11–13, SH03/12, BB02, WM06/08.
