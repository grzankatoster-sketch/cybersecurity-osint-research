# Problem

Donorzy mieszają konfigurację, futures, klienta HTTP i dane wynikowe. Błąd HTTP bywa brakiem konta.

# Rozważane rozwiązania

Luźne dict; model runtime validation z dodatkową biblioteką; frozen dataclasses i walidator wejścia.

# Wybrane rozwiązanie

Frozen dataclasses, tuple dla kolekcji konfiguracji, oddzielne Verdict i ExecutionState.
Granica JSON ma rekurencyjny jawny typ. FieldObservation przechowuje JSON tekst,
aby zagnieżdżona lista/słownik nie mogła zmienić wcześniejszej immutable obserwacji.

# Dlaczego

Modele nie wymagają ciężkiej zależności. Walidator registry izoluje błędne rekordy;
DetectionResult odrzuca kombinację błędu z rozstrzygniętym account verdict.

# Konsekwencje

Konfiguracja jest walidowana przed planowaniem; samo stworzenie SiteDefinition nie certyfikuje jej semantyki.
TransportResponse może zachować częściowe body razem z błędem. Confidence pozostaje null.

# Źródło decyzji

Blueprint §§9,12–16; WMN scripts/checker/models.py::CheckDetail;
Maigret result.py::SiteResult i error_detection.py::detect_error_page;
SH04, MG19, SO05, CO02 w DESIGN_LEDGER.

