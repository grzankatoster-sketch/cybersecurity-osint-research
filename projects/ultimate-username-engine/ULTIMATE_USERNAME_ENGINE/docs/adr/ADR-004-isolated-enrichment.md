# Problem

Synchroniczny parser może zablokować event loop; błąd enrichment nie może utracić detekcji.

# Rozważane rozwiązania

Parser w loop; thread z timeout bez możliwości przerwania; osobny proces z deadline.

# Wybrane rozwiązanie

Pure body-in parsers w ograniczonej liczbie procesów spawn. Parent kończy proces po deadline
i czeka na cleanup. Wynik bazowy jest commitowany wcześniej, enrichment ma osobny stan.

# Dlaczego

Timeout wątku nie zatrzymuje obliczeń; izolowany proces pozwala zwolnić zasoby.

# Konsekwencje

Cold start ma koszt, dlatego enrichment jest opcjonalne. Limit body wynosi domyślnie 1 MiB,
liczba pól 64, wartość pola 16 KiB. Bufor odpowiedzi oczekujących na extraction jest ograniczony
przez job_buffer i max_jobs; nie jest to cache całego katalogu. Relacja OWNER wymaga guard;
pozostałe pola mają UNVERIFIED. Nie ma ukrytego HTTP, aktywacji ani pobierania obrazów.

# Źródło decyzji

Blueprint base-result commit/process boundary; Maigret checking.py:1735;
Blackbird parse.py:55; socid schemes.py:255/300/421–475; MG02/20, BB04/08/12, SO01–05/09–12.
