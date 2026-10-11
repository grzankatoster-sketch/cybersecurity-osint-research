# Problem

Task dla każdej definicji i warstwowe retry mnożą zasoby. Redirect może ominąć limit hosta.

# Rozważane rozwiązania

Gather całego katalogu; stałe workers śpiące podczas backoff; wspólny dispatcher z gotowością pracy.

# Wybrane rozwiązanie

Jeden Scheduler na runtime, leniwi producenci jobów, ograniczona suma pending+active,
osobny bounded output per job i limity global/per-origin/per-job. Retry ma ready_at;
redirect jest nową próbą z nowym origin. Permit pozostaje zajęty aż transport zakończy cleanup.

# Dlaczego

Pozwala utrzymać zdrowe hosty w ruchu podczas cooldown i nie tworzy N kosztownych tasks.

# Konsekwencje

Przebieg jednej próby obejmuje transport i krótki detector. Enrichment jest później,
po zwolnieniu slotu HTTP. Search_many jest leniwy i sekwencyjny; równoległe search na
wspólnym engine mają wspólne limity. Jawny limit max_jobs odrzuca nadmiar zgłoszeń.
Origin oznacza scheme+hostname+effective port, bez heurystyki dwóch końcowych etykiet DNS.

# Źródło decyzji

Blueprint scheduler/runtime; Maigret executors.py:27/75; Blackbird username.py:122;
MG15–17, MG23–25, SH14, CO01. Pomiary: benchmarks/results.json.
