# ANALYST i DEBUG

Domyślne ustawienia CLI: **`--view analyst --enrich basic --selection quality`**.

## Codzienne użycie

```powershell
Set-Location 'C:\folder\przyklad\ULTIMATE_USERNAME_ENGINE'
.\.venv\Scripts\python.exe -m ultimate_username search JanKowalski `
  --registry data\catalog.json --request-budget 20 --job-timeout 120 `
  --only-matches --output results\JanKowalski.json
```

Najważniejszy do przeglądania plik: **`results\JanKowalski.analyst.json`**.
Pełny eksport pozostaje w `results\JanKowalski.json`. Plan wyboru z punktacją,
alternatywami i wykluczeniami zapisuje się w `results\JanKowalski.selection.json`.
Konsola wskazuje ścieżki. Dla wielu nicków pliki analityczne otrzymują osobny sufiks
zadania, żeby wyniki się nie nadpisywały.

Szybki test pojedynczego GitHuba, także z wielkimi literami:

```powershell
.\.venv\Scripts\python.exe -m ultimate_username search JanKowalski `
  --registry data\catalog.json --site maigret:f911e414cf6bdfc5 `
  --request-budget 2 --output results\github_check.json
```

## Co widzi analityk

- Nazwę serwisu, status, tested, username i profil URL.
- Użyteczne wartości w grupach IDENTITY, CORRELATION, PROFILE_CONTEXT,
  ACCOUNT_INFO, PUBLIC_ACTIVITY i MEDIA.
- Stan metadanych, skrót dowodów i znaczące problemy.
- Podsumowanie zakresu, prób, wyników, blokad i niesprawdzonych pozycji.

Przykładowo GitHub może pokazać FOUND, login `jankowalski`, account_id, profil,
avatar, witrynę, liczniki i daty, z dowodem: „Structured GitHub profile: username,
account ID and profile URL matched”. Liczba pól wynika z dostępnej odpowiedzi.
Nie dopisujemy nazwy ani lokalizacji, jeśli API zwróciło null.

Confidence zachowuje siłę dowodu i null zamiast niekalibrowanego procentu.
`profile_metadata` jest niezależne od werdyktu; PROBABLE/SUCCESS pozostaje poprawne.

## NOT_TESTED i filtry

`attempts=[]` oznacza NOT_TESTED w prezentacji, z osobno zachowanym technicznym
powodem. Tysiące takich placeholderów są agregowane w summary, a nie drukowane
jako pozorne odpowiedzi sieciowe. Jeżeli choć jedna próba wystąpiła, późniejsze
wyczerpanie budżetu nie zmienia jej w NOT_TESTED.

`--only-matches` ogranicza listę profili w widoku analityka do FOUND i PROBABLE.
Nie filtruje pliku pełnego ani journal, a summary nadal obejmuje wszystkie wyniki.
Nie wdrożono niejednoznacznego automatycznego pokazywania UNKNOWN jako trafienia.

## DEBUG i zgodność wsteczna

```powershell
.\.venv\Scripts\python.exe -m ultimate_username search JanKowalski `
  --registry data\catalog.json --site maigret:f911e414cf6bdfc5 `
  --view debug --output results\github_debug.json
```

DEBUG pokazuje plan oraz pełne rekordy, w tym job_id, task_id, attempts, czasy,
body_sha256, rewizję, backend, raw evidence, coverage, diagnostykę parserów i historię
żądań. Te informacje nadal istnieją w pełnym modelu i SQLite.

Zachowano format eksportu `--output` i API odczytu starych JSON-ów. Nowe pola
diagnostyczne mają wartości domyślne. Dzięki temu wcześniejsze integracje i testy
nie tracą danych. `--output -` jest jawnym eksportem maszynowym do stdout: nadal
wypisuje kompletny format JSON/NDJSON/CSV. Widok analityczny i komunikaty idą do
stderr, więc stdout pozostaje parsowalny. Zwykłe użycie z plikiem nie drukuje
pełnego debug JSON w domyślnym widoku.

Pełny JSON zawiera całą diagnostykę, CSV zachowuje dotychczasowy skrócony kontrakt,
a journal pozostaje kompletnym zapisem. Osobny JSON analityczny jest generowany
również przy eksporcie CSV. Wartości z profili są kodowane jako JSON, więc znaki
sterujące nie mogą bezpośrednio wstrzykiwać sekwencji terminala.
