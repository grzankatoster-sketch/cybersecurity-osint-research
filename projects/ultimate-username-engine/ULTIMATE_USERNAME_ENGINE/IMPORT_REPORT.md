# Import definicji — lokalne snapshoty

Nie wykonano zapytań do platform. IMPORTED oznacza poprawną konwersję offline, nie potwierdzoną skuteczność online.

| Donor | Wszystkie | Imported | Invalid | Unsupported | Disabled w imported |
|---|---:|---:|---:|---:|---:|
| maigret | 7922 | 7814 | 64 | 44 | 683 |
| sherlock | 481 | 455 | 26 | 0 | 0 |
| whatsmyname | 717 | 687 | 30 | 0 | 1 |

Konflikty: **756 grup**; warianty zachowano bez automatycznego scalania. Grupy po nazwie i szablonie mogą częściowo się nakładać.

Odrzucone z wykonywalnego katalogu = INVALID + UNSUPPORTED. Pełne rekordy, surowe dane i mapa każdego pola: `data/import-records.json`.

Blackbird: 17 reguł metadanych; {'IMPORTED': 17}. Nie przypisano automatycznie do platform bez weryfikacji kontekstu profilu.

Historyczne reguły nie otrzymują wymyślonego profile binding ani kalibracji. Pozytywny sygnał daje najwyżej PROBABLE; błędy/blokady zawsze UNKNOWN. Puste markery pominięto z jawną diagnostyką. Nieobsługiwane protokoły, aktywacje, placeholdery hosta i niejednoznaczne konflikty silników trafiają do kwarantanny. `ignore403` jest zachowane jako metadana; gate nadal odrzuca 403.

## Integralność wejścia

- maigret: SHA-256 `fd0902ca6b4be44bd13ca459156a73440580ca829588e1e5bae7255c039f7167`
- sherlock: SHA-256 `3fdfc6694c5cd99798881215554b09e617c6d5284a6219fae309882566a9fb30`
- whatsmyname: SHA-256 `507d2f8aa5b1297ae2d713634ccc7ce08357fed85b1d40130585810f456c1cfe`
