# Model pól analitycznych

Implementacja: `field_model.py`, `domain/metadata.py`, `enrichment.py`, `presentation.py`.

Klasyfikacja przydatności **HIGH / MEDIUM / LOW / TECHNICAL** jest odrębna od
`EvidenceQuality` oraz confidence detektora. HIGH nie znaczy, że informacja dowodzi
tożsamości osoby lub że ma określone prawdopodobieństwo poprawności.

| Grupa | Pola w modelu / widoku analityka | Przydatność |
|---|---|---|
| IDENTITY | username, display_name, user_id → account_id, profile_url | HIGH |
| CORRELATION | website, external_links → external_urls, linked_accounts, twitter_username, github_username, email, node_id, same_username_references | Zależnie od pola HIGH/MEDIUM |
| PROFILE_CONTEXT | bio, description, location, company, account_type, category, tags | location HIGH; pozostałe MEDIUM |
| ACCOUNT_INFO | created_at, updated_at, latest_activity_at, verified, is_looking_for_job, joined_text | MEDIUM |
| PUBLIC_ACTIVITY | followers, following, posts, public_repos_count, public_gists_count, xenforo_points | MEDIUM |
| MEDIA | avatar_url, banner_url | avatar HIGH; banner MEDIUM |
| TECHNICAL | Niesklasyfikowane rozszerzenia, telemetria żądań i identyfikatory wykonania | TECHNICAL |

Avatar jest przypisany do MEDIA, by nie dublować tej samej wartości w IDENTITY.
Rozpoznane techniczne URL-e API nie zastępują ludzkiego profile_url. `node_id` jest
publicznym identyfikatorem konta GitHuba; `job_id` i `task_id` są identyfikatorami
naszego wykonania i pozostają diagnostyką.

Nie wszystkie nazwy z klasyfikacji mają ekstraktor dla każdej platformy.
`linked_accounts` i `same_username_references` nie są generowane przez zgadywanie.
Odczytany twitter_username/github_username jest deklaracją widoczną na profilu,
nie potwierdzeniem istnienia ani własności zewnętrznego konta. Nie wykonuje dodatkowego GET.

## Wartości i ich pochodzenie

- Każda niepusta obserwacja zachowuje źródło, extractor, locator, czas oraz jakość dowodu.
- ID konta jest przechowywane jako tekst, by nie mylić go z licznikiem.
- `0` i `false` pozostają odrębne od null i braku pola.
- Jawne null jest zapisane w `coverage.null_fields`, a widok analityka pokazuje null.
  Nie jest liczone jako użyteczna wartość. Brak klucza nie tworzy pola null.
- Daty ISO są walidowane bez dopisywania strefy czasu. Tekst `joined_at` z DEV jest
  zachowany jako `joined_text`, bez udawania precyzyjnego znacznika czasu.
- Email pochodzi wyłącznie z odpowiedzi powiązanego publicznego profilu; prosta kontrola
  formatu nie potwierdza istnienia skrzynki. Nie odpytuje się poczty ani login endpointów.
- Sprzeczne wartości pozostają w pełnych kandydatach DEBUG; pole konfliktowe jest
  pomijane w domyślnych użytecznych wartościach i zgłaszane w issues.

## Coverage i powody odrzucenia

| Pole diagnostyczne | Znaczenie |
|---|---|
| available_fields | Rozpoznane nazwy pól zaobserwowane w analizowanym obiekcie; nie lista wszystkich możliwości serwisu |
| extracted_fields | Nazwy wybranych niepustych wartości po normalizacji |
| rejected_fields | Np. niewłaściwy właściciel, sprzeczny profil URL, rozpoznana wartość ogólna |
| invalid_fields | Np. ujemny licznik, niepoprawna data, email o nieobsługiwanym formacie |
| null_fields | Jawnie odnotowane null, bez dopisywania wartości |
| missing_fields | Rozpoznane dostępne pola, których nie pokrywa ekstrakcja, null lub wskazane odrzucenie |

Różne wystąpienia/aliasy tego samego pola mogą mieć różne wyniki walidacji. Kategorie
coverage nie muszą być rozłączną partycją nazw. Pełni kandydaci i locatory wyjaśniają
rozbieżności. Coverage nie twierdzi, że każdy nieobsługiwany klucz JSON jest znany.

## Filtrowanie danych bezwartościowych

Najpierw obowiązuje powiązanie z właścicielem i bramki HTTP/login/challenge.
Niepowiązany OpenGraph nie staje się danymi osoby. Dodatkowo mała jawna lista odrzuca
ogólne tytuły typu Login/Access denied, samą nazwę serwisu, znany opis Twitcha,
„Accept all cookies” oraz rozpoznane nazwy plików domyślnego avatara.

To ostrożne reguły, nie uniwersalny klasyfikator wszystkich cookie bannerów i obrazów.
Nieznany avatar nigdy nie jest samodzielnym, unikalnym dowodem tożsamości. Nie pobiera
się obrazów w celu oceny, czy są domyślne. LOW pozostaje kategorią dla przyszłych
słabych obserwacji; ogólnych tytułów nie promuje się do użytecznych danych tylko po
to, aby zwiększyć liczbę pól.
