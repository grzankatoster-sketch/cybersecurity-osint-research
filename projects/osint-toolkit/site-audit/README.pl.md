# Site Audit

Audytor jawnej konfiguracji strony WWW. Realizuje pozycję 3.1 audytu `../AUDYT_NARZEDZI_GITHUB_2026-10-03.md`: własna wersja [web-check](https://github.com/lissy93/web-check) w czystej bibliotece standardowej Pythona, bez jego słabości. Uzupełnia `dns-audit`: tam DNS i poczta, tu HTTP, TLS i pliki strony.

**Ruch do celu** to kilka zwykłych żądań GET, jak przy otwarciu strony: bez skanowania portów, bez JavaScriptu, bez wysyłania formularzy. Domyślnie najwyżej 8 żądań. Używaj na stronach własnych lub za zgodą.

```bash
py -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"     # zero zależności uruchomieniowych
.venv\Scripts\python -m site_audit example.com
.venv\Scripts\python -m pytest -q                   # testy bez internetu (lokalny serwer 127.0.0.1)
```

Najprościej: dwuklik `START_SITE_AUDIT.cmd`, potem `sa adres [opcje]`.

## Użycie

```
python -m site_audit adres [--json] [--html plik] [--timeout 8] [--budget 60] [--max-bytes 2000000] [--no-extra] [--allow-private]
```

| Opcja | Znaczenie |
|---|---|
| `--json` | wynik jako JSON (dane, ustalenia, liczniki) zamiast tabeli |
| `--html plik` | samodzielny raport HTML (jasny i ciemny motyw, własne CSP `default-src 'none'`) |
| `--timeout` | limit pojedynczej operacji sieciowej (s) |
| `--budget` | **łączny** limit czasu całego audytu (s); każda operacja dostaje min(timeout, pozostały budżet) |
| `--max-bytes` | limit treści na żądanie; większa treść jest przycinana i oznaczana |
| `--no-extra` | tylko strona główna: bez robots.txt, security.txt i sitemap |
| `--allow-private` | zezwala na adresy prywatne i lokalne (audyt własnej sieci) |

Adres bez schematu dostaje `https://`. IDN jest zamieniany na punycode. Adresy z `user:hasło@` są odrzucane.

Kody wyjścia: `0` audyt wykonany, `1` błąd zapisu HTML, `2` błędne argumenty, `3` strona niedostępna albo zablokowana.

## Co sprawdza

| Obszar | Zakres |
|---|---|
| Przekierowania | pełny łańcuch (max 10), pętle, downgrade HTTPS→HTTP, sonda `http://` → czy przekierowuje na `https://` tego samego hosta |
| TLS | weryfikacja certyfikatu (zły certyfikat to FAIL, a nagłówki i tak są odczytywane), ważność (FAIL < 14 dni, WARN < 30), wynegocjowana wersja i szyfr |
| HSTS | parser RFC 6797: max-age (0, krótkie, brak), includeSubDomains, preload i jego wymagania, duplikaty |
| CSP | parser CSP3 (pierwsza dyrektywa wygrywa): `'unsafe-inline'` bez nonce/hash, `'unsafe-eval'`, szerokie źródła (`*`, `https:`, `data:`), `object-src`, `base-uri`, Report-Only |
| Nagłówki | clickjacking (frame-ancestors / X-Frame-Options), nosniff, Referrer-Policy, Permissions-Policy, wersje w `Server`/`X-Powered-By`, CORS `*` + credentials |
| Ciasteczka | Secure, HttpOnly, SameSite, `SameSite=None` bez Secure, prefiksy `__Host-`/`__Secure-` |
| Treść HTML | mieszana treść aktywna i pasywna, formularze na `http://`, zewnętrzne skrypty bez SRI, `meta generator` z wersją |
| security.txt | RFC 9116: `/.well-known/` (i zapasowa lokalizacja), wymagane Contact i Expires, data RFC 3339 ze strefą, wygaśnięcie, termin > 1 rok, `text/plain`, HTTPS, podpis PGP rozpoznawany (nie weryfikowany), miękkie 404 |
| robots.txt | grupy, reguły Disallow, sitemapy, blokada wszystkiego, ścieżki wskazujące wrażliwe zasoby |
| Sitemap | z robots.txt (tylko ten sam host) albo `/sitemap.xml`; liczba adresów lub indeks; odmowa parsowania `DOCTYPE`/`ENTITY` |

Wagi: **OK / INFO / WARN / FAIL**, z zaleceniem po polsku. Błąd pobrania (timeout, zerwane połączenie, budżet) **nigdy** nie jest raportowany jako „brak”. Daje INFO „nie udało się sprawdzić”.

## Bezpieczeństwo klienta (wnioski z kodu web-check)

- **SSRF:** każda nazwa jest rozwiązywana, a cel odrzucany, jeśli **którykolwiek** adres jest niepubliczny (prywatne, loopback, link-local, w tym `169.254.169.254`, CGNAT, zarezerwowane). IPv4 osadzony w IPv6 (IPv4-mapped, NAT64 `64:ff9b::/96` i `64:ff9b:1::/48`, 6to4, Teredo) jest oceniany osobno. Dotyczy **każdego skoku przekierowania**. Połączenie idzie na sprawdzony adres bez drugiej rezolucji, co chroni przed DNS rebinding. Testy: `tests/test_fetch.py`, `tests/test_regressions.py`.
- **Czas:** jeden budżet na cały audyt, egzekwowany twardo. Rezolucja DNS idzie w wątku z limitem, a watchdog zamyka gniazdo z chwilą wyczerpania budżetu, także w trakcie nagłówków, ramek chunked i trailerów. Treść czytana przez `read1()`. Serwer wysyłający po kilka bajtów nie przetrzyma więc klienta ponad budżet. web-check ma tu `Promise.race` bez anulowania.
- **Rozmiar:** limit bajtów na żądanie, `Accept-Encoding: identity` (bez bomb kompresji). Liczba i długość nagłówków ograniczona przez `http.client`.
- **Pliki pomocnicze** (robots, security.txt, sitemap) tylko z hosta końcowego. Zakres jest sprawdzany **przed** każdym żądaniem i skokiem, więc obcy host ani port nie dostaje żadnego żądania.
- **XML** sitemap parsowany strumieniowo przez expat. DTD i deklaracje encji są odrzucane w parserze niezależnie od kodowania (także UTF-16).
- **Wrogie odpowiedzi** nie wywracają audytu: nietypowe cyfry w HSTS, `charset` wskazujący dziwny kodek, zepsuty `Location`, zły adres w HTML. Przerwana analiza HTML jest oznaczana w raporcie.
- **Wyjście:** znaki sterujące i sterujące kierunkiem tekstu (bidi) są neutralizowane w terminalu i HTML. Raport HTML ma ucieczkę znaków i własne CSP.
- **Błąd certyfikatu na skoku przekierowania** jest zapisywany i raportowany (FAIL), nie tylko na stronie końcowej.

Przegląd bezpieczeństwa: Codex 2026-10-03, 16 ustaleń. 15 przyjętych i pokrytych testami regresji. Odrzucone: maskowanie parametrów zapytania w raporcie (LOW), bo audytuje się własną stronę, a raport jest dla jej właściciela. Jeśli raport ma wyjść na zewnątrz, adresy z tokenami usuń ręcznie.

## Ograniczenia

- Wersja TLS to ta **wynegocjowana** z Pythonem (minimum TLS 1.2). Obsługę starych wersji sprawdzi `testssl.sh` na własnym hoście.
- Bez wykonywania JavaScriptu: ciasteczka ustawiane skryptem, trackery i technologie (Wappalyzer) są poza zakresem.
- „Zewnętrzny skrypt” to host spoza audytowanej domeny i jej subdomen. Bez listy PSL CDN tej samej firmy pod inną domeną (np. `githubassets.com`) też trafia do INFO.
- Podpis PGP w security.txt nie jest weryfikowany.

## Struktura

- `target.py`: normalizacja adresu, straż adresów (SSRF)
- `fetch.py`: klient HTTP(S) z połączeniem na sprawdzony IP, ręcznymi przekierowaniami, budżetem i limitem
- `collector.py`: strona, sonda HTTP, robots.txt, security.txt, sitemap → `analyze.py` (ustalenia) → `report.py` (tekst / JSON / HTML)
- `parsers.py`: czyste parsery bez sieci (HSTS, CSP, Set-Cookie, security.txt, robots, sitemap, HTML)
