# DNS Audit

Audytor DNS i konfiguracji poczty domeny. Realizuje sekcję 2 audytu (`../AUDYT_OSINT_NOTATKI_2026-10-03.md`): własny, prosty moduł na `dnspython`. Legalny i defensywny: czyta **wyłącznie publiczne rekordy DNS jawnej infrastruktury domeny**, nie osób. Używaj na domenach własnych, klientów (za zgodą) lub publicznych.

```bash
py -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m dns_audit example.com
.venv\Scripts\python -m pytest -q            # testy bez internetu
```

Najprościej: dwuklik `START_DNS_AUDIT.cmd` (tworzy `.venv` przy pierwszym uruchomieniu), potem `da domena [opcje]`.

## Użycie

```
python -m dns_audit domena [--json] [--selectors a,b] [--only-selectors] [--resolver 1.1.1.1] [--html plik] [--timeout 4] [--proxy URL | --direct] [--doh URL]
```

| Opcja | Znaczenie |
|---|---|
| `--json` | wynik jako JSON (dane + ustalenia + liczniki) zamiast tabeli |
| `--selectors a,b` | własne selektory DKIM, dodawane do ~25 domyślnych (`--only-selectors`: tylko własne) |
| `--resolver IP` | resolver IP (domyślnie systemowy). Do sprawdzenia DNSSEC użyj walidującego, np. `1.1.1.1` |
| `--html plik` | samodzielny raport HTML (jasny/ciemny motyw) |

Domenę można podać jako URL lub adres e-mail (zostanie wyciągnięta nazwa), IDN jest zamieniany na punycode.

## Tryb OPSEC (DoH przez Tor)

Zwykłe zapytania DNS widzi dostawca internetu (i resolver). W trybie OPSEC każde zapytanie idzie jako **DNS-over-HTTPS** (RFC 8484, `POST application/dns-message`) **przez proxy SOCKS5** (np. Tor), więc dostawca internetu nie widzi audytowanej domeny, a serwer DoH nie widzi Twojego IP.

```
python -m dns_audit example.com --proxy socks5h://127.0.0.1:9150 [--doh https://cloudflare-dns.com/dns-query]
set OSINT_PROXY=socks5h://127.0.0.1:9150     # domyślny --proxy (np. ustawiany przez panel)
python -m dns_audit example.com --direct     # zapytania bezpośrednie mimo OSINT_PROXY
```

- Tylko `socks5://` / `socks5h://` (`host:port`, opcjonalnie `user:haslo@`). Nazwa hosta DoH jest przekazywana proxy jako domena (ATYP=3): nic nie jest rozwiązywane lokalnie. Zwykły DNS nie przejdzie przez Tor, więc `--resolver` razem z proxy daje błąd (kod 2); `--proxy` i `--direct` wykluczają się.
- Bez danych logowania losowany jest login (jeden na uruchomienie), dzięki czemu Tor izoluje obwód audytu od reszty ruchu.
- Przed audytem idzie jedno zapytanie kontrolne (`example.com A`). Gdy proxy/DoH nie działa: komunikat, **kod wyjścia 3 i zero zapytań bezpośrednich** (brak cichego powrotu do zwykłego DNS).
- Na stderr: `Kanał: DoH przez proxy ...` albo `Kanał: bezpośrednio (...)`. Linia `Resolver:` w raporcie pokazuje serwer DoH i proxy, bez danych logowania.
- Bez `--proxy` i bez `OSINT_PROXY` zachowanie jest jak dotąd (zwykły resolver).
- Wolniej niż zwykły DNS: timeout zapytania to min. 10 s. Implementacja: tylko stdlib (`socket`/`ssl`/`http.client`) + dnspython, bez nowych zależności; klasa `DohResolver` w `resolver.py`. Testy (`tests/test_doh.py`) używają lokalnych stubów SOCKS5 i DoH po TLS (certyfikat tworzy `openssl`; bez niego testy TLS są pomijane).

## Co zbiera
A/AAAA, NS, SOA, MX (z rozpoznaniem dostawcy poczty i kontrolą, czy hosty MX się rozwiązują), TXT, CAA, SPF (parsowanie mechanizmów, rekurencyjne liczenie lookupów vs limit 10, kwalifikator `all`), DMARC (`p`/`sp`/`pct`/`rua`), DKIM (lista popularnych selektorów, długość klucza RSA), DNSSEC (DNSKEY/DS, flaga AD, algorytmy), MTA-STS (`_mta-sts`), TLS-RPT (`_smtp._tls`), BIMI (`default._bimi`) oraz rekordy weryfikacyjne w TXT (Google, Microsoft 365, Meta, Atlassian, Apple, DocuSign, Stripe, Zoom, OpenAI, Anthropic i kilkadziesiąt innych) z nazwą usługi.

## Ocena
Każde ustalenie ma wagę **OK / INFO / WARN / FAIL**, obszar i zalecenie po polsku. Przykłady: brak DMARC (FAIL dla domeny z pocztą, WARN dla bez poczty), `p=none` (WARN), SPF >10 lookupów (FAIL), `+all` (FAIL), `?all` (WARN), `~all` (INFO), brak DNSSEC (WARN), DKIM RSA 1024 (WARN), host MX bez adresu (FAIL), brak MTA-STS/TLS-RPT/CAA (INFO). Domena z jawnym null MX (RFC 7505) jest traktowana jako domena bez poczty: pomijane są DKIM, MTA-STS, TLS-RPT i BIMI.

Błąd zapytania (timeout, SERVFAIL) **nigdy** nie jest raportowany jako „brak rekordu”: daje INFO „nie udało się sprawdzić”.

## Struktura
- `src/dns_audit/resolver.py`: interfejs `Resolver` (+ `DnsPythonResolver`, `DohResolver`: DoH przez SOCKS5, `preflight`); testy używają `FakeResolver` z `tests/conftest.py`
- `collector.py` (zapytania, równolegle) → `analyze.py` (ustalenia) → `report.py` (tekst / JSON / HTML)
- `spf.py`, `dmarc.py`, `dkim.py`, `verification.py`: czyste parsery bez sieci

## Znane ograniczenia
- **DKIM**: selektory są dowolne; nieznalezienie na liście nie dowodzi braku DKIM (INFO, podaj własny `--selectors`). Wildcard `*._domainkey` jest wykrywany losowym selektorem kontrolnym; przy wildcardzie oceniane są selektory podane jawnie oraz te, których odpowiedź różni się od wildcard (pozostałe są pomijane jako niewiarygodne). Częściowe błędy zapytań i nieudana kontrola wildcard dają INFO „niepełne sprawdzenie”. OK dostaje tylko klucz bez błędów, znanego typu (rsa z poprawnym DER, ed25519 dokładnie 32 bajty); powtórzony tag, nieznany typ lub błąd to WARN. Długość klucza RSA czytamy własnym parserem DER (z wymaganym wykładnikiem), bez pełnej walidacji kryptograficznej.
- **DNSSEC / flaga AD**: zależy od resolvera. Resolver niewalidujący (np. router) nie zwróci AD; wtedy raport mówi, że walidacji nie potwierdzono. AD liczy się wyłącznie z odpowiedzi strefy (DNSKEY/SOA), nie z samego DS. Błąd jednego z zapytań (DNSKEY albo DS) daje INFO „nie udało się sprawdzić”, nigdy FAIL. Pełnej walidacji łańcucha zaufania nie wykonujemy sami.
- **Poczta a MX**: DKIM, MTA-STS, TLS-RPT i BIMI są pomijane wyłącznie przy jawnym null MX (`0 .`); brak MX lub błąd zapytania o MX ich nie wyłącza (waga braku SPF/DMARC nadal zależy od obecności MX).
- **MTA-STS / TLS-RPT**: sprawdzany jest tylko rekord TXT (dokładna wersja `v=STSv1;` / `v=TLSRPTv1;`, wiele rekordów to WARN), nie plik polityki po HTTPS. Nie sprawdzamy też certyfikatów SMTP ani realnej polityki TLS-RPT.
- **SPF**: lookupy `a`/`mx`/`exists` liczone jako 1 (bez rozwijania hostów MX i „void lookups”); makra są pomijane. Liczenie kończy się na pierwszym `all` (RFC 7208 5.1). Każda domena jest rozwijana raz, a globalny budżet to 50 rozwinięć include/redirect: po jego przekroczeniu analiza kończy się jawnym błędem „przekroczono budżet analizy” (liczba lookupów jest wtedy dolnym ograniczeniem). Składnia `ip4`/`ip6`/CIDR i prefiksów `a`/`mx` jest walidowana, a błędy rekordów z include/redirect propagowane z nazwą domeny.
- **DMARC**: odczyt tylko na `_dmarc.<domena>`; dla subdomeny nie szukamy rekordu domeny organizacyjnej (brak Public Suffix List), więc brak rekordu jest raportowany z zastrzeżeniem, że polityka może być dziedziczona. Nie weryfikujemy autoryzacji zewnętrznych adresów `rua`.
- **CAA**: tylko lokalna nazwa domeny (bez wspinania się po drzewie i bez CNAME); brak rekordu to „brak lokalnego rekordu CAA (może dziedziczyć z domeny nadrzędnej)”. `issue` i `issuewild` są oceniane osobno.
- **Raport**: status „nie udało się sprawdzić” jest zachowany w podsumowaniu (osobno od „nie znaleziono”). W trybie tekstowym znaki sterujące z niezaufanych rekordów (np. ESC) są zamieniane na widoczne `\xNN`. Zapis `--html` jest atomowy (plik tymczasowy + `os.replace`); jego błąd daje komunikat na stderr, kod wyjścia 1 i nadal pełny raport na stdout. `--timeout` musi być skończony i większy od 0.
- Reguły rozpoznawania usług weryfikacyjnych to lista prefiksów; nierozpoznane TXT są wypisane jako „Inne TXT”.
