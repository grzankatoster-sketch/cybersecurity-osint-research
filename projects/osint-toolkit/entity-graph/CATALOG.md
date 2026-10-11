# Katalog narzędzi: kategorie OSINT Framework a to repo

Źródło kategorii: osintframework.com (drzewo `arf.json`, stan z 2026-10-03, 33 gałęzie główne). Katalog mapuje kategorie na narzędzia, nie jest listą wszystkich serwisów z drzewa.

Legenda: **[EG]** zintegrowane w entity-graph, **[N]** dostępne w `..\narzedzia` (osobno, uruchamiane ręcznie), **[S]** siostrzane narzędzie z tego repo, **[ręcznie]** tylko link do własnego przeglądu, **[WYŁĄCZONE]** świadomie poza zakresem.

## Zintegrowane lub dostępne

| Kategoria OSINT Framework | Narzędzie | Status |
|---|---|---|
| Username / Username Search Engines | username-engine (WhatsMyName + Maigret, ~5800 serwisów) | [EG] `username_scan` |
| Username / Specific Sites | Maigret (`START_MAIGRET.cmd`) | [N] drugi silnik do porównania wyników |
| Email Address / Email Search, Common Email Formats | domena z adresu, generowanie kandydatów z nazwiska | [EG] `email_domain`, `person_candidates` |
| Email Address / Email Verification | Gravatar (istnienie awatara po skrócie adresu) | [EG] `email_gravatar` |
| Email Address / Breach Data | hibp-monitor + własny klucz HIBP | [EG] `email_hibp` (opcjonalnie, tylko z `HIBP_API_KEY`) |
| Email, Domain / adresy i hosty z wielu źródeł | theHarvester (`START_THEHARVESTER.cmd`) | [N] pasywnie na własnej domenie |
| Domain Name / Whois Records | RDAP (rejestrator, daty; bez danych rejestranta) | [EG] `domain_rdap` |
| Domain Name / Subdomains, Certificate Search | crt.sh (Certificate Transparency) | [EG] `domain_crtsh` |
| Domain Name / DNSSEC, PassiveDNS (rekordy własne) | dns-audit: A/AAAA/NS/MX/SPF/DMARC/DKIM/DNSSEC | [EG] `dns_audit` [S] |
| Domain Name / Discovery, Tools | dig (`START_DIG.cmd`), bbot, SpiderFoot | [N] bbot w trybie pasywnym `-rf passive`; SpiderFoot ma panel bez logowania, tylko 127.0.0.1 |
| IP & MAC Address / BGP | RIPEstat prefix-overview (ASN, prefiks) | [EG] `ip_asn` |
| IP & MAC Address / IPv4, IPv6 (rejestr) | RDAP (rdap.org, zapas RIPE): organizacja, kraj rejestru | [EG] `ip_rdap` |
| IP & MAC Address / Host / Port Discovery | Shodan InternetDB (dane z cudzych skanów, bez klucza) | [EG] `ip_internetdb` |
| IP & MAC Address / Neighbor Domains | reverse DNS (PTR), nazwy hostów z InternetDB | [EG] `ip_rdns` |
| Telephone Numbers / Phone Validator, International | phone-check (plan numeracji, offline) | [EG] `phone_metadata` [S] |
| Images / Videos / Docs, Metadata | ExifTool (`START_EXIFTOOL.cmd`), exif-map | [N] / [S] metadane plików, ręcznie |
| Search Engines | linki dorków do ręcznego otwarcia (Google, Bing, DuckDuckGo) | [EG] `person_candidates`, bez scrapowania |
| Archives | Wayback CDX w username-engine (`--wayback`) | [S] poza grafem, ręcznie |
| Documentation / Evidence Capture | raport HTML, GraphML, dziennik audytu | [EG] wbudowane |

## Świadomie wyłączone

| Kategoria / narzędzie | Powód |
|---|---|
| Telephone Numbers: True Caller, WhoCalld, SpyDialer, Reverse Genie, Whitepages, Numspy, Mr. Number, Hiya, Fone Finder, Sync.me, CallApp | Zamiana numeru na osobę. Brak oficjalnego API dla odbiorcy, dane z książek adresowych użytkowników, ToS i RODO. Patrz README. [WYŁĄCZONE] |
| Telephone Numbers: HLR Lookup, Twilio Lookup, Next Caller, Data24-7 | Odpytują operatora o stan i abonenta numeru. Płatne, bez zgody abonenta nie spełniają celu "metadane z planu numeracji". [WYŁĄCZONE] |
| IP & MAC Address / Geolocation, IP Loggers, Wireless Network Info | Geolokalizacja osoby z IP lub śledzenie ruchu; wychodzimy tylko z tego, co publicznie podaje RDAP/ASN. [WYŁĄCZONE] |
| IP / Port Discovery: aktywne skanowanie (Nmap, Masscan, Shodan z kluczem) | Nie skanujemy cudzych hostów. InternetDB to dane pasywne. Aktywnie tylko na własnej infrastrukturze, poza tym narzędziem. [WYŁĄCZONE] |
| Social Networks (Facebook, Instagram, X, LinkedIn, TikTok, Threads), People Search Engines | Scraping wymaga logowania, omijania blokad albo nieoficjalnych API. Zostają konta znalezione przez username-engine i linki do ręcznego przeglądu. [WYŁĄCZONE] |
| Dating, Instant Messaging (sprawdzanie kont po numerze/e-mailu) | Weryfikacja istnienia konta w komunikatorze po numerze to deanonimizacja bez podstawy. [WYŁĄCZONE] |
| Dark Web, Blockchain, Classifieds, Transportation, Geolocation Tools / Maps, Mobile OSINT | Poza zakresem due diligence i audytu infrastruktury; osobne metodyki i ryzyka. [poza zakresem] |
| Public Records, Business Records, Compliance & Risk | Dla Polski: KRS/CEIDG w osobnym `osint-poland` (tam jest zasada: brak wyszukiwania po osobie). Nie powielamy. [poza zakresem] |
| Email Search po osobie, hasła z wycieków (zrzuty baz) | Tylko oficjalne API HIBP i tylko własny klucz. Nie wyszukujemy po osobie ani nie pobieramy zrzutów. [WYŁĄCZONE] |
| Email Verification przez SMTP RCPT, rejestracje/reset hasła na cudzych serwisach | Zapytania do kont w serwisach (ignorant, holehe): sondowanie cudzych kont bez zgody. [WYŁĄCZONE] |
| Malicious File Analysis, Cyber Threat Intelligence, OpSec, Exploits | Inna dyscyplina (SOC/CTI), brak powiązania z grafem encji. [poza zakresem] |
| Tools / AI Tools, Language Translation, Encoding / Decoding, Training | Pomocnicze; nie są transformacjami encji. [poza zakresem] |

## Zasady doboru

1. Źródło oficjalne lub publiczne API bez omijania zabezpieczeń; bez logowania, CAPTCHA, proxy do obchodzenia blokad.
2. Każda transformacja zwraca FOUND / NOT_FOUND / UNKNOWN / ERROR; błąd sieci nie jest NOT_FOUND.
3. Frameworki z `..\narzedzia` (theHarvester, bbot, SpiderFoot) tylko na własnych domenach lub z pisemną zgodą właściciela (zasada naczelna z ich README).
4. Trafienie to trop, nie dowód: min. 2 niezależne korelacje, a pewność nie przekracza dowodu.
