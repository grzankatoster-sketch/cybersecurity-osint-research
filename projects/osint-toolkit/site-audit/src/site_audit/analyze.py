"""Ustalenia z zebranych danych. Blad pobrania nigdy nie jest raportowany jako "brak"."""

from __future__ import annotations

import ssl
from datetime import datetime, timedelta, timezone

from .collector import SiteData
from .fetch import REDIRECT_CODES, FetchResult, Response
from .models import Finding, Severity
from .parsers import (
    csp_issues, cookie_issues, discloses_version, frame_ancestors_open, parse_csp, parse_hsts,
    parse_page, parse_robots, parse_security_txt, parse_set_cookie, parse_sitemap,
)
from .target import TargetError, parse_target

HSTS_MIN_RECOMMENDED = 15_552_000   # 180 dni
HSTS_PRELOAD_MIN = 31_536_000       # 1 rok
CERT_WARN_DAYS = 30
CERT_FAIL_DAYS = 14
SENSITIVE_ROBOTS = ("admin", "backup", "bak", ".git", ".env", "config", "debug", "phpmyadmin",
                    "wp-admin", "private", "secret", "test", "staging", "old", "dump", "sql")

_UNAVAILABLE = ("timeout", "network", "budget", "tls", "redirects", "offhost")


def _f(area: str, sev: Severity, title: str, rec: str = "") -> Finding:
    return Finding(area, sev, title, rec)


def analyze(d: SiteData, now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    out: list[Finding] = []
    resp = d.main.response
    if resp is None:
        if d.main.error_kind == "blocked":
            out.append(_f("Cel", Severity.FAIL, f"Cel zablokowany: {d.main.error}",
                          "Audyt adresów prywatnych/lokalnych tylko świadomie, z --allow-private."))
        else:
            out.append(_f("Cel", Severity.INFO, f"Nie udało się sprawdzić strony: {d.main.error}",
                          "Sprawdź adres i dostępność; spróbuj z większym --timeout."))
        return out

    final_https = resp.url.startswith("https://")
    out += _status(d.main, resp)
    out += _redirects(d, final_https)
    if final_https:
        out += _tls(resp, now)
        out += _hsts(resp)
    out += _headers(resp)
    out += _cookies(resp, final_https)
    out += _content(resp, final_https)
    out += _security_txt(d.security_txt, final_https, now)
    out += _robots(d.robots)
    out += _sitemap(d.sitemap)
    for note in d.notes:
        out.append(_f("Zakres", Severity.INFO, note))
    return out


# ------------------------------------------------------------------ elementy


def _status(main: FetchResult, resp: Response) -> list[Finding]:
    out = []
    hops = len(main.chain) - 1
    if resp.status >= 500:
        out.append(_f("Odpowiedź", Severity.WARN, f"Strona zwraca błąd serwera {resp.status} {resp.reason}"))
    elif resp.status >= 400:
        out.append(_f("Odpowiedź", Severity.WARN, f"Strona zwraca {resp.status} {resp.reason}",
                      "Ustalenia o nagłówkach dotyczą strony błędu, nie właściwej treści."))
    else:
        out.append(_f("Odpowiedź", Severity.OK, f"{resp.status} {resp.reason}, {hops} przekierowań, adres końcowy {resp.url}"))
    if hops > 3:
        out.append(_f("Odpowiedź", Severity.INFO, f"Długi łańcuch przekierowań ({hops})", "Skróć do 1–2 skoków."))
    if resp.truncated:
        out.append(_f("Odpowiedź", Severity.INFO, "Treść niepełna (limit --max-bytes albo zerwane połączenie); analiza HTML częściowa"))
    return out


def _redirects(d: SiteData, final_https: bool) -> list[Finding]:
    out = []
    if not final_https:
        out.append(_f("HTTPS", Severity.FAIL, "Strona końcowa działa bez HTTPS",
                      "Włącz HTTPS i przekieruj cały ruch HTTP na HTTPS."))
    for hop in d.main.chain[:-1]:
        if hop.tls_error:
            out.append(_f("TLS", Severity.FAIL, f"Certyfikat na skoku przekierowania {hop.url} nie przechodzi weryfikacji: {hop.tls_error}",
                          "Przekierowanie z niezaufanego połączenia mogło zostać podmienione; popraw certyfikat tego hosta."))
        if hop.url.startswith("https://") and (hop.location or "").lower().startswith("http://"):
            out.append(_f("HTTPS", Severity.FAIL, f"Przekierowanie z HTTPS na HTTP ({hop.url} → {hop.location})"))
    probe = d.http_probe
    if probe is None:
        return out
    r = probe.response
    if r is None:
        if probe.error_kind == "network":
            out.append(_f("HTTPS", Severity.INFO, f"HTTP (port 80) nie przyjmuje połączeń: {probe.error}"))
        elif probe.error_kind in _UNAVAILABLE:
            out.append(_f("HTTPS", Severity.INFO, f"Nie rozstrzygnięto, czy działa HTTP (port 80): {probe.error}"))
        return out
    loc = (r.header("location") or "").strip()
    if r.status in REDIRECT_CODES and loc.lower().startswith("https://"):
        try:
            same = parse_target(loc).host == d.target.host
        except TargetError:
            same = False
        if same:
            out.append(_f("HTTPS", Severity.OK, f"http:// przekierowuje na https:// ({r.status})"))
        else:
            out.append(_f("HTTPS", Severity.INFO, f"http:// przekierowuje na HTTPS innego hosta ({loc})",
                          "Dla HSTS najpierw przekieruj na https:// tego samego hosta."))
    elif r.status in REDIRECT_CODES:
        out.append(_f("HTTPS", Severity.WARN, f"http:// przekierowuje, ale nie na HTTPS ({loc or 'brak Location'})"))
    else:
        out.append(_f("HTTPS", Severity.WARN, f"http:// odpowiada {r.status} bez przekierowania na HTTPS",
                      "Dodaj przekierowanie 301/308 z HTTP na HTTPS."))
    return out


def _tls(resp: Response, now: datetime) -> list[Finding]:
    out = []
    tls = resp.tls
    if tls is None:
        return out
    if tls.verify_error:
        out.append(_f("TLS", Severity.FAIL, f"Certyfikat nie przechodzi weryfikacji: {tls.verify_error}",
                      "Użyj certyfikatu zaufanego CA, pasującego do nazwy, z pełnym łańcuchem pośrednim."))
    if tls.version in ("TLSv1", "TLSv1.1", "SSLv3"):
        out.append(_f("TLS", Severity.FAIL, f"Wynegocjowano przestarzały {tls.version}"))
    elif tls.version:
        out.append(_f("TLS", Severity.OK, f"{tls.version}, szyfr {tls.cipher}",
                      "To wersja wynegocjowana z tym klientem; starsze wersje sprawdzi np. testssl.sh na własnym hoście."))
    cert = tls.cert
    if cert and cert.get("notAfter"):
        try:
            not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
        except ValueError:
            not_after = None
        if not_after is not None:
            days = (not_after - now) / timedelta(days=1)
            label = f"Certyfikat ważny do {not_after:%Y-%m-%d} ({int(days)} dni)"
            if days < 0:
                out.append(_f("TLS", Severity.FAIL, f"Certyfikat wygasł {not_after:%Y-%m-%d}"))
            elif days < CERT_FAIL_DAYS:
                out.append(_f("TLS", Severity.FAIL, label, "Odnów certyfikat natychmiast; sprawdź automat odnawiania."))
            elif days < CERT_WARN_DAYS:
                out.append(_f("TLS", Severity.WARN, label, "Sprawdź, czy automat odnawiania (ACME) działa."))
            else:
                out.append(_f("TLS", Severity.OK, label))
    return out


def _hsts(resp: Response) -> list[Finding]:
    values = resp.header_all("strict-transport-security")
    if not values:
        return [_f("HSTS", Severity.WARN, "Brak nagłówka Strict-Transport-Security",
                   "Dodaj np. 'max-age=31536000; includeSubDomains' po sprawdzeniu, że wszystkie subdomeny mają HTTPS.")]
    out = []
    if len(values) > 1:
        out.append(_f("HSTS", Severity.INFO, f"{len(values)} nagłówki HSTS: przeglądarka użyje pierwszego"))
    h = parse_hsts(values[0])
    for e in h.errors:
        out.append(_f("HSTS", Severity.WARN, f"HSTS: {e}"))
    if h.max_age == 0:
        out.append(_f("HSTS", Severity.WARN, "HSTS max-age=0 wyłącza ochronę"))
    elif h.max_age is not None and h.max_age < HSTS_MIN_RECOMMENDED:
        out.append(_f("HSTS", Severity.INFO, f"Krótkie HSTS max-age={h.max_age} s",
                      "Zalecane co najmniej 15552000 (180 dni), docelowo 31536000."))
    elif h.max_age is not None:
        sub = ", includeSubDomains" if h.include_subdomains else ""
        out.append(_f("HSTS", Severity.OK, f"HSTS max-age={h.max_age}{sub}{', preload' if h.preload else ''}"))
    if h.preload and not (h.include_subdomains and (h.max_age or 0) >= HSTS_PRELOAD_MIN):
        out.append(_f("HSTS", Severity.INFO, "Dyrektywa preload bez wymagań listy preload",
                      "Lista hstspreload.org wymaga max-age ≥ 31536000 i includeSubDomains."))
    return out


def _headers(resp: Response) -> list[Finding]:
    out = []
    csp_values = resp.header_all("content-security-policy")
    policy: dict = {}
    if csp_values:
        policy = parse_csp(csp_values[0])
        issues = csp_issues(policy)
        if not issues:
            out.append(_f("CSP", Severity.OK, "Content-Security-Policy bez typowych słabości"))
        for i in issues:
            sev = Severity.INFO if i.startswith(("object-src", "brak base-uri")) else Severity.WARN
            out.append(_f("CSP", sev, f"CSP: {i}"))
        if len(csp_values) > 1:
            out.append(_f("CSP", Severity.INFO, f"{len(csp_values)} polityki CSP: obowiązują wszystkie naraz, oceniono pierwszą"))
    elif resp.header("content-security-policy-report-only"):
        out.append(_f("CSP", Severity.INFO, "CSP tylko w trybie Report-Only (nie blokuje)",
                      "Po zebraniu raportów przenieś politykę do Content-Security-Policy."))
    else:
        out.append(_f("CSP", Severity.WARN, "Brak Content-Security-Policy",
                      "Zacznij od Report-Only z nonce dla skryptów, object-src 'none', base-uri 'self'."))

    # frame-ancestors ma pierwszenstwo przed X-Frame-Options (CSP3)
    fa_open = frame_ancestors_open(policy)
    xfo = (resp.header("x-frame-options") or "").strip().upper()
    if fa_open is True:
        out.append(_f("Nagłówki", Severity.WARN, "CSP frame-ancestors dopuszcza osadzanie przez dowolne strony",
                      "Ogranicz do 'self' albo konkretnych domen."))
    elif fa_open is False or xfo in ("DENY", "SAMEORIGIN"):
        out.append(_f("Nagłówki", Severity.OK, "Ochrona przed osadzaniem w ramce (frame-ancestors/X-Frame-Options)"))
    else:
        out.append(_f("Nagłówki", Severity.WARN, "Brak ochrony przed clickjackingiem",
                      "Dodaj CSP frame-ancestors 'self' (albo X-Frame-Options: SAMEORIGIN)."))

    if (resp.header("x-content-type-options") or "").strip().lower() != "nosniff":
        out.append(_f("Nagłówki", Severity.WARN, "Brak X-Content-Type-Options: nosniff"))
    rp = (resp.header("referrer-policy") or "").strip().lower()
    if not rp:
        out.append(_f("Nagłówki", Severity.INFO, "Brak Referrer-Policy (przeglądarka przyjmie strict-origin-when-cross-origin)"))
    elif any(v.strip() in ("unsafe-url", "no-referrer-when-downgrade") for v in rp.split(",")):
        out.append(_f("Nagłówki", Severity.WARN, f"Referrer-Policy: {rp} ujawnia pełne adresy innym serwisom"))
    if not resp.header("permissions-policy"):
        out.append(_f("Nagłówki", Severity.INFO, "Brak Permissions-Policy (kamera, mikrofon, geolokalizacja dla ramek)"))

    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        v = resp.header(name)
        if discloses_version(v):
            out.append(_f("Nagłówki", Severity.INFO, f"{name}: {v} ujawnia wersję oprogramowania",
                          "Usuń numer wersji z nagłówka (ułatwia dobór exploitów)."))

    acao = (resp.header("access-control-allow-origin") or "").strip()
    acac = (resp.header("access-control-allow-credentials") or "").strip().lower()
    if acao == "*" and acac == "true":
        out.append(_f("CORS", Severity.FAIL, "CORS: Allow-Origin '*' razem z Allow-Credentials: true"))
    elif acao == "*":
        out.append(_f("CORS", Severity.INFO, "CORS: Access-Control-Allow-Origin: * (ok dla treści publicznych)"))
    return out


def _cookies(resp: Response, https: bool) -> list[Finding]:
    out = []
    for raw in resp.header_all("set-cookie"):
        c = parse_set_cookie(raw)
        if c is None:
            continue
        issues = cookie_issues(c, https)
        if not issues:
            out.append(_f("Ciasteczka", Severity.OK, f"{c.name}: Secure, HttpOnly, SameSite={c.samesite}"))
        for sev, text in issues:
            out.append(_f("Ciasteczka", Severity(sev), f"{c.name}: {text}"))
    return out


def _content(resp: Response, https: bool) -> list[Finding]:
    ctype = (resp.header("content-type") or "").lower()
    if "html" not in ctype:
        return []
    host = parse_target(resp.url).host
    page = parse_page(resp.text(), host)
    out = []
    if https and page.mixed_active:
        out.append(_f("Treść", Severity.FAIL, f"Mieszana treść aktywna ({len(page.mixed_active)}): {', '.join(page.mixed_active[:3])}",
                      "Przeglądarki blokują skrypty/style z http:// na stronie https://; przełącz na https://."))
    if https and page.mixed_passive:
        out.append(_f("Treść", Severity.WARN, f"Mieszana treść pasywna ({len(page.mixed_passive)}): {', '.join(page.mixed_passive[:3])}"))
    if page.insecure_forms:
        out.append(_f("Treść", Severity.FAIL, f"Formularz wysyła dane przez HTTP: {page.insecure_forms[0]}"))
    if page.external_scripts_without_sri:
        out.append(_f("Treść", Severity.INFO,
                      f"Zewnętrzne skrypty bez integrity/SRI ({len(page.external_scripts_without_sri)}): {', '.join(page.external_scripts_without_sri[:3])}",
                      "Dla bibliotek z CDN dodaj integrity=\"sha384-…\" i crossorigin."))
    if discloses_version(page.generator):
        out.append(_f("Treść", Severity.INFO, f"meta generator ujawnia wersję: {page.generator}"))
    if page.incomplete:
        out.append(_f("Treść", Severity.INFO, f"Analiza HTML przerwana ({page.incomplete}); dalsza część strony niesprawdzona"))
    return out


def _security_txt(res: FetchResult | None, https: bool, now: datetime) -> list[Finding]:
    if res is None:
        return []
    r = res.response
    if r is None or r.status != 200:
        if r is None and res.error_kind in _UNAVAILABLE and res.error_kind != "offhost":
            return [_f("security.txt", Severity.INFO, f"Nie udało się sprawdzić security.txt: {res.error}")]
        return [_f("security.txt", Severity.INFO, "Brak security.txt",
                   "Opublikuj /.well-known/security.txt (RFC 9116) z Contact i Expires: badacze wiedzą, gdzie zgłosić lukę.")]
    out = []
    ctype = (r.header("content-type") or "").lower()
    if not ctype.startswith("text/plain"):
        if "html" in ctype:
            return [_f("security.txt", Severity.INFO, "Pod adresem security.txt jest strona HTML (prawdopodobnie miękkie 404)")]
        out.append(_f("security.txt", Severity.WARN, f"security.txt ma Content-Type {ctype or 'brak'}, wymagany text/plain"))
    if not https:
        out.append(_f("security.txt", Severity.WARN, "security.txt podany przez HTTP; RFC 9116 wymaga HTTPS"))
    if not r.url.split("://", 1)[-1].split("/", 1)[-1].startswith(".well-known/"):
        out.append(_f("security.txt", Severity.INFO, "security.txt tylko w lokalizacji zapasowej /security.txt",
                      "Właściwa lokalizacja to /.well-known/security.txt."))
    st = parse_security_txt(r.text())
    for e in st.errors:
        out.append(_f("security.txt", Severity.WARN, f"security.txt: {e}"))
    if st.expires is not None:
        if st.expires < now:
            out.append(_f("security.txt", Severity.WARN, f"security.txt wygasł {st.expires:%Y-%m-%d}",
                          "Zaktualizuj Expires; przeterminowanego pliku nie należy używać."))
        elif st.expires > now + timedelta(days=366):
            out.append(_f("security.txt", Severity.INFO, f"Expires za ponad rok ({st.expires:%Y-%m-%d})",
                          "RFC 9116 zaleca termin krótszy niż rok, żeby dane kontaktowe nie zestarzały się."))
    if "contact" in st.fields:
        out.append(_f("security.txt", Severity.OK, f"security.txt: kontakt {', '.join(st.fields['contact'][:3])}"
                      + (" (podpisany PGP, podpisu nie weryfikowano)" if st.signed else "")))
    return out


def _robots(res: FetchResult | None) -> list[Finding]:
    if res is None:
        return []
    r = res.response
    if r is None or r.status != 200 or "html" in (r.header("content-type") or "").lower():
        if r is None and res.error_kind in _UNAVAILABLE and res.error_kind != "offhost":
            return [_f("robots.txt", Severity.INFO, f"Nie udało się sprawdzić robots.txt: {res.error}")]
        return [_f("robots.txt", Severity.INFO, "Brak robots.txt")]
    rb = parse_robots(r.text())
    out = [_f("robots.txt", Severity.INFO, f"robots.txt: {rb.groups} grup, {len(rb.disallow)} reguł Disallow, {len(rb.sitemaps)} sitemap")]
    if rb.blocks_all:
        out.append(_f("robots.txt", Severity.INFO, "robots.txt blokuje wszystkie roboty (User-agent: * / Disallow: /)"))
    sensitive = [p for p in rb.disallow if any(w in p.lower() for w in SENSITIVE_ROBOTS)]
    if sensitive:
        out.append(_f("robots.txt", Severity.INFO, f"robots.txt wskazuje ścieżki wrażliwe: {', '.join(sensitive[:6])}",
                      "robots.txt jest publiczny i nie chroni dostępu; zabezpiecz te ścieżki uwierzytelnieniem."))
    return out


def _sitemap(res: FetchResult | None) -> list[Finding]:
    if res is None:
        return []
    r = res.response
    if r is None or r.status != 200:
        if r is None and res.error_kind in _UNAVAILABLE and res.error_kind != "offhost":
            return [_f("Sitemap", Severity.INFO, f"Nie udało się sprawdzić sitemap: {res.error}")]
        return [_f("Sitemap", Severity.INFO, "Brak sitemap.xml")]
    if "html" in (r.header("content-type") or "").lower():
        return [_f("Sitemap", Severity.INFO, "Pod adresem sitemap jest strona HTML (prawdopodobnie miękkie 404)")]
    sm = parse_sitemap(r.body)
    if sm.error and r.truncated:
        return [_f("Sitemap", Severity.INFO, "Sitemap większa niż --max-bytes: nie policzono adresów")]
    if sm.error:
        return [_f("Sitemap", Severity.WARN, f"Sitemap: {sm.error}")]
    kind = "indeks sitemap" if sm.kind == "sitemapindex" else "adresów"
    trunc = " (treść przycięta, liczba niepełna)" if r.truncated else ""
    return [_f("Sitemap", Severity.OK, f"Sitemap: {sm.count} {kind}{trunc}")]
