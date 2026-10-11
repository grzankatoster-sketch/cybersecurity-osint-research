"""Analiza na zbudowanych recznie danych (bez sieci)."""

from datetime import datetime, timezone

from site_audit.analyze import analyze
from site_audit.collector import SiteData
from site_audit.fetch import FetchResult, Hop, Response, TlsInfo
from site_audit.models import Severity
from site_audit.target import parse_target

NOW = datetime(2026, 10, 3, tzinfo=timezone.utc)
CERT = {"notAfter": "Jun  1 12:00:00 2027 GMT", "subject": ((("commonName", "shop.example"),),)}
GOOD_HEADERS = [
    ("Content-Type", "text/html; charset=utf-8"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'; script-src 'nonce-a'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "camera=()"),
    ("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax"),
]


def resp(url="https://shop.example/", status=200, headers=GOOD_HEADERS, body=b"<title>x</title>", tls="ok", **kw):
    if tls == "ok":
        tls = TlsInfo("TLSv1.3", "TLS_AES_128_GCM_SHA256", CERT)
    return Response(url, status, "OK", list(headers), body, tls=tls if url.startswith("https") else None, **kw)


def fetched(r: Response | None, error=None, kind=None, chain=None):
    url = r.url if r else "https://shop.example/"
    return FetchResult(url, chain or [Hop(url, r.status if r else None)], r, error, kind)


def plain(url, status=200, ctype="text/plain", body=b""):
    return fetched(resp(url, status, [("Content-Type", ctype)], body))


def site(main=None, http_probe="redirect", sec=None, robots=None, sitemap=None):
    data = SiteData(parse_target("https://shop.example/"), main or fetched(resp()))
    if http_probe == "redirect":
        http_probe = fetched(resp("http://shop.example/", 301, [("Location", "https://shop.example/")]))
    data.http_probe = http_probe
    data.security_txt = sec or plain("https://shop.example/.well-known/security.txt",
                                     body=b"Contact: mailto:s@shop.example\nExpires: 2027-01-01T00:00:00Z\n")
    data.robots = robots or plain("https://shop.example/robots.txt", body=b"User-agent: *\nDisallow:\n")
    data.sitemap = sitemap or plain("https://shop.example/sitemap.xml", ctype="application/xml",
                                    body=b"<urlset><url><loc>a</loc></url></urlset>")
    return data


def sev(findings, area=None):
    return {(f.severity, f.area) for f in findings if area is None or f.area == area}


def titles(findings, severity):
    return [f.title for f in findings if f.severity == severity]


def test_good_site_has_no_warn_or_fail():
    f = analyze(site(), NOW)
    assert not titles(f, Severity.WARN) and not titles(f, Severity.FAIL), [x.title for x in f]
    assert any("http:// przekierowuje na https://" in t for t in titles(f, Severity.OK))
    assert any("Certyfikat ważny do 2027-06-01" in t for t in titles(f, Severity.OK))


def test_bare_site_warnings():
    bare = fetched(resp(headers=[("Content-Type", "text/html"), ("Server", "nginx/1.18.0"),
                                 ("Set-Cookie", "sid=1")]))
    probe = fetched(resp("http://shop.example/", 200, [("Content-Type", "text/html")]))
    f = analyze(site(bare, probe), NOW)
    warn = " | ".join(titles(f, Severity.WARN))
    for needle in ("bez przekierowania na HTTPS", "Strict-Transport-Security", "Content-Security-Policy",
                   "clickjacking", "nosniff", "sid: brak Secure"):
        assert needle in warn
    assert any("nginx/1.18.0" in t for t in titles(f, Severity.INFO))


def test_main_fetch_error_is_not_reported_as_missing():
    f = analyze(site(fetched(None, "przekroczony czas", "timeout")), NOW)
    assert len(f) == 1 and f[0].severity == Severity.INFO and "Nie udało się sprawdzić" in f[0].title


def test_blocked_target_is_fail():
    f = analyze(site(fetched(None, "adres niepubliczny", "blocked")), NOW)
    assert f[0].severity == Severity.FAIL


def test_http_only_site_fails():
    data = site(fetched(resp("http://shop.example/", headers=[("Content-Type", "text/html")])), http_probe=None)
    assert any("bez HTTPS" in t for t in titles(analyze(data, NOW), Severity.FAIL))


def test_https_to_http_downgrade_in_chain():
    chain = [Hop("https://shop.example/", 302, "http://shop.example/x"), Hop("http://shop.example/x", 200)]
    data = site(fetched(resp("http://shop.example/x", headers=[("Content-Type", "text/html")]), chain=chain))
    assert any("z HTTPS na HTTP" in t for t in titles(analyze(data, NOW), Severity.FAIL))


def test_certificate_problems():
    bad = fetched(resp(tls=TlsInfo("TLSv1.2", "X", None, "self-signed certificate")))
    assert any("nie przechodzi weryfikacji" in t for t in titles(analyze(site(bad), NOW), Severity.FAIL))
    soon = dict(CERT, notAfter="Oct 10 00:00:00 2026 GMT")
    f = analyze(site(fetched(resp(tls=TlsInfo("TLSv1.3", "X", soon)))), NOW)
    assert any("Certyfikat ważny do 2026-10-10" in t for t in titles(f, Severity.FAIL))
    old = analyze(site(fetched(resp(tls=TlsInfo("TLSv1.1", "X", CERT)))), NOW)
    assert any("TLSv1.1" in t for t in titles(old, Severity.FAIL))


def test_hsts_variants():
    def with_hsts(v):
        h = [x for x in GOOD_HEADERS if x[0] != "Strict-Transport-Security"] + [("Strict-Transport-Security", v)]
        return analyze(site(fetched(resp(headers=h))), NOW)
    assert any("max-age=0" in t for t in titles(with_hsts("max-age=0"), Severity.WARN))
    assert any("Krótkie" in t for t in titles(with_hsts("max-age=300"), Severity.INFO))
    assert any("preload" in t for t in titles(with_hsts("max-age=300; preload"), Severity.INFO))


def test_report_only_csp_is_info():
    h = [x for x in GOOD_HEADERS if x[0] != "Content-Security-Policy"] + [
        ("Content-Security-Policy-Report-Only", "default-src 'self'"), ("X-Frame-Options", "DENY")]
    f = analyze(site(fetched(resp(headers=h))), NOW)
    assert any("Report-Only" in t for t in titles(f, Severity.INFO))
    assert not any("CSP" == x.area for x in f if x.severity == Severity.WARN)


def test_cors_wildcard_with_credentials():
    h = GOOD_HEADERS + [("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")]
    assert ("CORS" in {x.area for x in analyze(site(fetched(resp(headers=h))), NOW) if x.severity == Severity.FAIL})


def test_mixed_content_and_insecure_form():
    body = b'<script src="http://x.example/a.js"></script><img src="http://x.example/i.png"><form action="http://shop.example/l">'
    f = analyze(site(fetched(resp(body=body))), NOW)
    fail = " | ".join(titles(f, Severity.FAIL))
    assert "aktywna" in fail and "Formularz" in fail
    assert any("pasywna" in t for t in titles(f, Severity.WARN))


def test_security_txt_states():
    expired = plain("https://shop.example/.well-known/security.txt",
                    body=b"Contact: mailto:s@x\nExpires: 2025-01-01T00:00:00Z\n")
    assert any("wygasł" in t for t in titles(analyze(site(sec=expired), NOW), Severity.WARN))
    soft404 = plain("https://shop.example/.well-known/security.txt", ctype="text/html", body=b"<html>")
    assert any("miękkie 404" in t for t in titles(analyze(site(sec=soft404), NOW), Severity.INFO))
    missing = plain("https://shop.example/security.txt", status=404)
    assert any(t == "Brak security.txt" for t in titles(analyze(site(sec=missing), NOW), Severity.INFO))
    err = fetched(None, "przekroczony czas", "timeout")
    f = analyze(site(sec=err), NOW)
    assert any("Nie udało się sprawdzić security.txt" in t for t in titles(f, Severity.INFO))
    assert not any(t == "Brak security.txt" for t in titles(f, Severity.INFO))
    legacy = plain("https://shop.example/security.txt", body=b"Contact: x\nExpires: 2027-01-01T00:00:00Z\n")
    assert any("zapasowej" in t for t in titles(analyze(site(sec=legacy), NOW), Severity.INFO))
    far = plain("https://shop.example/.well-known/security.txt", body=b"Contact: x\nExpires: 2030-01-01T00:00:00Z\n")
    assert any("ponad rok" in t for t in titles(analyze(site(sec=far), NOW), Severity.INFO))


def test_robots_sensitive_paths_and_sitemap_errors():
    robots = plain("https://shop.example/robots.txt", body=b"User-agent: *\nDisallow: /admin/\nDisallow: /backup.zip\n")
    f = analyze(site(robots=robots), NOW)
    assert any("/admin/" in t and "/backup.zip" in t for t in titles(f, Severity.INFO))
    bad = plain("https://shop.example/sitemap.xml", ctype="application/xml", body=b"<urlset>")
    assert any("Sitemap" in t for t in titles(analyze(site(sitemap=bad), NOW), Severity.WARN))
    big = fetched(resp("https://shop.example/sitemap.xml", headers=[("Content-Type", "application/xml")],
                       body=b"<urlset><url>", truncated=True))
    f = analyze(site(sitemap=big), NOW)
    assert not titles([x for x in f if x.area == "Sitemap"], Severity.WARN)


def test_http_port_closed_is_info_not_warn():
    probe = fetched(None, "odmowa", "network")
    f = analyze(site(http_probe=probe), NOW)
    assert any("port 80" in t for t in titles(f, Severity.INFO))
    assert not [x for x in f if x.area == "HTTPS" and x.severity != Severity.INFO]
