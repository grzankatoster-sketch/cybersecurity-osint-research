from datetime import datetime, timezone

from site_audit.parsers import (
    cookie_issues, csp_issues, parse_csp, parse_hsts, parse_page, parse_robots,
    parse_security_txt, parse_set_cookie, parse_sitemap,
)


# ---- HSTS
def test_hsts_full():
    h = parse_hsts("max-age=31536000; includeSubDomains; preload")
    assert (h.max_age, h.include_subdomains, h.preload, h.errors) == (31536000, True, True, [])


def test_hsts_quoted_and_case_insensitive():
    h = parse_hsts('MAX-AGE="600"; INCLUDESUBDOMAINS')
    assert h.max_age == 600 and h.include_subdomains


def test_hsts_missing_and_invalid_max_age():
    assert "brak max-age" in parse_hsts("includeSubDomains").errors
    h = parse_hsts("max-age=abc")
    assert h.max_age is None and any("nieprawidłowe" in e for e in h.errors) and "brak max-age" not in h.errors


def test_hsts_duplicate_directive():
    assert any("powtórzona" in e for e in parse_hsts("max-age=1; max-age=2").errors)


# ---- CSP
def test_csp_first_directive_wins_and_lowercase():
    p = parse_csp("Script-Src 'self'; script-src *; ;")
    assert p == {"script-src": ["'self'"]}


def test_csp_strong_policy_has_no_issues():
    p = parse_csp("default-src 'self'; script-src 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'none'")
    assert csp_issues(p) == []


def test_csp_unsafe_inline_without_nonce_and_wildcards():
    issues = csp_issues(parse_csp("default-src * 'unsafe-inline' 'unsafe-eval'"))
    text = " | ".join(issues)
    assert "'unsafe-inline'" in text and "'unsafe-eval'" in text and "szerokie źródła: *" in text
    assert any("object-src" in i for i in issues) and any("base-uri" in i for i in issues)


def test_csp_unsafe_inline_with_nonce_is_ignored_by_browsers():
    issues = csp_issues(parse_csp("script-src 'unsafe-inline' 'nonce-x'; object-src 'none'; base-uri 'self'"))
    assert not any("unsafe-inline" in i for i in issues)


def test_csp_without_script_or_default():
    assert any("brak script-src" in i for i in csp_issues(parse_csp("img-src 'self'")))


# ---- Cookies
def test_cookie_parse_attributes():
    c = parse_set_cookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=lax; Max-Age=60")
    assert (c.name, c.secure, c.httponly, c.samesite, c.path, c.session) == ("sid", True, True, "Lax", "/", False)


def test_cookie_without_value_separator_ignored():
    assert parse_set_cookie("garbage") is None


def test_cookie_issues():
    weak = cookie_issues(parse_set_cookie("a=1"), https=True)
    sev = {s for s, _ in weak}
    assert sev == {"WARN", "INFO"}
    assert ("FAIL", "SameSite=None bez Secure (przeglądarki odrzucają)") in cookie_issues(parse_set_cookie("a=1; SameSite=None"), True)
    assert any(s == "FAIL" for s, _ in cookie_issues(parse_set_cookie("__Host-a=1; Secure; Path=/; Domain=x.pl"), True))
    assert cookie_issues(parse_set_cookie("a=1; Secure; HttpOnly; SameSite=Strict"), True) == []


# ---- security.txt
GOOD_SEC = "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\nPreferred-Languages: pl, en\n# komentarz\n"


def test_security_txt_good():
    st = parse_security_txt(GOOD_SEC)
    assert st.errors == [] and st.fields["contact"] == ["mailto:security@example.com"]
    assert st.expires == datetime(2027, 1, 1, tzinfo=timezone.utc)


def test_security_txt_missing_required_and_bad_date():
    st = parse_security_txt("Policy: https://x/\nExpires: jutro\n")
    assert "brak wymaganego pola Contact" in st.errors
    assert any("RFC 3339" in e for e in st.errors)
    assert "brak wymaganego pola Expires" in parse_security_txt("Contact: a@b").errors


def test_security_txt_date_without_timezone_rejected():
    assert any("RFC 3339" in e for e in parse_security_txt("Contact: x\nExpires: 2027-01-01T00:00:00").errors)


def test_security_txt_pgp_signed():
    text = ("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" + GOOD_SEC.replace("\n", "\r\n")
            + "- -dash escaped: x\n-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n")
    st = parse_security_txt(text)
    assert st.signed and "contact" in st.fields and "hash" not in st.unknown


# ---- robots
def test_robots_groups_disallow_sitemaps():
    rb = parse_robots("User-agent: *\nDisallow: /admin/\nDisallow: /\n\nUser-agent: Bot\nUser-agent: Other\nDisallow: /x\n"
                      "Sitemap: https://example.com/s.xml # komentarz\n")
    assert rb.groups == 2 and rb.blocks_all
    assert rb.disallow == ["/admin/", "/", "/x"] and rb.sitemaps == ["https://example.com/s.xml"]


def test_robots_empty_disallow_does_not_block():
    assert not parse_robots("User-agent: *\nDisallow:\n").blocks_all


# ---- sitemap
def test_sitemap_urlset_and_index():
    sm = parse_sitemap(b'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                       b"<url><loc>a</loc></url><url><loc>b</loc></url></urlset>")
    assert (sm.kind, sm.count, sm.error) == ("urlset", 2, None)
    assert parse_sitemap(b"<sitemapindex><sitemap><loc>x</loc></sitemap></sitemapindex>").kind == "sitemapindex"


def test_sitemap_refuses_entities():
    bomb = b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa">]><urlset>&a;</urlset>'
    assert "DOCTYPE" in parse_sitemap(bomb).error


def test_sitemap_invalid_xml_and_wrong_root():
    assert "niepoprawny XML" in parse_sitemap(b"<urlset>").error
    assert "nieoczekiwany" in parse_sitemap(b"<html></html>").error


# ---- HTML
def test_page_parser():
    html = """<html><head><title> Sklep
      Testowy </title><meta name="description" content="Opis"><meta name="generator" content="WordPress 6.4.2">
    <link rel="canonical" href="https://shop.example/"><link rel="stylesheet" href="http://cdn.example/a.css"></head>
    <body><script src="http://evil.example/x.js"></script><script src="https://cdn.other/lib.js"></script>
    <script src="https://static.shop.example/own.js"></script>
    <script src="https://cdn.other/ok.js" integrity="sha384-x"></script>
    <img src="http://img.example/p.png"><form action="http://shop.example/login"></form>
    <a href="/kontakt">k</a><a href="https://shop.example/x">x</a><a href="https://inny.pl/">i</a><a href="#top">t</a>
    </body></html>"""
    p = parse_page(html, "shop.example")
    assert p.title == "Sklep Testowy" and p.description == "Opis" and p.generator == "WordPress 6.4.2"
    assert p.canonical == "https://shop.example/"
    assert p.mixed_active == ["http://cdn.example/a.css", "http://evil.example/x.js"]
    assert p.mixed_passive == ["http://img.example/p.png"]
    assert p.insecure_forms == ["http://shop.example/login"]
    assert p.external_scripts_without_sri == ["https://cdn.other/lib.js"]
    assert (p.links_internal, p.links_external) == (2, 1)


def test_page_parser_survives_garbage():
    assert parse_page("<<<>>><title>x", "a.pl").title is None
