"""Testy poprawek z przeglądu logiki (Codex 03.10.2026). Offline."""
import asyncio
import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from username_engine import cli, sources
from username_engine.classify import classify
from username_engine.engine import check_site, random_name
from username_engine.extract import extract_profile
from username_engine.geo import Gazetteer, profile_evidence
from username_engine.health import (BLOCKED, FALSE_POSITIVE, OK, STALE, UNSTABLE, judge, load_health, save_health)
from username_engine.http import DNS_ERROR, DNS_TEMP, Fetcher, retry_delay
from username_engine.models import Response, Result, Site, Status
from username_engine.report import render_html
from username_engine.sources import load_db, merge, save_db, site_key
from username_engine.urlnorm import normalize_url

URL = "https://ex.com/u/{username}"
CUSTOM_SITES = Path(__file__).resolve().parents[1] / "src" / "username_engine" / "resources" / "custom_sites.json"


def site(**kw) -> Site:
    return Site(name="Ex", url=URL, **kw)


def resp(status=200, text="", username="alice", **kw):
    return Response(status=status, text=text, final_url=URL.replace("{username}", username), **kw)


class FakeFetcher:
    def __init__(self, handler):
        self.handler, self.calls = handler, []

    async def fetch(self, method, url, headers=None, body=None):
        self.calls.append((method, url, headers, body))
        return self.handler(url)


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------- classify

def test_control_error_does_not_raise_confidence():
    s = site(e_strings=["avatar"])
    login_page = Response(200, "<input type=password>", final_url="https://ex.com/login")
    st, conf, reason = classify(s, resp(200, "avatar"), "alice", login_page, "zq81kdm2")
    assert st is Status.FOUND and conf < 0.95 and "potwierdza" not in reason
    clear = Response(404, "", final_url="https://ex.com/u/zq81kdm2")
    st, conf, reason = classify(s, resp(200, "avatar"), "alice", clear, "zq81kdm2")
    assert st is Status.FOUND and conf >= 0.97 and "potwierdza" in reason


def test_same_length_but_different_content_is_not_soft_404():
    a = "Profil alice. " + "lorem ipsum dolor sit amet " * 40
    b = "Zupelnie inny serwis. " + "kot ala ma psa tralala cos " * 40
    a, b = a[:len(b)].ljust(len(b)), b
    assert abs(len(a) - len(b)) / len(b) < 0.05
    r = resp(200, a)
    c = resp(200, b, username="zq81kdm2")
    st, conf, reason = classify(site(check_type="status_code"), r, "alice", c, "zq81kdm2")
    assert st is Status.FOUND and "soft-404" not in reason


def test_truncated_equal_length_pages_not_blindly_same():
    r = resp(200, "alpha beta gamma " * 5000, truncated=True)
    c = resp(200, "totally different words here " * 5000, username="zq81kdm2", truncated=True)
    st, _, reason = classify(site(check_type="status_code"), r, "alice", c, "zq81kdm2")
    assert "soft-404" not in reason


def test_unrecognized_code_is_error_not_not_found():
    for code in (400, 405, 406, 409):
        st, _, reason = classify(site(e_code=200, m_code=404), resp(code, "x"), "alice")
        assert st is Status.ERROR and str(code) in reason, code
        assert classify(site(check_type="status_code"), resp(code, "x"), "alice")[0] is Status.ERROR
    # jawne kody braku konta nadal dają NOT_FOUND
    assert classify(site(e_code=200, m_code=404), resp(404, "x"), "alice")[0] is Status.NOT_FOUND
    assert classify(site(e_code=200, m_code=400), resp(400, "x"), "alice")[0] is Status.NOT_FOUND
    assert classify(site(check_type="status_code"), resp(404, "x"), "alice")[0] is Status.NOT_FOUND
    assert classify(site(check_type="status_code"), resp(410, "x"), "alice")[0] is Status.NOT_FOUND
    assert classify(site(e_strings=["a"], m_strings=["gone"]), resp(400, "gone"), "alice")[0] is Status.NOT_FOUND


def test_truncated_response_never_proves_absence():
    big = "x" * 1000
    s = site(e_strings=["avatar"])
    st, _, reason = classify(s, resp(200, big, truncated=True), "alice")
    assert st is Status.ERROR and "obci" in reason
    assert classify(s, resp(200, big), "alice")[0] is Status.NOT_FOUND            # pełna odpowiedź: brak tekstu = brak
    assert classify(s, resp(200, big + "avatar", truncated=True), "alice")[0] is Status.FOUND
    s2 = site(e_strings=["avatar"], m_strings=["User not found"])
    assert classify(s2, resp(200, big, truncated=True), "alice")[0] is Status.ERROR
    assert classify(s2, resp(200, big + "User not found", truncated=True), "alice")[0] is Status.NOT_FOUND


# ---------------------------------------------------------------- http

def test_retry_after_seconds_date_minimum_and_cap():
    assert retry_delay(0, "30") == 30.0                       # minimum = wskazany czas (nie obcinany do 10 s)
    assert retry_delay(0, "120") is None                      # > 60 s: nie czekamy, ERROR
    assert retry_delay(3, "2") == 8.0                         # Retry-After jest minimum: backoff 8 s większy
    now = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
    assert retry_delay(0, "Sat, 03 Oct 2026 12:00:20 GMT", now=now) == 20.0
    assert retry_delay(0, "Sat, 03 Oct 2026 14:00:00 GMT", now=now) is None
    assert retry_delay(1, "Wed, 21 Oct 2020 07:28:00 GMT", now=now) == 2.0      # data z przeszłości -> backoff
    assert retry_delay(0, "bzdura") == 1.0 and retry_delay(0, "-5") == 1.0 and retry_delay(0, "nan") == 1.0


def test_fetch_does_not_wait_for_long_retry_after_and_jitter_only_up(monkeypatch):
    sleeps = []

    async def fake_sleep(d):
        sleeps.append(d)

    monkeypatch.setattr("username_engine.http.asyncio.sleep", fake_sleep)
    seq = iter([Response(429, headers={"retry-after": "120"})])

    async def go():
        f = Fetcher(retries=2, jitter=True)

        async def once(*a, **k):
            return next(seq)
        f._once = once
        return await f.fetch("GET", "http://x.test/")

    r = run(go())
    assert r.status == 429 and sleeps == []                   # nie czekamy 120 s (429 -> ERROR limit zapytań)
    seq = iter([Response(429, headers={"Retry-After": "5"}), Response(200, "ok")])
    r = run(go())
    assert r.status == 200 and len(sleeps) == 1 and 5.0 <= sleeps[0] <= 6.0 + 1e-9    # jitter tylko w górę


def test_response_headers_case_insensitive():
    r = Response(200, "x", headers={"content-type": "application/json", "RETRY-AFTER": "3"})
    assert r.headers.get("Content-Type") == "application/json" and r.headers.get("Retry-After") == "3"
    assert "retry-after" in r.headers


def test_dns_permanent_vs_transient_classified():
    import socket
    import aiohttp
    from aiohttp.client_reqrep import ConnectionKey
    key = ConnectionKey("x.test", 443, True, True, None, None, None)

    def err(code):
        return aiohttp.ClientConnectorDNSError(key, socket.gaierror(code, "dns"))

    async def once_with(code):
        f = Fetcher(retries=0)
        f._session = object()

        async def raiser(*a, **k):
            raise err(code)
        f._request = raiser
        return await f._once("GET", "http://x.test/", {}, None)

    assert run(once_with(socket.EAI_NONAME)).error == DNS_ERROR
    assert run(once_with(socket.EAI_AGAIN)).error.startswith(DNS_TEMP)
    assert not DNS_TEMP.startswith(DNS_ERROR)


def test_transient_dns_is_retried_and_not_dead_in_health():
    calls = {"n": 0}

    async def go():
        f = Fetcher(retries=2, jitter=False)

        async def once(*a, **k):
            calls["n"] += 1
            return Response(None, error=DNS_TEMP)
        f._once = once
        return await f.fetch("GET", "http://x.test/")

    async def no_sleep(d):
        return None

    import username_engine.http as h
    orig = h.asyncio.sleep
    h.asyncio.sleep = no_sleep
    try:
        r = run(go())
    finally:
        h.asyncio.sleep = orig
    assert r.error == DNS_TEMP and calls["n"] == 3
    assert judge(Result("S", "u", Status.ERROR, reason=DNS_TEMP), None)[0] == UNSTABLE


def test_truncated_flag_set_for_big_body():
    from aiohttp import web
    import username_engine.http as h

    async def big(request):
        return web.Response(body=b"x" * 300_000)

    async def small(request):
        return web.Response(body=b"x" * 1000)

    async def go():
        app = web.Application()
        app.add_routes([web.get("/big", big), web.get("/small", small)])
        runner = web.AppRunner(app)
        await runner.setup()
        tcp = web.TCPSite(runner, "127.0.0.1", 0)
        await tcp.start()
        base = f"http://127.0.0.1:{tcp._server.sockets[0].getsockname()[1]}"
        old = h.MAX_BODY
        h.MAX_BODY = 100_000
        try:
            async with Fetcher(retries=0, allow_private=True) as f:
                return await f.fetch("GET", base + "/big"), await f.fetch("GET", base + "/small")
        finally:
            h.MAX_BODY = old
            await runner.cleanup()

    big_r, small_r = run(go())
    assert big_r.truncated and len(big_r.text) == 100_000 and not small_r.truncated


# ---------------------------------------------------------------- engine

def test_post_body_escaped_per_content_type():
    seen = []
    f = FakeFetcher(lambda url: Response(404, "", final_url=url))

    async def fetch(method, url, headers=None, body=None):
        seen.append(body)
        return Response(404, "", final_url=url)
    f.fetch = fetch
    nasty = 'a"b\\c&d=e'
    js = Site("J", "https://j.com/{username}", method="POST", body='{"user":"{username}"}',
              headers={"content-type": "application/json"}, e_strings=["x"], regex=None)
    run(check_site(js, nasty, f, control="none"))
    assert json.loads(seen[-1]) == {"user": nasty}
    form = Site("F", "https://f.com/{username}", method="POST", body="u={username}&x=1",
                headers={"Content-Type": "application/x-www-form-urlencoded"}, e_strings=["x"])
    run(check_site(form, nasty, f, control="none"))
    from urllib.parse import parse_qs
    assert parse_qs(seen[-1])["u"] == [nasty] and parse_qs(seen[-1])["x"] == ["1"]
    sniff = Site("S", "https://s.com/{username}", method="POST", body='{"user":"{username}"}', e_strings=["x"])
    run(check_site(sniff, nasty, f, control="none"))
    assert json.loads(seen[-1]) == {"user": nasty}               # JSON rozpoznany po treści bez nagłówka


def test_control_name_fits_short_regex():
    f = FakeFetcher(lambda url: Response(200, "avatar", final_url=url))
    s = Site("Short", "https://s.com/{username}", regex=r"^[a-z0-9]{3,8}$", e_strings=["avatar"])
    r = run(check_site(s, "alice", f, control="all"))
    assert len(f.calls) == 2                                    # kontrola wykonana mimo krótkiego regexu
    assert r.status is Status.ERROR and "niewiarygodna" in r.reason
    names = {c[1].rsplit("/", 1)[1] for c in f.calls}
    assert all(3 <= len(n) <= 8 for n in names)
    assert 3 <= len(random_name(6)) <= 8


def test_no_control_possible_is_marked():
    f = FakeFetcher(lambda url: Response(200, "avatar", final_url=url))
    s = Site("Digits", "https://d.com/{username}", regex=r"^\d{20}$", e_strings=["avatar"])
    r = run(check_site(s, "1" * 20, f, control="all"))
    assert r.status is Status.FOUND and "kontrola niemożliwa" in r.reason


def test_extract_prefers_object_matching_username():
    doc = {"organization": {"login": "mozilla", "name": "Mozilla Org", "location": "Mountain View"},
           "login": "alice", "name": "Alice A", "location": "Gdansk"}
    p = extract_profile(json.dumps(doc), "application/json", "alice")
    assert p["name"] == "Alice A" and p["location"] == "Gdansk"
    nested = {"orgs": [{"login": "mozilla", "name": "Org"}], "data": {"user": {"username": "Alice", "name": "Real"}}}
    assert extract_profile(json.dumps(nested), "application/json", "alice")["name"] == "Real"
    # własne pola obiektu mają pierwszeństwo przed zagnieżdżonymi nawet bez dopasowania nazwy
    assert extract_profile(json.dumps({"team": {"name": "T"}, "name": "Own"}), "application/json")["name"] == "Own"


def test_engine_passes_username_to_extract():
    doc = json.dumps({"organization": {"name": "Org"}, "login": "alice", "name": "Alice"})
    f = FakeFetcher(lambda url: Response(200, doc, final_url=url, headers={"CONTENT-TYPE": "application/json"})
                    if url.endswith("/alice") else Response(404, "{}", final_url=url))
    s = Site("Api", "https://api.test/{username}", e_strings=["login"])
    assert run(check_site(s, "alice", f)).profile["name"] == "Alice"


# ---------------------------------------------------------------- health

def R(status, conf=0.0, reason=""):
    return Result("S", "u", status, conf, reason)


def test_judge_all_status_combinations():
    nf, fnd = R(Status.NOT_FOUND, reason="kod 404"), R(Status.FOUND, 0.9, "tekst")
    # losowa NOT_FOUND + znane konto nieudane -> nie „OK”
    assert judge(nf, R(Status.ERROR, reason="timeout"))[0] == UNSTABLE
    assert judge(nf, R(Status.ERROR, reason="blokada anty-bot (x)"))[0] == UNSTABLE      # nigdy nie wyklucza serwisu
    assert judge(nf, R(Status.UNSUPPORTED, reason="regex"))[0] == UNSTABLE
    assert judge(nf, R(Status.FOUND, 0.45, "tylko kod"))[0] == UNSTABLE                 # za słabe trafienie znanego
    assert judge(nf, fnd)[0] == OK and judge(nf, nf)[0] == STALE and judge(nf, None)[0] == OK
    # losowa UNSUPPORTED (regex nie pasuje do losowej nazwy): oceniamy tylko znane konto
    un = R(Status.UNSUPPORTED, reason="nazwa niezgodna")
    assert judge(un, fnd)[0] == OK and judge(un, nf)[0] == STALE and judge(un, None)[0] == OK
    # losowa FOUND ≥ próg -> false positive; słaba -> nie
    assert judge(fnd, None)[0] == FALSE_POSITIVE and judge(R(Status.FOUND, 0.45), fnd)[0] == OK
    # losowa ERROR
    assert judge(R(Status.ERROR, reason="timeout"), fnd)[0] == OK
    assert judge(R(Status.ERROR, reason="dostęp zabroniony (403)"), None)[0] == BLOCKED


def test_health_entries_older_than_30_days_ignored(tmp_path):
    p = tmp_path / "health.json"
    health = {"Old": {"state": "dead", "reason": ""}, "New": {"state": "blocked", "reason": ""}}
    save_health(health, p)
    doc = json.loads(p.read_text(encoding="utf-8"))
    assert doc["sites"]["Old"]["checked"] == date.today().isoformat()          # data zapisana przy każdym wpisie
    doc["sites"]["Old"]["checked"] = (date.today() - timedelta(days=45)).isoformat()
    p.write_text(json.dumps(doc), encoding="utf-8")
    loaded = load_health(p)
    assert "Old" not in loaded and loaded["New"]["state"] == "blocked"
    doc["meta"]["checked"] = (date.today() - timedelta(days=45)).isoformat()   # cały plik przeterminowany
    for v in doc["sites"].values():
        v.pop("checked", None)
    p.write_text(json.dumps(doc), encoding="utf-8")
    assert load_health(p) == {}
    # plik bez dat (stary format): nie da się ocenić wieku — wpisy zostają
    p.write_text(json.dumps({"sites": {"X": {"state": "dead"}}}), encoding="utf-8")
    assert load_health(p) == {"X": {"state": "dead"}}


# ---------------------------------------------------------------- sources / urlnorm

def test_merge_names_unique_with_counter():
    a = [Site("X", f"https://a{i}.com/{{username}}", source="wmn") for i in range(3)]
    b = [Site("X [wmn]", "https://zz.com/{username}", source="wmn")]
    names = [s.name for s in merge(a, b)]
    assert len(names) == len(set(n.lower() for n in names)) == 4 and names[0] == "X"


def test_url_normalization_shared_keeps_path_case_and_query():
    assert normalize_url("HTTPS://WWW.Example.com/Users/Bob/") == "example.com/Users/Bob"
    assert normalize_url("https://x.com/p?b=2&a=1") == "x.com/p?a=1&b=2"
    assert normalize_url("https://x.com/p?id=7") != normalize_url("https://x.com/p?id=8")
    assert normalize_url("https://x.com/p#frag") == "x.com/p"
    assert normalize_url("http://[bad") == ""
    assert site_key(Site("A", "https://x.com/User/{username}")) != site_key(Site("B", "https://x.com/user/{username}"))
    assert site_key(Site("A", "https://x.com/m?username={username}")) != site_key(Site("B", "https://x.com/m?id={username}"))
    assert len(merge([Site("A", "https://www.x.com/u/{username}/")], [Site("B", "https://x.com/u/{username}")])) == 1


# ---------------------------------------------------------------- report

def test_report_lists_omitted_items_and_single_pass(monkeypatch):
    results = [Result(f"S{i}", f"https://s{i}.com/a", Status.ERROR, reason="blokada anty-bot (x)") for i in range(305)]
    results += [Result("T", "https://t.com/a", Status.ERROR, reason="timeout")]
    html = render_html("a", {"a": results}, {"a": {"checked": 306, "error": 306, "unsupported": 0}}, [])
    assert "Sprawdź ręcznie: 305" in html and "pominięto 5" in html
    assert "Nie udało się sprawdzić: 1" in html


def test_manual_split_is_linear():
    from username_engine import report
    results = [Result(f"S{i}", "https://s/a", Status.ERROR, reason="timeout") for i in range(3000)]
    import time
    t = time.perf_counter()
    report._errors_block(results)
    assert time.perf_counter() - t < 1.0


# ---------------------------------------------------------------- models

def test_site_from_dict_validates_types_and_load_db_skips_bad(tmp_path):
    with pytest.raises(ValueError):
        Site.from_dict({"name": "X", "url": "https://x/{username}", "e_strings": "avatar"})
    with pytest.raises(ValueError):
        Site.from_dict({"name": "X", "url": 5})
    with pytest.raises(ValueError):
        Site.from_dict({"name": "X", "url": "https://x/{username}", "e_code": "200"})
    with pytest.raises(ValueError):
        Site.from_dict({"name": "X", "url": "https://x/{username}", "headers": {"a": 1}})
    assert Site.from_dict({"name": "X", "url": "https://x/{username}", "e_code": 200, "extra": 1}).e_code == 200
    db = tmp_path / "sites.json"
    db.write_text(json.dumps({"sites": [
        {"name": "Good", "url": "https://g.com/{username}"},
        {"name": "Bad", "url": "https://b.com/{username}", "tags": "social"},
        "nie-slownik",
        {"url": "https://noname.com/{username}"}]}), encoding="utf-8")
    warns = []
    sites = load_db(db, warn=warns.append)
    assert [s.name for s in sites] == ["Good"] and len(warns) == 3 and "Bad" in warns[0]


# ---------------------------------------------------------------- geo

def test_global_site_with_country_tag_gives_no_country_evidence():
    g = Gazetteer()
    assert profile_evidence("Codeberg", "https://codeberg.org/x", {}, ["coding", "global", "de"], g) == []
    ev = profile_evidence("Wykop", "https://wykop.pl/x", {}, ["pl"], g)
    assert [e.country for e in ev] == ["PL"]
    ev = profile_evidence("Svc", "https://svc.example/x", {}, ["de"], g)
    assert [e.country for e in ev] == ["DE"]                  # sam tag krajowy (bez global) nadal liczy się


# ---------------------------------------------------------------- 429 nigdy nie udaje braku konta (Reddit)

def test_429_reason_is_readable_and_never_absence():
    s = site(check_type="status_code", e_code=200, m_code=404)
    st, conf, reason = classify(s, resp(429, headers={"Retry-After": "120"}), "alice")
    assert st is Status.ERROR and conf == 0.0
    assert "limit zapytań" in reason and "429" in reason and "120 s" in reason and "nie dowodzi braku konta" in reason
    st, _, reason = classify(s, resp(429, headers={"Retry-After": "<script>"}), "alice")
    assert st is Status.ERROR and "<script>" not in reason and "limit zapytań" in reason


def test_reddit_rule_rate_limited_gives_error_not_absence():
    custom = json.loads(CUSTOM_SITES.read_text(encoding="utf-8"))
    reddit = next(s for s in sources.from_custom(custom) if s.name == "Reddit")
    f = FakeFetcher(lambda url: Response(429, "", final_url=url, headers={"Retry-After": "30"}))
    r = run(check_site(reddit, "spez", f))
    assert r.status is Status.ERROR and "limit zapytań" in r.reason
