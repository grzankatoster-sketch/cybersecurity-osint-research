"""Klient Threads na fałszywym transporcie: wszystkie statusy kontraktu, bez sieci i bez prawdziwego tokenu."""
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from meta_search import cli
from meta_search.config import Config, load_config
from meta_search.contract import St
from meta_search.links import manual_links
from meta_search.report import render_html
from meta_search.threads import ThreadsClient, redact

TOKEN = "TESTTOKEN_abcdefghijklmnopqrstuvwxyz_0123"


class Fake:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.urls = []

    def __call__(self, url, timeout):
        self.urls.append(url)
        r = self.responses.pop(0)
        status, body = r[0], r[1]
        headers = r[2] if len(r) > 2 else {}
        err = r[3] if len(r) > 3 else None
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        return status, headers, raw, err


def client(*responses):
    fake = Fake(*responses)
    return ThreadsClient(Config(threads_token=TOKEN), transport=fake, sleep=lambda s: None), fake


def err(code, msg="x", sub=None):
    e = {"message": msg, "type": "OAuthException", "code": code}
    if sub:
        e["error_subcode"] = sub
    return {"error": e}


def assert_no_token(res):
    assert TOKEN not in json.dumps(res.to_dict()) and TOKEN not in render_html(res)


def test_profile_found_and_request_shape():
    c, fake = client((200, {"username": "Meta", "name": "Meta", "follower_count": 5, "is_verified": True,
                            "biography": "bio"}))
    res = c.profile("@meta")
    assert res.status is St.FOUND and res.items[0]["profile_url"] == "https://www.threads.com/@Meta"
    assert res.source_kind.value == "api" and res.endpoint == "https://graph.threads.net/v1.0/profile_lookup"
    q = parse_qs(urlsplit(fake.urls[0]).query)
    assert q["username"] == ["meta"] and q["access_token"] == [TOKEN] and "fields" in q
    assert any("tożsamości" in c for c in res.caveats)
    assert_no_token(res)


def test_profile_other_username_rejected():
    c, _ = client((200, {"username": "someoneelse"}))
    assert c.profile("meta").status is St.SOURCE_ERROR


def test_profile_empty_is_no_result_with_caveat():
    c, _ = client((200, {}))
    res = c.profile("meta")
    assert res.status is St.NO_RESULT and "nie dowodzi braku konta" in res.caveats[0]


def test_profile_code_100_is_source_error():
    c, _ = client((400, err(100, "Invalid parameter", 33)))
    res = c.profile("ghost_user")
    assert res.status is St.SOURCE_ERROR and res.error_code == 100 and res.exit_code == 1


def test_no_token_is_not_configured_and_sends_nothing():
    fake = Fake()
    res = ThreadsClient(Config(), transport=fake).profile("meta")
    assert res.status is St.NOT_CONFIGURED and fake.urls == [] and res.items == []
    assert res.exit_code == 3


@pytest.mark.parametrize("status,body,expected", [
    (400, err(190, f"Error validating access token {TOKEN}"), St.AUTH_ERROR),
    (401, {}, St.AUTH_ERROR),
    (400, err(10, "Application does not have permission"), St.PERMISSION_DENIED),
    (403, err(200), St.PERMISSION_DENIED),
    (429, {}, St.RATE_LIMITED),
    (400, err(4, "Application request limit reached"), St.RATE_LIMITED),
    (400, err(613), St.RATE_LIMITED),
    (404, b"<html>not json</html>", St.SOURCE_ERROR),
])
def test_error_mapping(status, body, expected):
    c, fake = client((status, body))
    res = c.profile("meta")
    assert res.status is expected and len(fake.urls) == 1   # bez ponowień przy limicie / autoryzacji
    assert_no_token(res)


def test_rate_limit_reports_retry_after():
    c, _ = client((429, {}, {"Retry-After": "60"}))
    assert "60" in c.profile("meta").message


def test_transient_error_retried_once_then_source_error():
    c, fake = client((None, b"", {}, "timeout"), (None, b"", {}, "timeout"))
    res = c.profile("meta")
    assert res.status is St.SOURCE_ERROR and "timeout" in res.message and len(fake.urls) == 2


def test_5xx_then_success():
    c, fake = client((500, {}), (200, {"username": "meta"}))
    assert c.profile("meta").status is St.FOUND and len(fake.urls) == 2


def test_invalid_inputs_send_nothing():
    c, fake = client()
    assert c.profile("ja kowalski").status is St.INVALID_INPUT
    assert c.profile("a" * 31).status is St.INVALID_INPUT
    assert c.search("").status is St.INVALID_INPUT
    assert c.search("x\ny").status is St.INVALID_INPUT
    assert c.search("x", limit=101).status is St.INVALID_INPUT
    assert c.search("x", search_type="ALL").status is St.INVALID_INPUT
    assert c.search("x", author="bad name").status is St.INVALID_INPUT
    assert fake.urls == []


def test_search_found_query_encoding_and_no_paging():
    c, fake = client((200, {"data": [{"id": "1", "text": "zażółć\x07", "username": "meta",
                                      "permalink": "https://www.threads.com/@meta/post/1", "timestamp": "t"},
                                     {"id": "2", "permalink": "javascript:alert(1)"}],
                            "paging": {"next": f"https://graph.threads.net/v1.0/keyword_search?access_token={TOKEN}"}}))
    res = c.search("zażółć & #tag", search_type="RECENT", limit=10, author="@meta")
    q = parse_qs(urlsplit(fake.urls[0]).query)
    assert q["q"] == ["zażółć & #tag"] and q["search_type"] == ["RECENT"] and q["author_username"] == ["meta"]
    assert res.status is St.FOUND and len(res.items) == 2 and len(fake.urls) == 1
    assert res.items[0]["text"] == "zażółć " and res.items[1]["permalink"] == ""
    assert any("threads_keyword_search" in x for x in res.caveats)
    assert_no_token(res)


def test_search_empty_is_no_result_and_bad_shape_is_error():
    c, _ = client((200, {"data": []}), (200, {"foo": 1}))
    assert c.search("abc").status is St.NO_RESULT
    assert c.search("abc").status is St.SOURCE_ERROR


def test_search_permission_denied_mentions_scope():
    c, _ = client((400, err(10)))
    res = c.search("abc")
    assert res.status is St.PERMISSION_DENIED and "threads_keyword_search" in res.message


def test_redact():
    assert TOKEN not in redact(f"bad https://x/?access_token={TOKEN}&a=1 {TOKEN}", TOKEN)
    assert "access_token=<REDACTED>" in redact("u?access_token=zzz", None)


def test_config_env_file_outside_repo_and_inside_repo(tmp_path, monkeypatch):
    f = tmp_path / "meta.env"
    f.write_text(f"# komentarz\nTHREADS_ACCESS_TOKEN={TOKEN}\nTHREADS_API_VERSION=v1.0\n", encoding="utf-8")
    cfg = load_config({"META_SEARCH_ENV_FILE": str(f)})
    assert cfg.threads_token == TOKEN and cfg.token_source.startswith("plik")
    assert TOKEN not in repr(cfg) and TOKEN not in json.dumps(cfg.describe())
    import meta_search.config as mc
    monkeypatch.setattr(mc, "REPO_ROOT", tmp_path)
    cfg = load_config({"META_SEARCH_ENV_FILE": str(f)})
    assert cfg.threads_token is None and "repozytorium" in cfg.problems[0]


def test_config_env_wins_and_validation(tmp_path):
    missing = str(tmp_path / "brak.env")
    assert load_config({"THREADS_ACCESS_TOKEN": TOKEN, "META_SEARCH_ENV_FILE": missing}).token_source == "env"
    cfg = load_config({"THREADS_ACCESS_TOKEN": "short", "THREADS_API_VERSION": "../x", "META_SEARCH_ENV_FILE": missing})
    assert cfg.threads_token is None and cfg.threads_version == "v1.0" and len(cfg.problems) == 3


def test_manual_links():
    res = manual_links("@nat.geo")
    assert res.status is St.MANUAL and {i["platform"] for i in res.items} == {"threads", "instagram", "facebook"}
    assert manual_links("a b").status is St.INVALID_INPUT


def test_report_escapes_api_values():
    c, _ = client((200, {"username": "meta", "name": "<script>alert(1)</script>", "biography": '"><img src=x>'}))
    html = render_html(c.profile("meta"))
    assert "<script>alert" not in html and "<img src=x>" not in html


def test_cli_not_configured_writes_json_and_html(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("THREADS_ACCESS_TOKEN", raising=False)
    monkeypatch.setenv("META_SEARCH_ENV_FILE", str(tmp_path / "brak.env"))
    j, h = tmp_path / "w.json", tmp_path / "w.html"
    code = cli.main(["threads-profile", "meta", "--json", str(j), "--html", str(h)])
    data = json.loads(j.read_text(encoding="utf-8"))
    assert code == 3 and data["status"] == "not_configured" and data["items"] == [] and data["tool"] == "meta-search"
    assert "wymaga konfiguracji" in h.read_text(encoding="utf-8")
    assert "wymaga konfiguracji" in capsys.readouterr().out


def test_cli_config_hides_token(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("THREADS_ACCESS_TOKEN", TOKEN)
    monkeypatch.setenv("META_SEARCH_ENV_FILE", str(tmp_path / "brak.env"))
    assert cli.main(["config"]) == 0
    out = capsys.readouterr().out
    assert TOKEN not in out and "ustawiony" in out
