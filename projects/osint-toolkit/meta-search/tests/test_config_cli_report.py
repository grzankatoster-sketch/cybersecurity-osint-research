"""Konfiguracja trzech źródeł, CLI i raport dla Instagrama / stron Facebooka (atrapa transportu, bez sieci)."""
import json

import pytest

from meta_search import cli, graph
from meta_search.config import load_config
from meta_search.report import render_html
from fakes import IG_ID, TOKEN, Fake

ENV_KEYS = ("THREADS_ACCESS_TOKEN", "INSTAGRAM_ACCESS_TOKEN", "INSTAGRAM_USER_ID", "FACEBOOK_ACCESS_TOKEN",
            "GRAPH_API_VERSION", "THREADS_API_VERSION")


@pytest.fixture
def clean_env(monkeypatch, tmp_path):
    for k in ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("META_SEARCH_ENV_FILE", str(tmp_path / "brak.env"))
    return monkeypatch


def test_config_reads_graph_keys_from_env():
    env = {"INSTAGRAM_ACCESS_TOKEN": TOKEN, "INSTAGRAM_USER_ID": IG_ID, "FACEBOOK_ACCESS_TOKEN": TOKEN + "x",
           "GRAPH_API_VERSION": "v24.0", "META_SEARCH_ENV_FILE": "brak.env"}
    cfg = load_config(env)
    assert (cfg.instagram_token, cfg.instagram_user_id, cfg.facebook_token) == (TOKEN, IG_ID, TOKEN + "x")
    assert cfg.graph_version == "v24.0" and cfg.threads_token is None
    assert cfg.token_sources == {"instagram": "env", "facebook": "env"}


def test_config_reads_graph_keys_from_file_outside_repo(tmp_path):
    f = tmp_path / "meta.env"
    f.write_text(f"INSTAGRAM_ACCESS_TOKEN={TOKEN}\nINSTAGRAM_USER_ID={IG_ID}\nFACEBOOK_ACCESS_TOKEN={TOKEN}\n",
                 encoding="utf-8")
    cfg = load_config({"META_SEARCH_ENV_FILE": str(f)})
    assert cfg.instagram_token == TOKEN and cfg.facebook_token == TOKEN and cfg.instagram_user_id == IG_ID
    assert cfg.token_sources["instagram"].startswith("plik") and cfg.token_sources["facebook"].startswith("plik")


def test_config_rejects_bad_values():
    cfg = load_config({"INSTAGRAM_ACCESS_TOKEN": "short", "INSTAGRAM_USER_ID": "abc/../1",
                       "FACEBOOK_ACCESS_TOKEN": "has space in token value 1234567890", "GRAPH_API_VERSION": "../x",
                       "META_SEARCH_ENV_FILE": "brak.env"})
    assert cfg.instagram_token is None and cfg.instagram_user_id is None and cfg.facebook_token is None
    assert cfg.graph_version == "v26.0" and len(cfg.problems) == 5   # plik + 4 błędne wartości
    assert not cfg.token_sources


def test_describe_shows_all_sources_without_values():
    cfg = load_config({"THREADS_ACCESS_TOKEN": TOKEN, "INSTAGRAM_ACCESS_TOKEN": TOKEN, "INSTAGRAM_USER_ID": IG_ID,
                       "META_SEARCH_ENV_FILE": "brak.env"})
    text = json.dumps(cfg.describe(), ensure_ascii=False)
    assert TOKEN not in text and IG_ID not in text and repr(cfg).count(TOKEN) == 0
    src = cfg.describe()["sources"]
    assert src["threads"]["configured"] is True
    assert src["instagram"]["configured"] is True and src["instagram"]["user_id"] == "ustawiony"
    assert src["facebook"]["configured"] is False and src["facebook"]["token"] == "brak"
    only_token = load_config({"INSTAGRAM_ACCESS_TOKEN": TOKEN, "META_SEARCH_ENV_FILE": "brak.env"})
    assert only_token.describe()["sources"]["instagram"]["configured"] is False   # brak IG user id


def test_cli_config_lists_three_sources(clean_env, capsys):
    clean_env.setenv("FACEBOOK_ACCESS_TOKEN", TOKEN)
    assert cli.main(["config"]) == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert set(data["sources"]) == {"threads", "instagram", "facebook"} and TOKEN not in out
    assert data["sources"]["facebook"]["configured"] is True


@pytest.mark.parametrize("argv,op", [(["instagram-profile", "natgeo"], "instagram_profile"),
                                     (["facebook-page", "natgeo"], "facebook_page")])
def test_cli_not_configured_writes_json_and_html(clean_env, tmp_path, capsys, argv, op):
    j, h = tmp_path / "w.json", tmp_path / "w.html"
    code = cli.main(argv + ["--json", str(j), "--html", str(h)])
    data = json.loads(j.read_text(encoding="utf-8"))
    assert code == 3 and data["status"] == "not_configured" and data["operation"] == op and data["items"] == []
    assert "wymaga konfiguracji" in h.read_text(encoding="utf-8")


def _patch_transport(monkeypatch, *responses):
    fake = Fake(*responses)
    monkeypatch.setattr(graph, "urllib_transport", fake)
    return fake


def test_cli_instagram_profile_with_media_end_to_end(clean_env, tmp_path, capsys):
    clean_env.setenv("INSTAGRAM_ACCESS_TOKEN", TOKEN)
    clean_env.setenv("INSTAGRAM_USER_ID", IG_ID)
    fake = _patch_transport(clean_env, (200, {"business_discovery": {
        "username": "natgeo", "name": "NG", "followers_count": 5, "media_count": 2, "id": "1",
        "media": {"data": [{"id": "9", "caption": "podpis", "permalink": "https://www.instagram.com/p/X/",
                            "timestamp": "2026-10-01T00:00:00+0000"}]}}}))
    j = tmp_path / "w.json"
    code = cli.main(["instagram-profile", "natgeo", "--media", "1", "--json", str(j)])
    out = capsys.readouterr().out
    data = json.loads(j.read_text(encoding="utf-8"))
    assert code == 0 and data["status"] == "found" and [i["type"] for i in data["items"]] == ["profile", "post"]
    assert "@natgeo" in out and "instagram.com/p/X" in out and TOKEN not in out + json.dumps(data)
    assert len(fake.urls) == 1


def test_cli_facebook_page_end_to_end(clean_env, tmp_path, capsys):
    clean_env.setenv("FACEBOOK_ACCESS_TOKEN", TOKEN)
    _patch_transport(clean_env, (200, {"id": "1", "name": "Strona", "category": "Media", "fan_count": 10,
                                       "link": "https://www.facebook.com/x/"}))
    code = cli.main(["facebook-page", "x"])
    out = capsys.readouterr().out
    assert code == 0 and "Strona" in out and "Media" in out and "facebook.com/x" in out and TOKEN not in out


def test_cli_exit_code_for_graph_errors(clean_env, capsys):
    clean_env.setenv("FACEBOOK_ACCESS_TOKEN", TOKEN)
    _patch_transport(clean_env, (400, {"error": {"code": 190, "message": f"bad {TOKEN}"}}))
    assert cli.main(["facebook-page", "x"]) == 4
    assert TOKEN not in capsys.readouterr().out


def test_report_renders_instagram_profile_and_posts_in_separate_tables(clean_env):
    from meta_search.config import Config
    from meta_search.instagram import InstagramClient
    c = InstagramClient(Config(instagram_token=TOKEN, instagram_user_id=IG_ID), sleep=lambda s: None,
                        transport=Fake((200, {"business_discovery": {
                            "username": "natgeo", "name": "<script>alert(1)</script>", "website": "https://natgeo.com",
                            "followers_count": 5, "media": {"data": [{"id": "1", "caption": '"><img src=x>',
                                                                      "permalink": "https://www.instagram.com/p/A/"}]}}})))
    html = render_html(c.profile("natgeo", media=1))
    assert html.count("<table>") == 2 and "<script>alert" not in html and "<img src=x>" not in html
    assert "oficjalne API" in html and "natgeo.com" in html and TOKEN not in html


def test_report_renders_facebook_page_escaped():
    from meta_search.config import Config
    from meta_search.facebook_pages import FacebookPagesClient
    c = FacebookPagesClient(Config(facebook_token=TOKEN), sleep=lambda s: None, transport=Fake((200, {
        "id": "1", "name": "<b>x</b>", "category": "Media", "about": "<img src=x>", "link": "https://www.facebook.com/x/",
        "verification_status": "blue_verified", "fan_count": 3})))
    html = render_html(c.page("x"))
    assert "<b>x</b>" not in html and "<img src=x>" not in html and "&lt;b&gt;x&lt;/b&gt;" in html
    assert "Strona" in html and "Kategoria" in html
