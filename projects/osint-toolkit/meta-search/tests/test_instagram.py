"""Instagram Business Discovery na fałszywym transporcie: kontrakt wyniku, klasyfikacja błędów, brak sekretów."""
import json
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from meta_search.config import Config
from meta_search.contract import St
from meta_search.instagram import InstagramClient
from fakes import ERROR_CASES, IG_ID, TOKEN, Fake, assert_no_token, err

CFG = dict(instagram_token=TOKEN, instagram_user_id=IG_ID)


def client(*responses, **cfg):
    fake = Fake(*responses)
    return InstagramClient(Config(**{**CFG, **cfg}), transport=fake, sleep=lambda s: None), fake


def bd(**kw):
    data = {"username": "natgeo", "name": "National Geographic", "biography": "bio", "followers_count": 1000,
            "media_count": 5, "website": "https://natgeo.com", "profile_picture_url": "https://cdn.example/p.jpg",
            "id": "17841400999999999"}
    data.update(kw)
    return {"business_discovery": data, "id": IG_ID}


def test_profile_found_and_request_shape():
    c, fake = client((200, bd()))
    res = c.profile("@NatGeo")
    assert res.status is St.FOUND and res.platform == "instagram" and res.operation == "instagram_profile"
    item = res.items[0]
    assert item["type"] == "profile" and item["profile_url"] == "https://www.instagram.com/natgeo/"
    assert item["follower_count"] == 1000 and item["media_count"] == 5 and item["website"] == "https://natgeo.com"
    parts = urlsplit(fake.urls[0])
    assert parts.path == f"/v26.0/{IG_ID}" and parts.netloc == "graph.facebook.com"
    q = parse_qs(parts.query)
    fields = q["fields"][0]
    assert fields.startswith("business_discovery.username(NatGeo){") and "followers_count" in fields
    assert "media.limit" not in fields and q["access_token"] == [TOKEN]
    assert res.source_kind.value == "api" and IG_ID not in res.endpoint and "{ig-user-id}" in res.endpoint
    assert any("tożsamości" in x for x in res.caveats) and any("profesjonaln" in x for x in res.caveats)
    assert_no_token(res)
    assert IG_ID not in json.dumps(res.to_dict())


def test_media_limit_and_items():
    media = {"data": [
        {"id": "1", "caption": "podpis\x07tekst", "media_type": "IMAGE", "permalink": "https://www.instagram.com/p/A/",
         "timestamp": "2026-10-01T10:00:00+0000", "like_count": 7, "comments_count": 2},
        {"id": "2", "permalink": "javascript:alert(1)"},
    ], "paging": {"cursors": {"after": "x"}}}
    c, fake = client((200, bd(media=media)))
    res = c.profile("natgeo", media=3)
    assert "media.limit(3){" in parse_qs(urlsplit(fake.urls[0]).query)["fields"][0]
    posts = [i for i in res.items if i["type"] == "post"]
    assert res.items[0]["type"] == "profile" and len(posts) == 2 and len(fake.urls) == 1
    assert posts[0]["username"] == "natgeo" and posts[0]["text"] == "podpis tekst" and posts[0]["like_count"] == 7
    assert posts[1]["permalink"] == ""
    assert_no_token(res)


def test_media_over_requested_limit_is_cut():
    rows = [{"id": str(n), "permalink": f"https://www.instagram.com/p/{n}/"} for n in range(6)]
    c, _ = client((200, bd(media={"data": rows})))
    assert len([i for i in c.profile("natgeo", media=2).items if i["type"] == "post"]) == 2


def test_other_username_rejected():
    c, _ = client((200, bd(username="ktos_inny")))
    assert c.profile("natgeo").status is St.SOURCE_ERROR


@pytest.mark.parametrize("body", [{"id": IG_ID}, {"business_discovery": []}, {"business_discovery": {"name": "x"}},
                                  b"[]"])
def test_bad_shape_is_source_error(body):
    c, _ = client((200, body))
    assert c.profile("natgeo").status is St.SOURCE_ERROR


@pytest.mark.parametrize("code,sub", [(110, 2207013), (100, 2207013), (100, None), (110, None), (24, 2207013)])
def test_ambiguous_errors_are_not_successful_empty_results(code, sub):
    c, fake = client((400, err(code, "Invalid user id", sub)))
    res = c.profile("prywatne_konto")
    assert res.status is St.SOURCE_ERROR and res.error_code == code and res.exit_code == 1 and len(fake.urls) == 1
    assert_no_token(res)


def test_not_configured_sends_nothing():
    for cfg in (Config(), Config(instagram_token=TOKEN), Config(instagram_user_id=IG_ID)):
        fake = Fake()
        res = InstagramClient(cfg, transport=fake).profile("natgeo")
        assert res.status is St.NOT_CONFIGURED and fake.urls == [] and res.items == [] and res.exit_code == 3
    assert "INSTAGRAM_USER_ID" in InstagramClient(Config(instagram_token=TOKEN), transport=Fake()).profile("a").message


def test_invalid_inputs_send_nothing():
    c, fake = client()
    for nick in ("ja kowalski", "a" * 31, "", "a)b", "x{y}"):
        assert c.profile(nick).status is St.INVALID_INPUT
    for media in (-1, 51, "5", True):
        assert c.profile("natgeo", media=media).status is St.INVALID_INPUT
    assert fake.urls == []


@pytest.mark.parametrize("status,body,expected", ERROR_CASES)
def test_error_mapping(status, body, expected):
    c, fake = client((status, body))
    res = c.profile("natgeo")
    assert res.status is expected and len(fake.urls) == 1
    assert_no_token(res)


def test_permission_error_names_required_permissions():
    c, _ = client((400, err(10)))
    assert "instagram_basic" in c.profile("natgeo").message


def test_rate_limit_reports_retry_after():
    c, _ = client((429, {}, {"Retry-After": "120"}))
    assert "120" in c.profile("natgeo").message


def test_transient_error_retried_once():
    c, fake = client((None, b"", {}, "timeout"), (None, b"", {}, "timeout"))
    res = c.profile("natgeo")
    assert res.status is St.SOURCE_ERROR and len(fake.urls) == 2
    c, fake = client((500, {}), (200, bd()))
    assert c.profile("natgeo").status is St.FOUND and len(fake.urls) == 2


def test_query_with_special_characters_is_encoded():
    c, fake = client((200, bd(username="a.b_c")))
    c.profile("a.b_c")
    assert "business_discovery.username(a.b_c)" in unquote(urlsplit(fake.urls[0]).query)
    assert "{" not in urlsplit(fake.urls[0]).query
