"""Facebook Pages (Graph API) na fałszywym transporcie: tylko publiczne dane Strony, bez profili prywatnych."""
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from meta_search.config import Config
from meta_search.contract import St
from meta_search.facebook_pages import FacebookPagesClient
from fakes import ERROR_CASES, TOKEN, Fake, assert_no_token, err


def client(*responses, **cfg):
    fake = Fake(*responses)
    return FacebookPagesClient(Config(**({"facebook_token": TOKEN} | cfg)), transport=fake,
                               sleep=lambda s: None), fake


def page(**kw):
    data = {"id": "23497828950", "name": "National Geographic", "category": "Media", "link":
            "https://www.facebook.com/natgeo/", "fan_count": 50000000, "about": "o nas",
            "website": "https://natgeo.com", "verification_status": "blue_verified"}
    data.update(kw)
    return data


def test_page_found_and_request_shape():
    c, fake = client((200, page()))
    res = c.page("natgeo")
    assert res.status is St.FOUND and res.platform == "facebook" and res.operation == "facebook_page"
    item = res.items[0]
    assert item["type"] == "page" and item["id"] == "23497828950" and item["name"] == "National Geographic"
    assert item["category"] == "Media" and item["link"] == "https://www.facebook.com/natgeo/"
    assert item["fan_count"] == 50000000 and item["verification_status"] == "blue_verified"
    parts = urlsplit(fake.urls[0])
    assert parts.netloc == "graph.facebook.com" and parts.path == "/v26.0/natgeo"
    q = parse_qs(parts.query)
    assert q["fields"] == ["id,name,category,link,fan_count,about,website,verification_status"]
    assert q["access_token"] == [TOKEN]
    assert res.source_kind.value == "api" and res.endpoint == "https://graph.facebook.com/v26.0/{page-id}"
    text = " ".join(res.caveats)
    assert "Page Public Content Access" in text and "App Review" in text
    assert_no_token(res)


def test_numeric_id_must_match():
    c, _ = client((200, page()), (200, page(id="999")))
    assert c.page("23497828950").status is St.FOUND
    assert c.page("23497828950").status is St.SOURCE_ERROR


def test_response_that_is_not_a_page_is_rejected():
    """Węzeł osoby nie ma pól strony; odpowiedź bez category/fan_count nie może trafić do wyniku."""
    c, _ = client((200, {"id": "10000000000000001", "name": "Jan Kowalski"}), (200, {"name": "x"}), (200, []))
    for _ in range(3):
        res = c.page("10000000000000001")
        assert res.status is St.SOURCE_ERROR and res.items == []


def test_long_text_trimmed_and_unsafe_urls_dropped():
    c, _ = client((200, page(about="a" * 5000, website="javascript:alert(1)", link="ftp://x")))
    item = c.page("natgeo").items[0]
    assert len(item["about"]) <= 1000 and item["website"] == "" and item["link"] == ""


@pytest.mark.parametrize("code", [100, 803])
def test_ambiguous_object_error_is_not_a_successful_empty_result(code):
    c, fake = client((400, err(code, "Unsupported get request. Object does not exist", 33)))
    res = c.page("nieistniejaca.strona")
    assert res.status is St.SOURCE_ERROR and res.error_code == code and res.exit_code == 1 and len(fake.urls) == 1
    assert_no_token(res)


def test_not_configured_sends_nothing():
    fake = Fake()
    res = FacebookPagesClient(Config(), transport=fake).page("natgeo")
    assert res.status is St.NOT_CONFIGURED and fake.urls == [] and res.exit_code == 3
    assert "FACEBOOK_ACCESS_TOKEN" in res.message


def test_invalid_inputs_send_nothing():
    c, fake = client()
    for bad in ("", "a/b", "x?y=1", "a b", "a" * 101, "../me", "me&fields=email", "nat\ngeo", "%2e", "@@", "..", ".", "-x"):
        assert c.page(bad).status is St.INVALID_INPUT, bad
    assert fake.urls == []


def test_at_sign_and_surrounding_space_stripped():
    c, fake = client((200, page()))
    c.page("  @natgeo ")
    assert urlsplit(fake.urls[0]).path == "/v26.0/natgeo"


@pytest.mark.parametrize("status,body,expected", ERROR_CASES)
def test_error_mapping(status, body, expected):
    c, fake = client((status, body))
    res = c.page("natgeo")
    assert res.status is expected and len(fake.urls) == 1
    assert_no_token(res)


def test_permission_error_mentions_page_public_content_access():
    c, _ = client((400, err(10, "This endpoint requires the 'Page Public Content Access' feature")))
    res = c.page("natgeo")
    assert res.status is St.PERMISSION_DENIED and "Page Public Content Access" in res.message


def test_transient_error_retried_once():
    c, fake = client((500, {}), (200, page()))
    assert c.page("natgeo").status is St.FOUND and len(fake.urls) == 2


def test_graph_version_from_config():
    c, fake = client((200, page()), graph_version="v24.0")
    res = c.page("natgeo")
    assert urlsplit(fake.urls[0]).path == "/v24.0/natgeo" and res.api_version == "v24.0"
    assert json.loads(json.dumps(res.to_dict()))["source"]["api_version"] == "v24.0"
