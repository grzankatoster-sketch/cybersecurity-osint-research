import json
from urllib.parse import quote

import pytest

from meta_search.config import Config
from meta_search.contract import St
from meta_search.graph import https_url
from meta_search.threads import ThreadsClient
from fakes import Fake, TOKEN, assert_no_token, err


@pytest.mark.parametrize("body,expected", [(err(190), St.AUTH_ERROR), (err(10), St.PERMISSION_DENIED),
                                         ({"unexpected": "layout"}, St.SOURCE_ERROR),
                                         ({"data": "invalid"}, St.SOURCE_ERROR)])
def test_http_200_does_not_hide_error_or_schema_change(body, expected):
    result = ThreadsClient(Config(threads_token=TOKEN), transport=Fake((200, body))).profile("meta")
    assert result.status is expected and not result.items


def test_credentials_echoed_in_success_are_removed_before_export():
    secret = TOKEN + "+/="
    fake = Fake((200, {"username": "meta", "name": secret, "biography": quote(secret, safe=""),
                       "profile_picture_url": "https://cdn.example/x?access_token=" + secret}))
    result = ThreadsClient(Config(threads_token=secret), transport=fake).profile("meta")
    serialized = json.dumps(result.to_dict())
    assert secret not in serialized and quote(secret, safe="") not in serialized
    assert_no_token(result)


@pytest.mark.parametrize("url", ["https://", "https://user:pass@example.com/x", "https://x/\npath"])
def test_invalid_urls_are_not_exported(url):
    assert https_url(url) == ""


def test_nonempty_malformed_search_is_error_not_no_result():
    result = ThreadsClient(Config(threads_token=TOKEN), transport=Fake((200, {"data": [None]}))).search("x")
    assert result.status is St.SOURCE_ERROR
