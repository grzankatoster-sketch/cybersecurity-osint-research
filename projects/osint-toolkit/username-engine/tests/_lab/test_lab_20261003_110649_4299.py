import asyncio
from urllib.parse import unquote, urlsplit

from username_engine.engine import check_site
from username_engine.models import Response, Site, Status

NAME = "a/b?c#d"


class FakeFetcher:
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    async def fetch(self, method, url, headers=None, body=None):
        self.calls.append((method, url, body))
        return self.handler(url)


def _assert_single_segment(url: str) -> None:
    parts = urlsplit(url)
    assert parts.netloc == "ex.com"
    assert parts.query == "", f"nazwa przeciekla do query: {url!r}"
    assert parts.fragment == "", f"nazwa przeciekla do fragmentu: {url!r}"
    assert parts.path.startswith("/u/"), url
    segment = parts.path[len("/u/"):]
    assert "/" not in segment, f"nazwa zmienila sciezke: {url!r}"
    assert unquote(segment) == NAME


def test_profile_url_encodes_reserved_characters():
    site = Site(name="Ex", url="https://ex.com/u/{username}")
    _assert_single_segment(site.profile_url(NAME))


def test_request_url_encodes_reserved_characters():
    site = Site(name="Ex", url="https://ex.com/profile/{username}", probe_url="https://ex.com/u/{username}")
    _assert_single_segment(site.request_url(NAME))


def test_engine_queries_encoded_url_but_keeps_body_raw():
    site = Site(
        name="Ex",
        url="https://ex.com/u/{username}",
        method="POST",
        body='{"user": "{username}"}',
        e_strings=["profile-ok"],
    )

    def handler(url):
        return Response(status=200, text="profile-ok", final_url=url)

    fetcher = FakeFetcher(handler)
    result = asyncio.run(check_site(site, NAME, fetcher, control="none"))
    assert fetcher.calls, "brak zapytania"
    method, url, body = fetcher.calls[0]
    _assert_single_segment(url)
    assert body == '{"user": "a/b?c#d"}'
    _assert_single_segment(result.url)
    assert result.status is Status.FOUND
