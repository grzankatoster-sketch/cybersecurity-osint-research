import asyncio

from username_engine.engine import scan, summarize
from username_engine.models import Response, Site, Status


class FakeFetcher:
    """Serwis 'bad' rzuca CancelledError (anulowanie wewnatrz fetchera), reszta odpowiada normalnie."""

    def __init__(self):
        self.calls = []

    async def fetch(self, method, url, headers=None, body=None):
        self.calls.append(url)
        if "bad.example" in url:
            raise asyncio.CancelledError()
        return Response(status=200, text="profile-ok alice", final_url=url)


def _sites():
    return [
        Site(name="Good1", url="https://good1.example/u/{username}", e_strings=["profile-ok"]),
        Site(name="Bad", url="https://bad.example/u/{username}", e_strings=["profile-ok"]),
        Site(name="Good2", url="https://good2.example/u/{username}", e_strings=["profile-ok"]),
    ]


def test_cancelled_fetch_becomes_error_result_and_is_counted():
    fetcher = FakeFetcher()
    try:
        results = asyncio.run(scan("alice", _sites(), fetcher, control="none"))
    except BaseException as e:  # CancelledError nie dziedziczy po Exception
        results = None
        escaped = type(e).__name__
    else:
        escaped = None

    assert results is not None, f"skan przerwany przez {escaped} z jednego serwisu - wszystkie wyniki utracone"
    assert len(results) == 3, "kazdy serwis musi miec wynik"
    by_site = {r.site: r for r in results}
    assert set(by_site) == {"Good1", "Bad", "Good2"}
    assert by_site["Bad"].status is Status.ERROR
    assert by_site["Good1"].status is Status.FOUND
    assert by_site["Good2"].status is Status.FOUND

    s = summarize(results)
    assert s["checked"] == 3
    assert s["error"] == 1
    assert s["found"] == 2
    assert s["not_found"] == 0
