import asyncio

from username_engine.engine import check_site, needs_control, random_name, scan, summarize
from username_engine.models import Response, Site, Status


class FakeFetcher:
    """Odpowiada wg funkcji (url -> Response); zapisuje wykonane zapytania."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    async def fetch(self, method, url, headers=None, body=None):
        self.calls.append(url)
        return self.handler(url)


def run(coro):
    return asyncio.run(coro)


def test_random_name_shape():
    n = random_name()
    assert len(n) == 14 and n[0].isalpha() and n.islower()


def test_regex_mismatch_is_unsupported_without_request():
    f = FakeFetcher(lambda url: Response(200, "x"))
    s = Site("Gh", "https://gh.com/{username}", regex=r"^[a-z]+$", e_strings=["x"])
    r = run(check_site(s, "Bad Name!", f))
    assert r.status is Status.UNSUPPORTED and f.calls == []


def test_control_only_for_weak_rules_in_auto():
    assert needs_control(Site("a", "u", e_strings=[]), "auto")
    assert not needs_control(Site("a", "u", e_strings=["x"]), "auto")
    assert needs_control(Site("a", "u", e_strings=["x"]), "all")
    assert not needs_control(Site("a", "u"), "none")


def test_weak_rule_soft404_rejected_via_control():
    page = "<html>no such page</html>" + "z" * 600
    f = FakeFetcher(lambda url: Response(200, page, final_url=url))
    s = Site("Soft", "https://soft.com/{username}", check_type="status_code")
    r = run(check_site(s, "alice", f))
    assert len(f.calls) == 2                    # zapytanie właściwe + kontrolne
    assert r.status is Status.NOT_FOUND


def test_lazy_control_catches_rule_matching_any_name():
    """Wiki z pomiaru 03.10.2026: reguła tekstowa pasowała do każdej nazwy -> nie może być FOUND."""
    f = FakeFetcher(lambda url: Response(200, "<div class=user-page>Utilisateur</div>", final_url=url))
    s = Site("Wiki", "https://wiki.example/User:{username}", e_strings=["user-page"])
    r = run(check_site(s, "Sampler51", f))
    assert len(f.calls) == 2 and r.status is Status.ERROR and "niewiarygodna" in r.reason


def test_lazy_control_only_after_hit():
    f = FakeFetcher(lambda url: Response(404, "nope", final_url=url))
    run(check_site(Site("X", "https://x.com/{username}", e_strings=["avatar"]), "alice", f))
    assert len(f.calls) == 1                     # brak trafienia -> brak dodatkowego zapytania


def test_search_endpoint_requires_exact_name():
    body = '{"accounts":[{"acct":"X-51@pixelfed.social"},{"acct":"hitman51@misskey.io"}]}'
    s = Site("Masto", "https://m.social/api/v2/search?q={username}&type=accounts", e_strings=['"acct"'])
    f = FakeFetcher(lambda url: Response(200, body, final_url=url))
    assert run(check_site(s, "sampler.51", f)).status is Status.NOT_FOUND
    f2 = FakeFetcher(lambda url: Response(200, '{"acct":"sampler.51"}' if "sampler" in url else "{}", final_url=url))
    assert run(check_site(s, "sampler.51", f2)).status is Status.FOUND


def test_exception_in_site_becomes_error_and_scan_continues():
    def handler(url):
        if "boom" in url:
            raise RuntimeError("x")
        return Response(200, "avatar" if url.endswith("/alice") else "nic", final_url=url)

    sites = [Site("Boom", "https://boom.com/{username}", e_strings=["avatar"]),
             Site("Ok", "https://ok.com/{username}", e_strings=["avatar"])]
    results = {r.site: r for r in run(scan("alice", sites, FakeFetcher(handler)))}
    assert results["Boom"].status is Status.ERROR and "wyjątek" in results["Boom"].reason
    assert results["Ok"].status is Status.FOUND


def test_summary_counts_and_errors():
    def handler(url):
        if "down" in url:
            return Response(None, error="timeout")
        return Response(200, "avatar" if url.endswith("/alice") else "nic", final_url=url)

    sites = [Site("Down", "https://down.com/{username}", e_strings=["avatar"]),
             Site("Up", "https://up.com/{username}", e_strings=["avatar"]),
             Site("Re", "https://re.com/{username}", regex=r"^\d+$", e_strings=["avatar"])]
    s = summarize(run(scan("alice", sites, FakeFetcher(handler))))
    assert (s["checked"], s["found"], s["error"], s["unsupported"]) == (3, 1, 1, 1)
    assert s["top_errors"] == [("timeout", 1)]


def test_on_result_callback_called_for_each():
    seen = []
    sites = [Site(f"S{i}", f"https://s{i}.com/{{username}}", e_strings=["a"]) for i in range(5)]
    run(scan("alice", sites, FakeFetcher(lambda u: Response(200, "a", final_url=u)), on_result=seen.append))
    assert len(seen) == 5
