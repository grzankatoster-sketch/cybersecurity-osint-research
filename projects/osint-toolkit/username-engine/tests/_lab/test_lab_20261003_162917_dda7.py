"""NOT_FOUND jednoznaczny (reguła wprost potwierdziła brak konta) vs domyślny (brak dopasowania)."""
import asyncio

from username_engine.classify import NEGATIVE_MATCH, NO_MATCH_DEFAULT, classify, not_found_kind
from username_engine.engine import check_site, scan, summarize
from username_engine.models import Response, Result, Site, Status


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


def const(status, text=""):
    return FakeFetcher(lambda url: Response(status, text, final_url=url))


def test_constants_values():
    assert NEGATIVE_MATCH == "negative_match"
    assert NO_MATCH_DEFAULT == "no_match_default"


def test_negative_text_match_is_explicit():
    s = Site("Neg", "https://neg.example/{username}", e_strings=["avatar"], m_strings=["User not found"])
    r = run(check_site(s, "alice", const(200, "<p>User not found</p>")))
    assert r.status is Status.NOT_FOUND
    assert r.not_found_kind == "negative_match"
    assert r.to_dict()["not_found_kind"] == "negative_match"


def test_neutral_page_without_any_match_is_default():
    s = Site("Neu", "https://neu.example/{username}", e_strings=["avatar"])
    r = run(check_site(s, "alice", const(200, "<html>home</html>")))
    assert r.status is Status.NOT_FOUND
    assert r.not_found_kind == "no_match_default"
    assert r.to_dict()["not_found_kind"] == "no_match_default"


def test_negative_code_match_is_explicit():
    s = Site("Code", "https://code.example/{username}", e_code=200, m_code=404)
    r = run(check_site(s, "alice", const(404, "nope")))
    assert r.status is Status.NOT_FOUND and r.not_found_kind == "negative_match"


def test_code_mismatch_without_m_code_is_default():
    s = Site("Mis", "https://mis.example/{username}", e_code=200, e_strings=["avatar"])
    r = run(check_site(s, "alice", const(404, "nope")))
    assert r.status is Status.NOT_FOUND and r.not_found_kind == "no_match_default"


def test_redirect_away_is_default():
    s = Site("Red", "https://red.example/{username}", check_type="status_code")
    f = FakeFetcher(lambda url: Response(200, "welcome", final_url="https://red.example/"))
    r = run(check_site(s, "alice", f, control="none"))
    assert r.status is Status.NOT_FOUND and r.not_found_kind == "no_match_default"


def test_soft404_via_control_is_default():
    page = "<html>no such page</html>" + "z" * 600
    s = Site("Soft", "https://soft.example/{username}", check_type="status_code")
    r = run(check_site(s, "alice", const(200, page)))
    assert r.status is Status.NOT_FOUND and r.not_found_kind == "no_match_default"


def test_found_and_error_have_no_kind_and_no_json_key():
    found = run(check_site(Site("F", "https://f.example/{username}", e_strings=["avatar"]), "alice",
                           FakeFetcher(lambda url: Response(200, "avatar alice" if url.endswith("/alice") else "x",
                                                            final_url=url))))
    assert found.status is Status.FOUND
    assert found.not_found_kind is None and "not_found_kind" not in found.to_dict()
    err = run(check_site(Site("E", "https://e.example/{username}", e_strings=["avatar"]), "alice",
                         FakeFetcher(lambda url: Response(None, error="timeout"))))
    assert err.status is Status.ERROR
    assert err.not_found_kind is None and "not_found_kind" not in err.to_dict()


def test_error_logic_unchanged_unrecognized_page_stays_error():
    """Reguła zna oba teksty, strona nie pasuje do żadnego -> nadal ERROR, bez pola NOT_FOUND."""
    s = Site("Both", "https://both.example/{username}", e_strings=["avatar"], m_strings=["User not found"])
    r = run(check_site(s, "alice", const(200, "<html>Please wait</html>")))
    assert r.status is Status.ERROR and r.not_found_kind is None


def test_429_with_negative_text_stays_error():
    s = Site("Lim", "https://lim.example/{username}", e_strings=["avatar"], m_strings=["User not found"])
    r = run(check_site(s, "alice", const(429, "User not found")))
    assert r.status is Status.ERROR and r.not_found_kind is None


def test_not_found_kind_function_direct():
    assert not_found_kind(Status.NOT_FOUND, "tekst braku konta") == NEGATIVE_MATCH
    assert not_found_kind(Status.NOT_FOUND, "kod braku konta (404)") == NEGATIVE_MATCH
    assert not_found_kind(Status.NOT_FOUND, "brak tekstu obecności konta") == NO_MATCH_DEFAULT
    assert not_found_kind(Status.NOT_FOUND, "kod 404") == NO_MATCH_DEFAULT
    assert not_found_kind(Status.ERROR, "tekst braku konta") is None
    assert not_found_kind(Status.FOUND, "tekst obecności konta") is None
    assert not_found_kind(Status.UNSUPPORTED, "nazwa niezgodna z formatem serwisu") is None


def test_classify_still_returns_three_tuple():
    s = Site("Neg", "https://neg.example/{username}", e_strings=["avatar"], m_strings=["User not found"])
    out = classify(s, Response(200, "User not found", final_url="https://neg.example/alice"), "alice")
    assert len(out) == 3 and out[0] is Status.NOT_FOUND


def test_result_default_kind_none_positional_constructor_unchanged():
    r = Result("S", "https://s.example/a", Status.NOT_FOUND, 0.0, "kod 404", 404, {})
    assert r.not_found_kind is None and "not_found_kind" not in r.to_dict()


def test_summarize_counts_explicit_not_found():
    def handler(url):
        if "neg.example" in url:
            return Response(200, "User not found", final_url=url)
        if "down.example" in url:
            return Response(None, error="timeout")
        return Response(200, "<html>home</html>", final_url=url)

    sites = [Site("Neg", "https://neg.example/{username}", e_strings=["avatar"], m_strings=["User not found"]),
             Site("Neu", "https://neu.example/{username}", e_strings=["avatar"]),
             Site("Down", "https://down.example/{username}", e_strings=["avatar"], m_strings=["User not found"])]
    s = summarize(run(scan("alice", sites, FakeFetcher(handler))))
    assert s["not_found"] == 2 and s["error"] == 1
    assert s["not_found_explicit"] == 1
