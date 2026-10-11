"""Wspólna warstwa Graph API: brak przekierowań, limit rozmiaru odpowiedzi, redakcja tokenu."""
import io
import urllib.request

from meta_search import graph, threads
from meta_search.graph import MAX_BODY, redact
from fakes import TOKEN


def test_redirects_are_never_followed():
    req = urllib.request.Request("https://graph.facebook.com/v23.0/x?access_token=" + TOKEN)
    assert graph._NoRedirect().redirect_request(req, None, 302, "Found", {}, "https://evil.example/") is None


class _Resp:
    def __init__(self, size):
        self.code, self.headers, self._raw = 200, {"A": "b"}, io.BytesIO(b"x" * size)

    def read(self, n=-1):
        return self._raw.read(n)


def test_oversized_response_is_cut_off():
    status, _, body, err = graph._read_response(_Resp(MAX_BODY + 10))
    assert body == b"" and "limit rozmiaru" in err
    status, _, body, err = graph._read_response(_Resp(100))
    assert status == 200 and len(body) == 100 and err is None


def test_redact_removes_token_everywhere():
    text = redact(f"https://x/?fields=a&access_token={TOKEN}&b=1 oraz {TOKEN}", TOKEN)
    assert TOKEN not in text and "access_token=<REDACTED>" in text
    assert redact("a", None) == "a"


def test_threads_reexports_shared_helpers():
    assert threads.redact is graph.redact and threads.USERNAME is graph.USERNAME
