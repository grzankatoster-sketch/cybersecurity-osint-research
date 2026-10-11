"""Wspólna atrapa transportu i pomocnicy testów klientów Graph API (bez sieci, bez prawdziwych tokenów)."""
import json

from meta_search.contract import St
from meta_search.report import render_html

TOKEN = "TESTTOKEN_abcdefghijklmnopqrstuvwxyz_0123"
IG_ID = "17841400000000000"


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


def err(code, msg="x", sub=None):
    e = {"message": msg, "type": "OAuthException", "code": code}
    if sub:
        e["error_subcode"] = sub
    return {"error": e}


def assert_no_token(res):
    assert TOKEN not in json.dumps(res.to_dict()) and TOKEN not in render_html(res)


# wspólna tabela klasyfikacji błędów: (HTTP, treść, oczekiwany status)
ERROR_CASES = [
    (400, err(190, f"Error validating access token {TOKEN}"), St.AUTH_ERROR),
    (401, {}, St.AUTH_ERROR),
    (400, err(10, "Application does not have permission"), St.PERMISSION_DENIED),
    (403, err(200), St.PERMISSION_DENIED),
    (429, {}, St.RATE_LIMITED),
    (400, err(4, "Application request limit reached"), St.RATE_LIMITED),
    (400, err(613), St.RATE_LIMITED),
    (400, err(80002, "Instagram request limit"), St.RATE_LIMITED),
    (404, b"<html>not json</html>", St.SOURCE_ERROR),
    (400, err(9999, "dziwny błąd"), St.SOURCE_ERROR),
]
