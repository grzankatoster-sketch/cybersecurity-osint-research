"""Klient oficjalnego Threads API (graph.threads.net): profil publiczny po nicku i wyszukiwanie publicznych postów.

Dokumentacja (sprawdzona 03.10.2026):
- profile_lookup: https://developers.facebook.com/docs/threads/threads-profiles
  uprawnienia threads_basic + threads_profile_discovery; tylko publiczne profile z >= 100 obserwujących;
  bez zaawansowanego dostępu tylko konta Meta (@meta, @threads, @instagram, @facebook); 1000 zapytań / 24 h.
- keyword_search: https://developers.facebook.com/docs/threads/keyword-search
  threads_basic + threads_keyword_search; bez zatwierdzenia uprawnienia szuka TYLKO w postach właściciela tokenu;
  2200 zapytań / 24 h (zapytania bez wyników się nie liczą); limit 1-100.
Kody błędów Threads nie są osobno opisane - mapowanie wg ogólnej konwencji Graph API (190, 10, 200-299, 4/17/32/613,
100). Brak automatycznego przejścia na scrapowanie po błędzie autoryzacji; kolejnych stron (paging) nie pobieramy.
"""
from __future__ import annotations

from .contract import IDENTITY_CAVEAT, MetaResult, St
from .graph import CONTROL, MAX_TEXT, USERNAME, GraphClient, clean, error_info, https_url, json_body, redact  # noqa: F401

BASE = "https://graph.threads.net"
PROFILE_FIELDS = "username,name,biography,is_verified,follower_count,profile_picture_url"
SEARCH_FIELDS = "id,text,media_type,permalink,timestamp,username,is_reply,is_quote_post"
MAX_QUERY = 200

PROFILE_NO_RESULT = ("Brak wyniku nie dowodzi braku konta: API zwraca tylko publiczne profile z co najmniej 100 "
                     "obserwującymi, a bez zaawansowanego dostępu (App Review) wyłącznie konta Meta.")
SEARCH_SCOPE = ("Bez zatwierdzonego uprawnienia threads_keyword_search API przeszukuje tylko posty właściciela "
                "tokenu, a nie wszystkie publiczne posty.")


class ThreadsClient(GraphClient):
    platform, base = "threads", BASE
    permissions = {"threads_profile": "threads_basic + threads_profile_discovery",
                   "threads_search": "threads_basic + threads_keyword_search"}

    @property
    def token(self):
        return self.cfg.threads_token

    @property
    def version(self):
        return self.cfg.threads_version

    def profile(self, username: str) -> MetaResult:
        op, path = "threads_profile", "profile_lookup"
        name = username.strip().lstrip("@")
        if not USERNAME.match(name):
            return self._result(op, username[:60], St.INVALID_INPUT, path,
                                message="nick Threads: 1-30 znaków, litery, cyfry, '.', '_'")
        if not self.cfg.threads_token:
            return self._not_configured(op, name, path, "threads_basic + threads_profile_discovery")
        status, headers, body, err = self._call(path, {"username": name, "fields": PROFILE_FIELDS})
        bad = self._failure(op, name, path, status, headers, body, err)
        if bad:
            return bad
        data = json_body(body)
        if isinstance(data, dict) and "data" in data:
            rows = data["data"]
            data = (rows[0] if rows else {}) if isinstance(rows, list) and len(rows) <= 1 else None
        if not isinstance(data, dict):
            return self._result(op, name, St.SOURCE_ERROR, path, http_status=status,
                                message="nieprawidłowa odpowiedź API (to nie JSON-obiekt)")
        if not data:
            return self._result(op, name, St.NO_RESULT, path, http_status=status, caveats=[PROFILE_NO_RESULT],
                                message="API nie zwróciło profilu")
        if not isinstance(data.get("username"), str) or not USERNAME.fullmatch(data["username"]):
            return self._result(op, name, St.SOURCE_ERROR, path, http_status=status,
                                message="nieprawidłowa odpowiedź API (brak poprawnego username)")
        got = str(data["username"])
        if got.lower() != name.lower():
            return self._result(op, name, St.SOURCE_ERROR, path, http_status=status,
                                message="API zwróciło profil o innej nazwie niż zapytanie - wynik odrzucony")
        item = {
            "type": "profile", "username": got, "name": str(data.get("name") or "")[:200],
            "profile_url": f"https://www.threads.com/@{got}",
            "biography": str(data.get("biography") or "")[:MAX_TEXT],
            "is_verified": bool(data.get("is_verified")),
            "follower_count": data.get("follower_count") if isinstance(data.get("follower_count"), int) else None,
            "profile_picture_url": https_url(data.get("profile_picture_url"), 1000),   # nigdy nie renderować jako <img>
        }
        return self._result(op, name, St.FOUND, path, http_status=status, items=[item], caveats=[IDENTITY_CAVEAT],
                            message="publiczny profil Threads (oficjalne API)")

    def search(self, query: str, search_type: str = "TOP", limit: int = 25, author: str | None = None,
               search_mode: str = "KEYWORD") -> MetaResult:
        op, path = "threads_search", "keyword_search"
        q = query.strip()
        problem = None
        if not q or len(q) > MAX_QUERY or CONTROL.search(q):
            problem = f"fraza: 1-{MAX_QUERY} znaków, bez znaków sterujących"
        elif search_type not in ("TOP", "RECENT"):
            problem = "typ: TOP albo RECENT"
        elif search_mode not in ("KEYWORD", "TAG"):
            problem = "tryb: KEYWORD albo TAG"
        elif not isinstance(limit, int) or not 1 <= limit <= 100:
            problem = "limit: 1-100"
        elif author and not USERNAME.match(author.lstrip("@")):
            problem = "autor: nick Threads (1-30 znaków)"
        if problem:
            return self._result(op, q[:MAX_QUERY], St.INVALID_INPUT, path, message=problem)
        if not self.cfg.threads_token:
            return self._not_configured(op, q, path, "threads_basic + threads_keyword_search")
        params = {"q": q, "search_type": search_type, "search_mode": search_mode, "limit": limit,
                  "fields": SEARCH_FIELDS}
        if author:
            params["author_username"] = author.lstrip("@")
        status, headers, body, err = self._call(path, params)
        bad = self._failure(op, q, path, status, headers, body, err)
        if bad:
            bad.caveats.append(SEARCH_SCOPE)
            return bad
        data = json_body(body)
        rows = data.get("data") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            return self._result(op, q, St.SOURCE_ERROR, path, http_status=status,
                                message="nieprawidłowa odpowiedź API (brak listy data)")
        if any(not isinstance(r, dict) or not isinstance(r.get("id"), str) or not r["id"] for r in rows):
            return self._result(op, q, St.SOURCE_ERROR, path, http_status=status,
                                message="nieprawidłowa odpowiedź API (post bez identyfikatora)")
        items = [_post(r) for r in rows[:limit]]
        if not items:
            return self._result(op, q, St.NO_RESULT, path, http_status=status, caveats=[SEARCH_SCOPE],
                                message="API nie zwróciło postów dla tej frazy")
        return self._result(op, q, St.FOUND, path, http_status=status, items=items,
                            caveats=[SEARCH_SCOPE, IDENTITY_CAVEAT],
                            message=f"{len(items)} publicznych postów (oficjalne API, tylko pierwsza strona)")

    def _not_configured(self, op: str, query: str, path: str, perms: str) -> MetaResult:
        return super()._not_configured(op, query, path, (
            f"brak tokenu Threads API (THREADS_ACCESS_TOKEN albo ~/.osint/meta.env; uprawnienia: {perms})."))


def _post(r: dict) -> dict:
    user = str(r.get("username") or "")
    return {
        "type": "post", "id": str(r.get("id") or "")[:40], "username": user if USERNAME.match(user) else "",
        "text": clean(r.get("text")), "permalink": https_url(r.get("permalink")),
        "timestamp": str(r.get("timestamp") or "")[:40], "media_type": str(r.get("media_type") or "")[:30],
        "is_reply": bool(r.get("is_reply")), "is_quote_post": bool(r.get("is_quote_post")),
    }
