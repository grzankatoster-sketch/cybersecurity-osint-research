"""Publiczne dane Strony Facebooka (graph.facebook.com) po identyfikatorze albo nazwie (vanity) Strony.

GET /{page-id|nazwa}?fields=id,name,category,link,fan_count,about,website,verification_status
- Tylko pola publiczne Strony. Profile osób prywatnych nie są obsługiwane: węzeł osoby nie ma pól Strony
  (API odpowiada błędem 100), a odpowiedź bez category/fan_count jest odrzucana po stronie klienta.
- Dostęp do publicznych danych cudzych Stron wymaga zatwierdzonej w App Review funkcji aplikacji: Page Public Metadata
  Access (metadane) / Page Public Content Access (treści Strony) - zależnie od pól. Bez nich API zwraca błąd uprawnień
  albo ograniczony zestaw pól. Dokładne wymagania potwierdź w konsoli aplikacji Meta (dokumentacja nie była dostępna
  w narzędziu przeglądarkowym w dniu przeglądu, 03.10.2026).
- Szukanie Stron po frazie (/pages/search) NIE jest zaimplementowane: wymagania tego punktu nie zostały potwierdzone.
- Niejednoznaczne błędy 100/803 to SOURCE_ERROR; nie potwierdzają poprawnego wyszukania ani braku Strony."""
from __future__ import annotations

import re
from urllib.parse import quote

from .contract import MetaResult, St
from .graph import GraphClient, clean, count, error_info, https_url, json_body

BASE = "https://graph.facebook.com"
OP = "facebook_page"
SHOWN_PATH = "{page-id}"
FIELDS = "id,name,category,link,fan_count,about,website,verification_status"
PAGE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,99}$")   # id liczbowe albo nazwa Strony; bez '/', '?', '..'
FEATURE = "Page Public Metadata Access / Page Public Content Access (App Review)"

SCOPE_CAVEAT = ("Publiczne dane cudzych Stron wymagają zatwierdzonej funkcji aplikacji Page Public Content Access "
                "(metadane: Page Public Metadata Access) po App Review; bez niej API zwraca błąd uprawnień albo "
                "mniej pól. Wynik dotyczy Strony, nie prywatnego profilu osoby.")


class FacebookPagesClient(GraphClient):
    platform, base = "facebook", BASE
    permissions = {OP: FEATURE}

    @property
    def token(self):
        return self.cfg.facebook_token

    @property
    def version(self):
        return self.cfg.graph_version

    def page(self, page: str) -> MetaResult:
        ref = str(page).strip().lstrip("@")
        if not PAGE_REF.match(ref):
            return self._result(OP, str(page)[:60], St.INVALID_INPUT, SHOWN_PATH,
                                message="Strona: identyfikator liczbowy albo nazwa (litery, cyfry, '.', '-'; do 100 znaków)")
        if not self.cfg.facebook_token:
            return self._not_configured(OP, ref, SHOWN_PATH, (
                "brak tokenu Facebook Pages (FACEBOOK_ACCESS_TOKEN w środowisku albo ~/.osint/meta.env; "
                f"wymagane: {FEATURE})."))
        status, headers, body, err = self._call(quote(ref, safe=""), {"fields": FIELDS})
        bad = self._failure(OP, ref, SHOWN_PATH, status, headers, body, err)
        if bad:
            return bad
        data = json_body(body)
        if not isinstance(data, dict) or not isinstance(data.get("id"), str) or not data["id"] \
                or not isinstance(data.get("name"), str):
            return self._result(OP, ref, St.SOURCE_ERROR, SHOWN_PATH, http_status=status,
                                message="nieprawidłowa odpowiedź API (brak id lub nazwy)")
        if "category" not in data and "fan_count" not in data:
            return self._result(OP, ref, St.SOURCE_ERROR, SHOWN_PATH, http_status=status,
                                message="odpowiedź nie wygląda na Stronę (brak category i fan_count) - wynik odrzucony")
        if ref.isdigit() and data["id"] != ref:
            return self._result(OP, ref, St.SOURCE_ERROR, SHOWN_PATH, http_status=status,
                                message="API zwróciło obiekt o innym id niż zapytanie - wynik odrzucony")
        item = {
            "type": "page", "id": clean(data["id"], 40), "name": clean(data["name"], 200),
            "category": clean(data.get("category"), 100),
            "link": https_url(data.get("link")), "fan_count": count(data.get("fan_count")),
            "about": clean(data.get("about")), "website": https_url(data.get("website"), 500, ("https://", "http://")),
            "verification_status": clean(data.get("verification_status"), 30),
        }
        return self._result(OP, ref, St.FOUND, SHOWN_PATH, http_status=status, items=[item],
                            caveats=[SCOPE_CAVEAT], message="publiczne dane Strony Facebooka (oficjalne API)")
