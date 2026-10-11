"""Instagram Business Discovery (graph.facebook.com): publiczne dane KONT PROFESJONALNYCH (Business / Creator) po nicku.

GET /{ig-user-id}?fields=business_discovery.username(<nick>){username,name,biography,followers_count,media_count,
website,profile_picture_url[,media.limit(N){...}]}
- {ig-user-id} to konto profesjonalne WŁAŚCICIELA tokenu (INSTAGRAM_USER_ID), nie szukane konto; w wyniku i raporcie
  pokazujemy placeholder zamiast jego numeru.
- Dostęp: Instagram API with Facebook Login; token użytkownika z uprawnieniami instagram_basic + instagram_manage_insights
  + pages_read_engagement (referencja IG User / business_discovery, 04.10.2026; dodatkowo ads_read lub ads_management,
  gdy rolę na Stronie nadano przez portfolio firmowe / Business Manager) oraz pages_show_list do znalezienia numeru
  konta; konto właściciela profesjonalne i połączone ze Stroną Facebooka. Bez instagram_manage_insights API zwraca #10.
- Zakres: konta prywatne i osobiste nie są widoczne. Niejednoznaczne błędy API są błędami źródła,
  nie poprawnym wyszukiwaniem bez wyników; mogą wynikać z błędnej konfiguracji lub parametrów.
Źródło: https://www.postman.com/meta/instagram/documentation/6yqw8pt/instagram-api (kolekcja Meta)."""
from __future__ import annotations

from .contract import IDENTITY_CAVEAT, MetaResult, St
from .graph import USERNAME, GraphClient, clean, count, error_info, https_url, json_body

BASE = "https://graph.facebook.com"
OP = "instagram_profile"
SHOWN_PATH = "{ig-user-id}"
PROFILE_FIELDS = "username,name,biography,followers_count,media_count,website,profile_picture_url"
MEDIA_FIELDS = "id,caption,media_type,permalink,timestamp,like_count,comments_count"
MAX_MEDIA = 50
PERMS = "instagram_basic + instagram_manage_insights + pages_read_engagement (+ ads_read przy roli z portfolio firmowego)"

SCOPE_CAVEAT = ("Business Discovery widzi tylko konta profesjonalne (Business/Creator); konta prywatne i osobiste "
                "nie są dostępne, a część danych (np. liczba polubień) może być ukryta.")


class InstagramClient(GraphClient):
    platform, base = "instagram", BASE
    permissions = {OP: PERMS}

    @property
    def token(self):
        return self.cfg.instagram_token

    @property
    def version(self):
        return self.cfg.graph_version

    def profile(self, username: str, media: int = 0) -> MetaResult:
        name = str(username).strip().lstrip("@")
        if not USERNAME.match(name):
            return self._result(OP, str(username)[:60], St.INVALID_INPUT, SHOWN_PATH,
                                message="nick Instagrama: 1-30 znaków, litery, cyfry, '.', '_'")
        if isinstance(media, bool) or not isinstance(media, int) or not 0 <= media <= MAX_MEDIA:
            return self._result(OP, name, St.INVALID_INPUT, SHOWN_PATH, message=f"media: liczba 0-{MAX_MEDIA}")
        if not self.cfg.instagram_ready:
            return self._not_configured(OP, name, SHOWN_PATH, (
                "brak konfiguracji Instagram Business Discovery (INSTAGRAM_ACCESS_TOKEN i INSTAGRAM_USER_ID "
                f"w środowisku albo ~/.osint/meta.env; uprawnienia: {PERMS})."))
        inner = PROFILE_FIELDS + (f",media.limit({media}){{{MEDIA_FIELDS}}}" if media else "")
        fields = f"business_discovery.username({name}){{{inner}}}"
        status, headers, body, err = self._call(self.cfg.instagram_user_id, {"fields": fields})
        bad = self._failure(OP, name, SHOWN_PATH, status, headers, body, err)
        if bad:
            return bad
        data = json_body(body)
        info = data.get("business_discovery") if isinstance(data, dict) else None
        if not isinstance(info, dict):
            return self._result(OP, name, St.SOURCE_ERROR, SHOWN_PATH, http_status=status,
                                message="nieprawidłowa odpowiedź API (brak business_discovery)")
        got = info.get("username")
        if not isinstance(got, str) or not USERNAME.fullmatch(got):
            return self._result(OP, name, St.SOURCE_ERROR, SHOWN_PATH, http_status=status,
                                message="nieprawidłowa odpowiedź API (brak poprawnego username)")
        if got.lower() != name.lower():
            return self._result(OP, name, St.SOURCE_ERROR, SHOWN_PATH, http_status=status,
                                message="API zwróciło konto o innej nazwie niż zapytanie - wynik odrzucony")
        items = [{
            "type": "profile", "username": got, "name": clean(info.get("name"), 200),
            "profile_url": f"https://www.instagram.com/{got}/", "biography": clean(info.get("biography")),
            "follower_count": count(info.get("followers_count")), "media_count": count(info.get("media_count")),
            "website": https_url(info.get("website"), 500, ("https://", "http://")),
            "profile_picture_url": https_url(info.get("profile_picture_url"), 1000),
        }]
        rows = (info.get("media") or {}).get("data") if isinstance(info.get("media"), dict) else None
        if media and isinstance(rows, list):
            items += [_post(r, got) for r in rows if isinstance(r, dict) and r.get("id")][:media]
        return self._result(OP, name, St.FOUND, SHOWN_PATH, http_status=status, items=items,
                            caveats=[SCOPE_CAVEAT, IDENTITY_CAVEAT],
                            message="konto profesjonalne Instagram (oficjalne API, Business Discovery)")


def _post(r: dict, username: str) -> dict:
    return {
        "type": "post", "id": clean(r.get("id"), 40), "username": username, "text": clean(r.get("caption")),
        "permalink": https_url(r.get("permalink")), "timestamp": clean(r.get("timestamp"), 40),
        "media_type": clean(r.get("media_type"), 30), "like_count": count(r.get("like_count")),
        "comments_count": count(r.get("comments_count")),
    }
