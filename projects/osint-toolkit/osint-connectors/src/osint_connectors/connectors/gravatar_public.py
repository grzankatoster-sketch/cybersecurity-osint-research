"""Konektor Gravatar — publiczny profil po adresie e-mail.

Źródło PASSIVE: oficjalny, publiczny endpoint profilu Gravatara. Nie wymaga
uwierzytelnienia, nie wchodzi w interakcję z kontem celu i nie wysyła do celu
żadnej wiadomości. Zwraca wyłącznie informacje, które użytkownik sam
opublikował publicznie.

Prywatność: surowy e-mail (potrzebny do policzenia skrótu wymaganego przez
Gravatar) pozostaje wewnątrz konektora i żądania — NIE trafia do Finding ani
logów. W wyniku jest tylko ``subject_ref`` (HMAC z solą) wstrzykiwany przez runner.

Mapowanie odpowiedzi na Status:
  * 200 + profil        -> FOUND
  * 404                 -> NOT_FOUND (brak Gravatara ≠ e-mail nieużywany globalnie)
  * 429                 -> RateLimited -> UNKNOWN
  * 5xx / błąd sieci    -> TransportError -> ERROR
  * 200 bez treści / zła struktura / zły JSON -> SchemaChanged/ParseError -> ERROR
"""
from __future__ import annotations

import hashlib

from ..connector import Context, connector
from ..errors import ParseError, RateLimited, SchemaChanged, TransportError
from ..errors import ConnectorError
from ..model import Finding, InputKind, SourceKind, Status, Subject

# Udokumentowany publiczny host profilu. Bez ścieżek z danymi celu w kodzie.
_GRAVATAR_HOST = "https://en.gravatar.com"


@connector
class GravatarPublic:
    name = "gravatar_public"
    source_kind = SourceKind.PASSIVE
    supported_inputs = frozenset({InputKind.EMAIL})

    async def check(self, subject: Subject, ctx: Context) -> Finding:
        if ctx.http is None:
            return Finding(
                connector=self.name,
                source=self.source_kind,
                status=Status.UNKNOWN,
                confidence=0.0,
                subject_ref="",
                evidence="brak klienta HTTP w kontekście",
                error_kind="no_http",
            )

        email = subject.value.strip().lower()
        gravatar_hash = hashlib.md5(email.encode("utf-8")).hexdigest()  # schemat Gravatara
        url = f"{_GRAVATAR_HOST}/{gravatar_hash}.json"

        try:
            resp = await ctx.http.get(
                url,
                headers={"Accept": "application/json"},
                timeout=ctx.timeout,
            )
        except ConnectorError:
            raise
        except Exception as exc:  # błąd sieci/transportu -> typowany wyjątek
            raise TransportError(str(exc)) from exc

        code = getattr(resp, "status_code", None)

        if code == 200:
            try:
                data = resp.json()
            except Exception as exc:
                raise ParseError("niepoprawny JSON profilu") from exc
            entry = (data or {}).get("entry") if isinstance(data, dict) else None
            # Trafienie wymaga PRAWDZIWEGO rekordu profilu, nie samej obecności klucza 'entry'.
            # Odrzucamy: 'entry' nie-lista ({"entry":"..."}), pusta lista, element nie-obiekt ([null]),
            # obiekt bez pola identyfikującego ([{}]). Każdy z tych przypadków to zmiana formatu, nie FOUND.
            if not isinstance(entry, list) or not entry:
                raise SchemaChanged("200 bez listy 'entry'")
            profile = entry[0]
            if not isinstance(profile, dict):
                raise SchemaChanged("wpis profilu nie jest obiektem")
            identifier = (profile.get("profileUrl") or profile.get("hash")
                          or profile.get("requestHash") or profile.get("preferredUsername"))
            if not identifier:
                raise SchemaChanged("wpis profilu bez pola identyfikującego")
            extra = {}
            # Tylko jawnie publiczne, samodzielnie opublikowane pole.
            if profile.get("profileUrl"):
                extra["public_profile_url"] = profile["profileUrl"]
            return Finding(
                connector=self.name,
                source=self.source_kind,
                status=Status.FOUND,
                confidence=0.95,
                subject_ref="",  # uzupełni runner
                evidence="publiczny profil Gravatara istnieje",
                extra=extra,
            )

        if code == 404:
            return Finding(
                connector=self.name,
                source=self.source_kind,
                status=Status.NOT_FOUND,
                confidence=0.9,  # brak Gravatara nie przesądza o nieużywaniu e-maila
                subject_ref="",
                evidence="brak publicznego profilu Gravatara",
            )

        if code == 429:
            raise RateLimited("429 z Gravatara")

        if isinstance(code, int) and 500 <= code < 600:
            raise TransportError(f"status {code}")

        raise SchemaChanged(f"nieoczekiwany status {code}")
