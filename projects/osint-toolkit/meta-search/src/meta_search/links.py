"""Linki do ręcznego sprawdzenia nicku w serwisach Meta. Niczego nie pobiera: status `manual`."""
from __future__ import annotations

from urllib.parse import quote, quote_plus

from .contract import IDENTITY_CAVEAT, MetaResult, SourceKind, St
from .threads import USERNAME


def manual_links(username: str) -> MetaResult:
    name = username.strip().lstrip("@")
    if not USERNAME.match(name):
        return MetaResult("meta", "links", username[:60], St.INVALID_INPUT, SourceKind.MANUAL,
                          message="nick: 1-30 znaków, litery, cyfry, '.', '_'")
    n = quote(name, safe="")
    items = [
        {"type": "link", "platform": "threads", "label": "Profil Threads", "url": f"https://www.threads.com/@{n}"},
        {"type": "link", "platform": "threads", "label": "Wyszukiwarka Threads",
         "url": f"https://www.threads.com/search?q={quote_plus(name)}"},
        {"type": "link", "platform": "instagram", "label": "Profil Instagram", "url": f"https://www.instagram.com/{n}/"},
        {"type": "link", "platform": "facebook", "label": "Profil lub strona Facebook",
         "url": f"https://www.facebook.com/{n}"},
    ]
    return MetaResult("meta", "links", name, St.MANUAL, SourceKind.MANUAL, items=items,
                      message="linki do ręcznego otwarcia - nic nie sprawdzono automatycznie",
                      caveats=["Strona logowania albo błąd w przeglądarce nie oznacza braku konta.", IDENTITY_CAVEAT])
