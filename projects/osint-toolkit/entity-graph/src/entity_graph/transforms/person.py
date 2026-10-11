"""Transformacja osoby (imię i nazwisko): kandydaci nazw użytkownika + linki dorków do RĘCZNEGO przeglądu.

Nic nie jest wysyłane do sieci: narzędzie buduje adresy, człowiek decyduje, czy je otworzyć. Wyszukiwarek nie
scrapujemy. Kandydaci to HIPOTEZY ze wzorców (pewność krawędzi 0), nie ustalenia."""
from __future__ import annotations

import re
from urllib.parse import quote_plus

from ..model import Node, Status
from ..normalize import EntityType, fold
from .base import Context, TransformResult, register

USERNAME_OK = re.compile(r"^[a-z0-9._-]{2,40}$")
SEPARATORS = ("", ".", "_", "-")
ENGINES = {
    "google": "https://www.google.com/search?q=",
    "bing": "https://www.bing.com/search?q=",
    "duckduckgo": "https://duckduckgo.com/?q=",
}


def name_tokens(name: str) -> list[str]:
    """'Łukasz Żółć-Nowak' -> ['lukasz', 'zolc', 'nowak'] (ł osobno, bo NFKD go nie rozkłada)."""
    return [t for t in re.split(r"[^a-z0-9]+", fold(name)) if t]


def generate_usernames(name: str, limit: int = 12) -> list[tuple[str, str]]:
    """-> [(nazwa, opis wzorca)] od najczęstszych wzorców; bez duplikatów; co najwyżej `limit`.
    Pierwszy token = imię, ostatni = nazwisko (środkowe są pomijane)."""
    tokens = name_tokens(name)
    if limit < 1 or len(tokens) < 2:
        return []
    first, last = tokens[0], tokens[-1]
    fi, li = first[0], last[0]
    patterns: list[tuple[str, str]] = []
    patterns += [(f"{first}{sep}{last}", f"imię{sep or '+'}nazwisko") for sep in SEPARATORS]
    patterns += [(f"{fi}{sep}{last}", f"inicjał{sep or '+'}nazwisko") for sep in SEPARATORS]
    patterns += [(f"{last}{sep}{first}", f"nazwisko{sep or '+'}imię") for sep in SEPARATORS]
    patterns += [(f"{first}{sep}{li}", f"imię{sep or '+'}inicjał nazwiska") for sep in SEPARATORS]
    patterns += [(f"{last}{sep}{fi}", f"nazwisko{sep or '+'}inicjał imienia") for sep in SEPARATORS]
    patterns += [(f"{fi}{li}", "inicjały"), (first, "samo imię (bardzo ogólne)"), (last, "samo nazwisko (bardzo ogólne)")]
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for cand, label in patterns:
        if USERNAME_OK.match(cand) and cand not in seen:
            seen.add(cand)
            out.append((cand, label))
        if len(out) >= limit:
            break
    return out


def dork_links(name: str) -> list[dict]:
    """Zapytania do ręcznego otwarcia. Nazwa w cudzysłowie (fraza dokładna), z wariantem bez polskich znaków."""
    exact = f'"{name.strip()}"'
    folded = " ".join(name_tokens(name))
    variants = [exact] + ([f'"{folded}"'] if folded and folded != name.strip().casefold() else [])
    queries: list[tuple[str, str]] = []
    for v in variants:
        queries += [
            ("fraza dokładna", v),
            ("profile zawodowe", f"{v} site:linkedin.com/in"),
            ("kod i projekty", f"{v} site:github.com"),
            ("serwisy społecznościowe", f"{v} (site:facebook.com OR site:instagram.com OR site:x.com)"),
            ("dokumenty", f"{v} filetype:pdf"),
        ]
    return [{"engine": e, "label": label, "query": q, "url": base + quote_plus(q)}
            for label, q in queries for e, base in ENGINES.items()]


@register("person_candidates", (EntityType.PERSON,),
          "Kandydaci nazw użytkownika (polskie znaki, separatory, inicjały) + dorki do ręcznego przeglądu", network=False)
def person_candidates(node: Node, ctx: Context) -> TransformResult:
    cands = generate_usernames(node.value, ctx.settings.max_usernames)
    if not name_tokens(node.value) or len(name_tokens(node.value)) < 2:
        return TransformResult.failed(Status.UNKNOWN, "potrzebne imię i nazwisko (min. 2 człony), by zbudować kandydatów")
    res = TransformResult(
        Status.FOUND, node_attrs={"manual_review_links": dork_links(node.value)},
        note="kandydaci to hipotezy ze wzorców, a linki dorków służą do ręcznego przeglądu; nic nie wysłano do sieci",
        stats={"candidates": len(cands)})
    for user, label in cands:
        u = Node.make(EntityType.USERNAME, user, {"candidate": True}, "person_candidates")
        res.nodes.append(u)
        res.edges.append(ctx.edge("person_candidates", node, u, "candidate_username", 0.0,
                                  f"wygenerowano ze wzorca: {label}. HIPOTEZA bez dowodu, wymaga weryfikacji"))
    return res
