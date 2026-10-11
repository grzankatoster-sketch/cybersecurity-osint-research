"""Czy konta znalezione pod różnymi wariantami nazwy (sampler51, sampler_51, sampler.51…) należą do tej samej
osoby? Ocena z danych profili (extract.py): linki między profilami, ta sama strona www, nazwa wyświetlana,
avatar, bio, lokalizacja. Bez danych profilu nie ma oceny — sama zbieżność nazwy to nie dowód.

Reguła wspólna z entity-graph (entity_graph/evidence.py): pola, które może skopiować każdy (strona www, wspólne
linki, avatar, nazwa wyświetlana, bio, lokalizacja, link w jedną stronę), tworzą jedną zależną grupę: liczy się
najsilniejsze z nich, nie wyżej niż COPYABLE_CAP, a poziom dowodów najwyżej "umiarkowane". Poziom "mocne" dają tylko
linki wzajemne (kontrola obu kont). Wynik to poziom dowodów, nie procent pewności; `score` służy do sortowania."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .geo import Gazetteer
from .models import Result, Status
from .urlnorm import normalize_url
from .variants import ascii_fold


@dataclass
class Account:
    variant: str
    site: str
    url: str
    profile: dict


MAX_SCORE = 0.95
COPYABLE_CAP = 0.7          # te same stałe co entity_graph.evidence
RECIPROCAL = 0.85
LEVELS = ("brak", "słabe", "umiarkowane", "mocne")


@dataclass
class Link:
    score: float                     # 0–1, tylko do sortowania (nie prawdopodobieństwo)
    reasons: list[str] = field(default_factory=list)
    level: str = "brak"              # poziom dowodów: brak / słabe / umiarkowane / mocne
    copy_only: bool = False          # wszystkie sygnały to pola, które da się skopiować


def _norm_url(u) -> str:
    """Wspólna normalizacja (urlnorm.py); niepoprawny adres z profilu daje "" i jest pomijany, nigdy wyjątek."""
    return normalize_url(u) if isinstance(u, str) else ""


def _norm_text(t: str) -> str:
    return re.sub(r"\s+", " ", ascii_fold(t)).strip()


def _words(t: str) -> set[str]:
    return {w for w in re.findall(r"\w{3,}", ascii_fold(t))}


def _bio_mentions_url(bio: str, url: str) -> bool:
    """Czy bio zawiera adres profilu bez schematu (http(s)://), z opcjonalnym 'www.',
    ukośnikiem na końcu oraz kropką/przecinkiem kończącym zdanie. Wzmianka musi mieć
    granice z obu stron — ani dłuższa nazwa, ani głębsza ścieżka się nie liczą."""
    target = _norm_url(url)
    if not target:
        return False
    pattern = r"(?<![\w.-])(?:www\.)?" + re.escape(target) + r"/?(?=[\s,.]|$)"
    return re.search(pattern, bio, re.IGNORECASE) is not None


# drugi poziom w domenach typu example.co.uk / example.com.pl (uproszczona lista sufiksów publicznych)
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac"}
# tytuł strony wyciągnięty zamiast nazwy wyświetlanej ("mozilla's profile on AudioJungle")
_PAGE_TITLE_RE = re.compile(r"\bprofile?\b", re.IGNORECASE)
_BOILERPLATE_MIN_SERVICES = 3
# domyślne obrazki platform (np. Twitch: user-default-pictures-uv/...)
_DEFAULT_AVATAR_RE = re.compile(r"default|placeholder|no[-_]?avatar|anonymous|blank", re.IGNORECASE)


def _generated_avatar(avatar: str, *variants: str) -> bool:
    """Obrazek domyślny albo generowany z samej nazwy (cash.app/share-image?ct=<nazwa>) — każdy, kto ma tę
    nazwę, dostanie ten sam adres, więc nie jest poszlaką."""
    if _DEFAULT_AVATAR_RE.search(avatar):
        return True
    low = avatar.lower()
    return any(len(v) >= 3 and v.lower() in low for v in variants)


def service_domain(url: str) -> str:
    """Domena serwisu bez subdomen (account.venmo.com -> venmo.com). Niepoprawny adres daje ""."""
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
    labels = [x for x in host.split(".") if x]
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def boilerplate_avatars(accounts: list[Account]) -> set[str]:
    """Adresy avatara wspólne dla kont z >= 3 różnych serwisów: domyślny obrazek platformy lub rodziny
    serwisów (np. sklepy Envato), nie zdjęcie wgrane przez użytkownika — nie są poszlaką."""
    seen: dict[str, set[str]] = {}
    for a in accounts:
        av = a.profile.get("avatar") if a.profile else None
        if av:
            seen.setdefault(av, set()).add(service_domain(a.url) or a.url)
    return {av for av, services in seen.items() if len(services) >= _BOILERPLATE_MIN_SERVICES}


def _bare(t: str) -> str:
    return re.sub(r"[\W_]+", "", ascii_fold(t))


def _names_service(name: str, *sites: str) -> bool:
    """Nazwa wyświetlana zawiera nazwę serwisu ("Pay me on Cash App" na Cash.app): to szablon strony."""
    bare = _bare(name)
    for site in sites:
        s = _bare(re.sub(r"\s*[\[(].*?[\])]", "", site).split(".")[0])   # "Cash.app" -> cash, "X [maigret]" -> x
        if len(s) >= 4 and s in bare:
            return True
    return False


def _same_account(a: Account, b: Account) -> bool:
    """Ten sam serwis i ta sama nazwa: jedno konto widziane przez dwa szablony adresu (baza WMN i Maigret)."""
    da = service_domain(a.url)
    return bool(da) and da == service_domain(b.url) and a.variant.lower() == b.variant.lower()


def _combine(scores: list[float]) -> float:
    """Niezależne poszlaki: 1 - Π(1 - s)."""
    rest = 1.0
    for s in scores:
        rest *= 1 - s
    return 1 - rest


def link_accounts(a: Account, b: Account, gaz: Gazetteer | None = None,
                  ignore_avatars: set[str] | frozenset[str] = frozenset()) -> Link:
    if _same_account(a, b):
        return Link(0.0, [])
    pa, pb = a.profile, b.profile
    signals: list[tuple[float, str]] = []          # pola kopiowalne (jedna zależna grupa)
    a_links = {n for n in (_norm_url(u) for u in pa.get("links", [])) if n}
    b_links = {n for n in (_norm_url(u) for u in pb.get("links", [])) if n}
    a_url, b_url = _norm_url(a.url), _norm_url(b.url)
    a_links_to_b = bool(b_url) and b_url in a_links
    b_links_to_a = bool(a_url) and a_url in b_links
    claims: list[str] = []
    if a_links_to_b:
        claims.append(f"{a.site} linkuje do {b.site}")
    if b_links_to_a:
        claims.append(f"{b.site} linkuje do {a.site}")
    wa, wb = pa.get("website"), pb.get("website")
    if wa and wb and _norm_url(wa) and _norm_url(wa) == _norm_url(wb):
        signals.append((0.6, f"ta sama strona www ({wa[:50]})"))
    elif a_links & b_links:
        signals.append((0.4, "wspólne linki w profilach"))
    av_a, av_b = pa.get("avatar"), pb.get("avatar")
    if (av_a and av_b and av_a == av_b and av_a not in ignore_avatars
            and not _generated_avatar(av_a, a.variant, b.variant)):
        signals.append((0.5, "ten sam adres avatara"))
    na, nb = pa.get("name"), pb.get("name")
    if (na and nb and _norm_text(na) == _norm_text(nb) and len(_norm_text(na)) >= 4
            and not _PAGE_TITLE_RE.search(na) and not _names_service(na, a.site, b.site)):
        name_bare = _norm_text(na).replace(" ", "").replace(".", "").replace("_", "")
        variant_bare = {_norm_text(a.variant).replace(" ", "").replace(".", "").replace("_", ""),
                         _norm_text(b.variant).replace(" ", "").replace(".", "").replace("_", "")}
        generic = name_bare in variant_bare
        signals.append((0.1 if generic else 0.35, f'ta sama nazwa wyświetlana "{na[:40]}"'))
    ba, bb = pa.get("bio"), pb.get("bio")
    if not a_links_to_b and ba and _bio_mentions_url(ba, b.url):
        a_links_to_b = True
        claims.append(f"{a.site} linkuje do {b.site}")
    if not b_links_to_a and bb and _bio_mentions_url(bb, a.url):
        b_links_to_a = True
        claims.append(f"{b.site} linkuje do {a.site}")
    control: list[tuple[float, str]] = []
    if a_links_to_b and b_links_to_a:
        control += [(RECIPROCAL, claims[0]), (0.0, claims[1])]     # wzajemne linki: jeden sygnał kontroli
    elif claims:
        signals.append((0.7, claims[0]))                           # jednostronny link: twierdzenie jednej strony
    if ba and bb:
        sa, sb = _words(ba), _words(bb)
        if len(sa) >= 4 and len(sb) >= 4 and len(sa & sb) / len(sa | sb) >= 0.5:
            signals.append((0.35, "podobne bio"))
    la, lb = pa.get("location"), pb.get("location")
    if la and lb:
        if _norm_text(la) == _norm_text(lb):
            signals.append((0.2, f'ta sama lokalizacja "{la[:40]}"'))
        elif gaz:
            ra, rb = gaz.resolve(la), gaz.resolve(lb)
            if ra and rb and ra[0] == rb[0]:
                signals.append((0.05, f"ten sam kraj ({ra[0]})"))
    return _link(control, signals)


def _link(control: list[tuple[float, str]], copyable: list[tuple[float, str]]) -> Link:
    """Wspólna reguła: grupa kopiowalna liczy się raz (najsilniejszy sygnał, nie wyżej niż COPYABLE_CAP)."""
    parts = [s for s, _ in control if s]
    if copyable:
        parts.append(min(COPYABLE_CAP, max(s for s, _ in copyable)))
    score = round(min(MAX_SCORE, _combine(parts)), 2)
    if control:
        level = 3
    elif copyable:
        level = 2 if max(s for s, _ in copyable) >= 0.5 else 1
    else:
        level = 0
    return Link(score, [r for _, r in control + copyable], LEVELS[level], bool(copyable) and not control)


def accounts_from(scans: dict[str, list[Result]], min_conf: float = 0.6) -> list[Account]:
    # wyniki z odpowiedzi bez weryfikacji TLS nie biorą udziału w korelacji (treść mogła zostać podmieniona)
    return [Account(name, r.site, r.url, r.profile) for name, results in scans.items() for r in results
            if r.status is Status.FOUND and r.confidence >= min_conf and not r.insecure]


def variant_links(scans: dict[str, list[Result]], original: str, gaz: Gazetteer | None = None,
                  min_conf: float = 0.6) -> dict[str, dict]:
    """Dla każdego wariantu: najmocniejsze powiązanie z kontami oryginalnej nazwy.
    {wariant: {"score": 0–1 | None, "reasons": [...], "pair": "SerwisA ↔ SerwisB", "accounts": n}}"""
    accounts = accounts_from(scans, min_conf)
    noise = boilerplate_avatars(accounts)
    base = [a for a in accounts if a.variant == original]
    out = {}
    for variant in scans:
        if variant == original:
            continue
        mine = [a for a in accounts if a.variant == variant]
        best: tuple[Link, Account, Account] | None = None
        for x in mine:
            for y in base:
                if not (x.profile and y.profile):
                    continue
                link = link_accounts(x, y, gaz, noise)
                if best is None or link.score > best[0].score:
                    best = (link, x, y)
        if not mine:
            out[variant] = {"score": None, "level": None, "reasons": ["brak znalezionych kont"], "pair": "",
                            "accounts": 0}
        elif best is None or best[0].score == 0:
            out[variant] = {"score": 0.0 if best else None, "level": "brak" if best else None,
                            "reasons": ["brak wspólnych danych w profilach" if best else "brak danych profilu"],
                            "pair": "", "accounts": len(mine)}
        else:
            link, x, y = best
            out[variant] = {"score": link.score, "level": link.level, "copy_only": link.copy_only,
                            "reasons": link.reasons,
                            "pair": f"{x.site} ({x.variant}) ↔ {y.site} ({y.variant})", "accounts": len(mine)}
    return out


def same_name_clusters(accounts: list[Account], gaz: Gazetteer | None = None, threshold: float = 0.5) -> list[dict]:
    """Pary kont (dowolne warianty) z mocnym powiązaniem — do raportu „prawdopodobnie ta sama osoba”."""
    pairs = []
    noise = boilerplate_avatars(accounts)
    for i, a in enumerate(accounts):
        for b in accounts[i + 1:]:
            if a.url == b.url or not (a.profile and b.profile):
                continue
            link = link_accounts(a, b, gaz, noise)
            if link.score >= threshold:
                pairs.append({"a": f"{a.site} ({a.variant})", "b": f"{b.site} ({b.variant})",
                              "score": link.score, "level": link.level, "copy_only": link.copy_only,
                              "reasons": link.reasons})
    return sorted(pairs, key=lambda p: -p["score"])[:30]
