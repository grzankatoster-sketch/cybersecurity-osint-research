"""Wspólna ocena dowodów dopasowania dwóch rekordów (profili). Jedna reguła dla korelacji (correlate.py),
rozszerzania rekordów (expand.py) i, przez te same stałe, dla username-engine (correlate.link_accounts).

Wynik NIE jest prawdopodobieństwem ani procentem pewności. To poziom (brak / słabe / umiarkowane / mocne),
decyzja (rozwiń / przegląd / zatrzymaj) i lista powodów. Liczba `weight` służy tylko do porządkowania krawędzi.

Zasady:
  * Pochodzenie: liczy się, KTO coś twierdzi. Mocny dowód wymaga deklaracji strony kontrolowanej przez podmiot
    z danych początkowych (kotwica linkuje do kandydata) albo linków wzajemnych (kontrola obu kont). Link kandydata
    do kotwicy to tylko twierdzenie kandydata: dodać go może każdy.
  * Zależność sygnałów: pola, które da się skopiować (nazwa wyświetlana, awatar, bio, strona www, lokalizacja,
    jednostronny link), tworzą JEDNĄ grupę: liczy się najsilniejsze z nich, a cała grupa daje najwyżej poziom
    "umiarkowane". Dziesięć skopiowanych pól to nadal jedna kopia.
  * Wiarygodność: kandydat ze źródła o niskiej pewności istnienia konta (albo bez tej informacji, albo z odpowiedzi
    bez weryfikacji TLS) idzie do przeglądu.
  * Sprzeczności: inny typ encji (osoba / organizacja) to sprzeczność twarda, różne własne strony albo zupełnie inna
    nazwa wyświetlana to rozbieżność. Każda kieruje do przeglądu.
  * Sprzeczne obserwacje jednego rekordu (dwa źródła podały różny typ encji, stronę www, flagę TLS...; patrz
    model.Node.observations) to sprzeczność twarda: sporne pole jest nieznane, a decyzja nie zależy od kolejności.
  * Porównanie zawsze z kotwicą: dowód przez pośrednika (A-B i B-C) to łańcuch, który nie potwierdza A-C.
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from urllib.parse import urlsplit

from .normalize import fold, normalize_url

MAX_WEIGHT = 0.95          # wspólny sufit wagi (nigdy 1.0)
COPYABLE_CAP = 0.7         # sufit grupy pól kopiowalnych: tyle co jednostronny link
CONFLICT_CAP = 0.3         # sufit wagi przy sprzeczności twardej
MIN_RELIABILITY = 0.6      # poniżej: kandydat do przeglądu (ten sam próg co ue_min_confidence)
BIO_MIN_WORDS = 4
BIO_MIN_JACCARD = 0.5
MAX_FINGERPRINT = 64

# hosty platform: link do nich nie świadczy o własnej stronie
PLATFORM_HOSTS = frozenset({
    "x.com", "facebook.com", "instagram.com", "youtube.com", "linkedin.com", "github.com", "gitlab.com",
    "tiktok.com", "reddit.com", "t.me", "telegram.org", "medium.com", "wordpress.com", "blogspot.com",
    "linktr.ee", "wikipedia.org", "google.com", "pinterest.com", "twitch.tv", "gravatar.com", "about.me",
    "threads.com", "threads.net",
})


class Level(IntEnum):
    NONE = 0
    WEAK = 1
    MODERATE = 2
    STRONG = 3

    @property
    def label(self) -> str:
        return ("brak", "słabe", "umiarkowane", "mocne")[self]


class Decision(str, Enum):
    EXPAND = "rozwin"        # wolno wykonać kolejne ograniczone zapytania; kandydat nadal jest hipotezą
    REVIEW = "przeglad"      # niejednoznaczne: decyzję podejmuje człowiek
    STOP = "zatrzymaj"       # brak podstaw do dalszych zapytań


GROUP_CONTROL = "kontrola"          # deklaracja kotwicy albo linki wzajemne
GROUP_IDENTIFIER = "identyfikator"  # ten sam e-mail poświadczony przez platformę (Gravatar liczony z adresu konta)
GROUP_COPYABLE = "kopiowalne"       # pola, które może wpisać każdy


@dataclass
class Signal:
    kind: str
    score: float             # waga do porządkowania, nie prawdopodobieństwo
    detail: str
    group: str = GROUP_COPYABLE
    level: Level = Level.WEAK

    @property
    def copyable(self) -> bool:
        return self.group == GROUP_COPYABLE

    def to_dict(self) -> dict:
        return {"kind": self.kind, "group": self.group, "level": self.level.label, "detail": self.detail}


@dataclass
class Contradiction:
    kind: str
    detail: str
    hard: bool = False

    def to_dict(self) -> dict:
        return {"kind": self.kind, "hard": self.hard, "detail": self.detail}


@dataclass(frozen=True)
class Record:
    """Neutralny opis rekordu do porównania. Wypełniany z węzła grafu, z danych początkowych albo z profilu
    username-engine. `url` to klucz po normalize_url (pusty dla danych początkowych bez adresu)."""
    url: str = ""
    site: str = ""
    display_name: str = ""
    avatar_hash: str = ""
    website: str = ""
    links: tuple[str, ...] = ()
    emails: tuple[str, ...] = ()
    bio_fingerprint: tuple[str, ...] = ()
    entity_kind: str = ""
    provenance: str = ""
    reliability: float | None = None
    insecure: bool = False
    anchor: bool = False     # dane początkowe albo profil wskazany przez operatora jako należący do podmiotu
    aliases: tuple[str, ...] = ()   # inne adresy TEGO rekordu (dla danych początkowych: profile wskazane przez operatora)
    conflicts: tuple[str, ...] = ()  # sprzeczne obserwacje tego rekordu (opis pola, wartości i źródeł)


@dataclass
class Assessment:
    level: Level
    decision: Decision
    signals: list[Signal] = field(default_factory=list)
    contradictions: list[Contradiction] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    chain: list[dict] = field(default_factory=list)

    @property
    def copy_only(self) -> bool:
        return bool(self.signals) and all(s.copyable for s in self.signals)

    def to_dict(self) -> dict:
        return {"decision": self.decision.value, "level": self.level.label, "copy_only": self.copy_only,
                "reasons": self.reasons, "signals": [s.to_dict() for s in self.signals],
                "contradictions": [c.to_dict() for c in self.contradictions], "chain": self.chain}


# --- pomocnicze ---

def url_key(raw: str) -> str | None:
    try:
        return normalize_url(raw)[0]
    except ValueError:
        return None


def host_of(raw: str) -> str | None:
    key = url_key(raw) if raw else None
    return key.split("/", 1)[0].split("?", 1)[0] if key else None


def is_platform(host: str) -> bool:
    return any(host == p or host.endswith("." + p) for p in PLATFORM_HOSTS)


def bio_fingerprint(text: str) -> list[str]:
    """Skróty słów bio (>= 3 litery, bez polskich znaków): pozwalają porównać podobieństwo bez przechowywania treści."""
    words = sorted({w for w in re.findall(r"\w{3,}", fold(text or ""))})
    return sorted({hashlib.sha256(w.encode()).hexdigest()[:10] for w in words})[:MAX_FINGERPRINT]


def _name(text: str) -> str:
    return " ".join(fold(text or "").split())


def _gravatar_hashes(email: str) -> set[str]:
    from .transforms.email import gravatar_hashes   # import leniwy: transforms importuje moduły sieciowe
    return set(gravatar_hashes(email).values())


def _declared(rec: Record) -> set[str]:
    keys = {url_key(u) for u in rec.links}
    if rec.website:
        keys.add(url_key(rec.website))
    keys.discard(None)
    return keys


def _ids(rec: Record) -> set[str]:
    out = {url_key(u) for u in rec.aliases} | {rec.url}
    out.discard(None)
    out.discard("")
    return out


def _label(rec: Record) -> str:
    return rec.site or rec.url or "dane początkowe"


# --- porównanie ---

def compare(a: Record, b: Record) -> tuple[list[Signal], list[Contradiction]]:
    """Sygnały i sprzeczności między dwoma rekordami. Kierunek ma znaczenie tylko dla kotwicy (a.anchor / b.anchor)."""
    signals: list[Signal] = []
    a_to_b = bool(_ids(b) & _declared(a))
    b_to_a = bool(_ids(a) & _declared(b))
    if a_to_b and b_to_a:
        signals.append(Signal("cross_link", 0.85, "profile linkują do siebie nawzajem", GROUP_CONTROL, Level.STRONG))
    elif a_to_b or b_to_a:
        src, dst = (a, b) if a_to_b else (b, a)
        if src.anchor and not dst.anchor:
            signals.append(Signal("cross_link", 0.7, f"kotwica ({_label(src)}) linkuje do {_label(dst)}",
                                  GROUP_CONTROL, Level.STRONG))
        else:
            signals.append(Signal("cross_link", 0.7, f"profil {_label(src)} linkuje do {_label(dst)} "
                                  "(jednostronnie: twierdzenie tej strony, może je dodać każdy)",
                                  GROUP_COPYABLE, Level.MODERATE))

    shared = set(a.emails) & set(b.emails)
    for rec, other in ((a, b), (b, a)):
        if other.avatar_hash:
            shared |= {e for e in rec.emails if other.avatar_hash in _gravatar_hashes(e)}
    for email in sorted(shared):
        signals.append(Signal("same_email", 0.8, f"oba rekordy powiązane z adresem {email}",
                              GROUP_IDENTIFIER, Level.MODERATE))

    ha, hb = host_of(a.website), host_of(b.website)
    if ha and ha == hb and not is_platform(ha):
        signals.append(Signal("same_domain", 0.6, f"ta sama własna strona www ({ha})", GROUP_COPYABLE, Level.MODERATE))

    na, nb = _name(a.display_name), _name(b.display_name)
    same_name = bool(na) and na == nb and len(na) >= 4
    same_avatar = bool(a.avatar_hash) and a.avatar_hash == b.avatar_hash
    different_sites = not (a.site and a.site == b.site)
    if same_name and same_avatar and different_sites:
        signals.append(Signal("name_and_avatar", 0.75, f'ta sama nazwa wyświetlana "{a.display_name[:40]}" i ten sam '
                              f"awatar (skrót {a.avatar_hash[:10]}...)", GROUP_COPYABLE, Level.MODERATE))
    elif same_name:
        signals.append(Signal("same_name", 0.1, f'ta sama nazwa wyświetlana "{a.display_name[:40]}"'))
    elif same_avatar and different_sites:
        signals.append(Signal("same_avatar", 0.3, "ten sam adres awatara"))

    fa, fb = set(a.bio_fingerprint), set(b.bio_fingerprint)
    if len(fa) >= BIO_MIN_WORDS and len(fb) >= BIO_MIN_WORDS and len(fa & fb) / len(fa | fb) >= BIO_MIN_JACCARD:
        signals.append(Signal("similar_bio", 0.35, "podobne bio (porównanie skrótów słów)"))

    contradictions: list[Contradiction] = []
    for rec in (a, b):
        if rec.conflicts:
            contradictions.append(Contradiction("observations", f"sprzeczne obserwacje rekordu {_label(rec)}: "
                                                + "; ".join(rec.conflicts), True))
    if a.entity_kind and b.entity_kind and a.entity_kind != b.entity_kind:
        contradictions.append(Contradiction("entity_kind", f"różny typ encji: {a.entity_kind} / {b.entity_kind}", True))
    if ha and hb and ha != hb and not is_platform(ha) and not is_platform(hb):
        contradictions.append(Contradiction("website", f"różne własne strony: {ha} / {hb}"))
    if na and nb and len(na) >= 4 and len(nb) >= 4 and not (set(na.split()) & set(nb.split())):
        contradictions.append(Contradiction("display_name", "zupełnie inna nazwa wyświetlana"))
    return signals, contradictions


def weight(signals: list[Signal], contradictions: list[Contradiction] = (),
           reliabilities: tuple[float | None, ...] = ()) -> float:
    """Waga do porządkowania (0-MAX_WEIGHT): grupy niezależne łączone 1 - Π(1 - s), w grupie liczy się najsilniejszy
    sygnał, grupa kopiowalna nie wyżej niż COPYABLE_CAP, nigdy wyżej niż pewność istnienia słabszego konta."""
    best: dict[str, float] = {}
    for s in signals:
        best[s.group] = max(best.get(s.group, 0.0), s.score)
    if GROUP_COPYABLE in best:
        best[GROUP_COPYABLE] = min(best[GROUP_COPYABLE], COPYABLE_CAP)
    rest = 1.0
    for v in best.values():
        rest *= 1 - v
    out = min(MAX_WEIGHT, 1 - rest)
    if any(c.hard for c in contradictions):
        out = min(out, CONFLICT_CAP)
    for r in reliabilities:
        if r is not None:
            out = min(out, r)
    return round(out, 3)


def level_of(signals: list[Signal]) -> Level:
    if not signals:
        return Level.NONE
    top = max(s.level for s in signals)
    if all(s.copyable for s in signals):
        top = min(top, Level.MODERATE)   # kopia nie może dać "mocne"
    return Level(top)


def _dedup(items: list, key) -> list:
    seen, out = set(), []
    for x in items:
        k = key(x)
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


def _reliable(record: Record) -> bool:
    r = record.reliability
    return (not record.insecure and type(r) in (int, float) and math.isfinite(r)
            and MIN_RELIABILITY <= r <= 1.0)


def assess(anchors: list[Record], candidate: Record, intermediates: list[Record] = ()) -> Assessment:
    """Decyzja o kandydacie względem WSZYSTKICH rekordów kotwicy (dane początkowe + profile wskazane przez operatora).
    `intermediates` to wcześniej rozwinięci kandydaci: dowód z nimi trafia do raportu jako łańcuch i nigdy sam nie
    pozwala rozwinąć gałęzi."""
    signals: list[Signal] = []
    contradictions: list[Contradiction] = []
    trusted_control = False
    for anchor in anchors:
        s, c = compare(anchor, candidate)
        signals += s
        contradictions += c
        # The operator supplies initial facts, but fetched anchor content still needs a reliable source.
        trusted = not anchor.insecure and not anchor.conflicts and (anchor.provenance == "operator" or _reliable(anchor))
        if trusted and any(x.group == GROUP_CONTROL and x.level is Level.STRONG for x in s):
            trusted_control = True
    signals = _dedup(signals, lambda s: (s.kind, s.detail))
    contradictions = _dedup(contradictions, lambda c: (c.kind, c.detail))
    level = level_of(signals)
    reasons: list[str] = []
    chain: list[dict] = []
    for mid in intermediates:
        s, _ = compare(mid, candidate)
        chain_level = level_of(s)
        if chain_level > level:
            chain.append({"via": mid.url, "level": chain_level.label, "signals": [x.kind for x in s]})

    if not signals:
        decision = Decision.STOP
        reasons.append("brak dowodu względem danych początkowych (sama zbieżność identyfikatora nie wystarcza)")
    else:
        decision = Decision.REVIEW
        reasons.append(f"dowody: {level.label}")
    hard = [c for c in contradictions if c.hard]
    if hard:
        reasons.append("sprzeczność: " + "; ".join(c.detail for c in hard))
    elif signals and contradictions:
        reasons.append("rozbieżność: " + "; ".join(c.detail for c in contradictions))
    if signals and all(s.copyable for s in signals):
        reasons.append("tylko pola, które da się skopiować: możliwa kopia lub podszycie")
    reliable = _reliable(candidate)
    if signals and not reliable:
        reasons.append("słabe lub nieznane źródło kandydata" if not candidate.insecure
                       else "odpowiedź bez weryfikacji TLS: treść mogła zostać podmieniona")
    if level is Level.STRONG and not trusted_control:
        reasons.append("mocny sygnał pochodzi z niewiarygodnego lub nieznanego źródła kotwicy")
    if level is Level.STRONG and not contradictions and reliable and trusted_control:
        decision = Decision.EXPAND
        reasons.append("mocny dowód kontroli po stronie danych początkowych; kandydat pozostaje hipotezą")
    if chain:
        best = max(chain, key=lambda c: ("brak", "słabe", "umiarkowane", "mocne").index(c["level"]))
        reasons.append(f"łańcuch przez {best['via']} ({best['level']}) nie potwierdza powiązania z danymi początkowymi")
        if decision is Decision.STOP:
            decision = Decision.REVIEW
    return Assessment(level, decision, signals, contradictions, reasons, chain)


def handle_from_url(raw: str) -> str | None:
    """Nazwa konta z adresu profilu (/nick, /@nick, /u/nick, /user/nick). Inne kształty adresu: None."""
    try:
        parts = urlsplit(raw if "://" in raw else "https://" + raw)
    except ValueError:
        return None
    segs = [s for s in parts.path.split("/") if s]
    if len(segs) == 1:
        handle = segs[0]
    elif len(segs) == 2 and segs[0].lower() in {"u", "user", "users", "in", "profile", "people", "c", "channel"}:
        handle = segs[1]
    else:
        return None
    handle = handle.lstrip("@")
    if handle.lower() in _NOT_HANDLES or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,39}", handle):
        return None
    return handle


_NOT_HANDLES = frozenset({"home", "about", "login", "signup", "share", "intent", "search", "explore", "settings",
                          "index.html", "index.php", "contact", "blog", "privacy", "terms", "help"})
