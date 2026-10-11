"""Control-request model: random control names, response comparison and decision tables.

Everything here is a pure function over already received responses; no network and no
engine state. The engine sends the request and feeds the answer back. See
docs/SPEC_CONTROL_REQUEST.md for the rules (sections 2-4).
"""

from __future__ import annotations

import json
import random
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from html import unescape
from urllib.parse import quote, quote_plus, unquote, urljoin, urlsplit

from ultimate_username.detection import (
    DetectionContext,
    DetectionEngine,
    Evaluation,
    ResponseView,
)
from ultimate_username.domain.models import (
    Confidence,
    DetectionEvidence,
    DetectionResult,
    EvidenceSignal,
    ExecutionState,
    IdentifierPolicy,
    Polarity,
    PredicateState,
    RequestPlan,
    Rule,
    TransportResponse,
    Verdict,
)
from ultimate_username.domain.urls import host_without_www
from ultimate_username.domain.validation import walk_rules
from ultimate_username.planning import normalize

# Comparison kinds; they double as reason codes.
CONTROL_UNAVAILABLE = "CONTROL_UNAVAILABLE"
CONTROL_IDENTICAL = "CONTROL_IDENTICAL"
CONTROL_DIFFERS_STRONG = "CONTROL_DIFFERS_STRONG"
CONTROL_DIFFERS_WEAK = "CONTROL_DIFFERS_WEAK"
# Further reason codes.
CONTROL_INCONCLUSIVE = "CONTROL_INCONCLUSIVE"
CONTROL_NONDISCRIMINATING = "CONTROL_NONDISCRIMINATING"
CONTROL_IDENTICAL_ABSENCE = "CONTROL_IDENTICAL_ABSENCE"
CONTROL_DIFFERS_STALE_RULE = "CONTROL_DIFFERS_STALE_RULE"
ACCOUNT_STATE_SIGNATURE = "ACCOUNT_STATE_SIGNATURE"
STATUS_ABSENCE_DONOR_VERIFIED = "STATUS_ABSENCE_DONOR_VERIFIED"
ABSENCE_CONTENT_OVERRIDES_STATUS = "ABSENCE_CONTENT_OVERRIDES_STATUS"
JS_SHELL = "JS_SHELL"
NOT_SUBSTANTIVE = "NOT_SUBSTANTIVE"

SIMILARITY_IDENTICAL = 0.90
SIMILARITY_DISCRIMINATING = 0.50
LENGTH_TOLERANCE = 0.05
SUBSTANTIVE_CHARS = 200
CLIP = 20_000
SIGNATURE_SNIPPET = 2_000
RAW_HEAD, RAW_TAIL = 100_000, 20_000
SHELL_VISIBLE_CHARS = 1_500
HEAVY_RAW_CHARS = 50_000
HEAVY_TEXT_RATIO = 0.02
HEAVY_SCRIPTS = 5
MIN_CONTROL_LENGTH = 8
NAME_LENGTHS = (14, 10, 8, 6, 4, 3)
MAX_REAL_LENGTH = 64
TRIES_PER_LENGTH = 3
ABSENT_STATUSES = (404, 410)


@dataclass(frozen=True, slots=True)
class ControlFlags:
    """One switch per rule so each can be measured and disabled on its own."""

    found: bool = True
    absence: bool = True
    stale_rule: bool = True
    status_absence: bool = True
    content_override: bool = True
    signatures: bool = True


# ------------------------------------------------------------------ control name


def _candidate(rng: random.Random, length: int) -> str:
    letters, digits = "abcdefghijklmnopqrstuvwxyz", "0123456789"
    chars = [rng.choice(letters)]
    run = 1
    for _ in range(length - 1):
        if run >= 2 or rng.random() < 0.4:
            chars.append(rng.choice(digits))
            run = 0
        else:
            chars.append(rng.choice(letters))
            run += 1
    wanted = min(2, length - 1)
    missing = wanted - sum(c in digits for c in chars)
    if missing > 0:
        positions = [i for i in range(1, length) if chars[i] in letters]
        rng.shuffle(positions)
        for index in positions[:missing]:
            chars[index] = rng.choice(digits)
    return "".join(chars)


def control_name(
    rng: random.Random, real: str, identifier: IdentifierPolicy | None = None
) -> str | None:
    """A name that almost certainly does not exist and that the site would accept.

    The first length is the real name's, but never below MIN_CONTROL_LENGTH: a 3-5
    character name drawn from 36 symbols collides with a real account far too easily.
    Then 14, 10, 8, 6, 4 and 3, so a shorter name is used only when the site's
    identifier pattern refuses every longer one. Returns None when no candidate
    passes the site's identifier policy.
    """
    identifier = identifier or IdentifierPolicy()
    first = min(max(len(real), MIN_CONTROL_LENGTH), MAX_REAL_LENGTH)
    lengths = tuple(dict.fromkeys((first, *NAME_LENGTHS)))
    real_cf = real.casefold()
    for length in lengths:
        for _ in range(TRIES_PER_LENGTH):
            name = _candidate(rng, length)
            if name.casefold() in real_cf or real_cf in name.casefold():
                continue
            try:
                specific = normalize(name, identifier).site_specific.casefold()
            except ValueError:
                continue
            if not specific or specific in real_cf or real_cf in specific:
                continue
            return name
    return None


# ------------------------------------------------------------------ normalization

# Every pattern below is linear on hostile input: nothing scans to the end of the text
# once per opening tag. An unclosed block simply runs to the end of the document, as
# a browser would treat it.
_COMMENT = re.compile(r"<!--.*?(?:-->|\Z)", re.S)
_BLOCKS = re.compile(
    r"<(script|style|noscript|template|svg)\b[^<>]{0,2000}>.*?(?:</\1\s*>|\Z)", re.I | re.S
)
_HEAD = re.compile(r"<head\b[^<>]{0,2000}>.*?(?:</head\s*>|(?=<body\b)|\Z)", re.I | re.S)
_TITLE = re.compile(r"<title\b[^<>]{0,200}>([^<]{0,2000})</title\s*>", re.I)
_TAG = re.compile(r"<[^<>]{0,2000}>")
_ISO = re.compile(
    r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?"
)
_CLOCK = re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\b")
_LONG_TOKEN = re.compile(r"[A-Za-z0-9_\-]{16,}")
_LONG_NUMBER = re.compile(r"\d{6,}")
_CJK = "぀-ヿ㐀-鿿가-힯豈-﫿"
_WORDS = re.compile(rf"[^\W{_CJK}]+")
_CJK_RUNS = re.compile(rf"[{_CJK}]+")
_URLS = re.compile(r"https?://[^\s\"'<>]+", re.I)
_ENABLE_JS = re.compile(r"enable javascript|<noscript", re.I)
_EMPTY_ROOT = re.compile(
    r"<body\b[^<>]{0,300}>\s*</body>"
    r"|<div\b[^<>]{0,300}?\bid=[\"'](?:root|app|__next)[\"'][^<>]{0,300}>\s*</div>",
    re.I,
)
_ROOT_DIV = re.compile(r"<div\b[^<>]{0,300}?\bid=[\"'](?:root|app|__next|___gatsby)[\"']", re.I)
_SCRIPT_SRC = re.compile(r"<script\b[^<>]{0,500}?\bsrc\s*=", re.I)
_SCRIPT_TAG = re.compile(r"<script", re.I)
_STATE_MARKERS = ("__NEXT_DATA__", "__INITIAL_STATE__", "__NUXT__", "__APOLLO_STATE__")


def _name_forms(name: str) -> list[str]:
    forms = {name, quote(name, safe=""), quote_plus(name)}
    return sorted((f for f in forms if f), key=len, reverse=True)


def _name_pattern(name: str) -> re.Pattern[str] | None:
    forms = _name_forms(name)
    if not forms:
        return None
    body = "|".join(re.escape(f) for f in forms)
    # A very short name is also a fragment of ordinary words; only whole tokens count.
    if len(name) < 4:
        body = r"(?<!\w)(?:" + body + r")(?!\w)"
    return re.compile(body, re.I)


def clip_raw(text: str) -> str:
    """Keep the first 100 000 and the last 20 000 characters before any processing."""
    if len(text) <= RAW_HEAD + RAW_TAIL + 1:
        return text
    return text[:RAW_HEAD] + "\n" + text[-RAW_TAIL:]


def visible_text(text: str) -> str:
    """Text a visitor would read; JSON is returned unchanged."""
    text = clip_raw(text)
    if text.lstrip()[:1] in ("{", "["):
        return text
    cleaned = _COMMENT.sub(" ", text)
    cleaned = _BLOCKS.sub(" ", cleaned)
    cleaned = _HEAD.sub(" ", cleaned, count=1)
    cleaned = _TITLE.sub(" ", cleaned)
    return unescape(_TAG.sub(" ", cleaned))


def normalize_content(text: str, name: str) -> str:
    """Drop the name and everything that changes between two identical requests."""
    pattern = _name_pattern(name)
    if pattern is not None:
        text = pattern.sub("", text)
    for volatile in (_ISO, _CLOCK, _LONG_TOKEN, _LONG_NUMBER):
        text = volatile.sub(" ", text)
    text = " ".join(text.split()).lower()
    if len(text) > 2 * CLIP:
        text = text[:CLIP] + text[-CLIP:]
    return text


def raw_title(text: str) -> str:
    match = _TITLE.search(clip_raw(text))
    return " ".join(unescape(match.group(1)).split()) if match else ""


def normalize_title(text: str, name: str) -> str:
    return normalize_content(raw_title(text), name)


def normalize_url(url: str, name: str) -> str:
    """Host and path with the name replaced by <n>; query and fragment are dropped."""
    parts = urlsplit(url)
    host, path = parts.hostname or "", unquote(parts.path)
    pattern = _name_pattern(name)
    if pattern is not None:
        host, path = pattern.sub("<n>", host), pattern.sub("<n>", path)
    path = path.rstrip("/")
    return (host + path).lower()


def _words(text: str) -> Counter[str]:
    """Word tokens, plus character bigrams for scripts written without spaces."""
    counter = Counter(_WORDS.findall(text))
    for run in _CJK_RUNS.findall(text):
        if len(run) == 1:
            counter[run] += 1
        else:
            counter.update(run[i : i + 2] for i in range(len(run) - 1))
    return counter


def word_similarity(a: Mapping[str, int], b: Mapping[str, int]) -> float:
    total_a, total_b = sum(a.values()), sum(b.values())
    if not total_a and not total_b:
        return 1.0
    shared = sum(min(count, b.get(word, 0)) for word, count in a.items())
    return shared / max(total_a, total_b)


def similarity(a: str, b: str) -> float:
    return word_similarity(_words(a), _words(b))


# ------------------------------------------------------------------ account state

# Patterns run on text whose whitespace is already collapsed, so a space is always \s+
# and a name or another word may sit in the middle of a phrase.
_DEAD = r"suspended|deleted|deactivated|terminated|closed|banned|locked|disabled"
_SIGNATURES: tuple[tuple[str, str], ...] = (
    (rf"account\s+(?:\S+\s+){{0,3}}(?:has\s+been|was|is)\s+(?:{_DEAD})", "text"),
    (r"user\s+(?:\S+\s+)?(?:has\s+been|was|is)\s+(?:deleted|removed|banned|suspended)", "text"),
    (r"user\s+banned", "text"),
    (r"banned\s+by", "text"),
    (r"(?:suspended|deactivated)\s+account", "text"),
    (r"account\s+(?:suspended|closed|deleted|locked|deactivated)", "text"),
    (r"locked:\s*yes", "text"),
    (r"centralauth-admin-info-locked", "html"),
    (
        r"konto\s+(?:\S+\s+){0,4}"
        r"(?:usunięte|zawieszone|zablokowane|zbanowane|wyłączone|gesperrt|gelöscht|deaktiviert)",
        "text",
    ),
    (
        r"(?:пользовател\w*|аккаунт|профиль|страниц\w*)[^.]{0,40}"
        r"(?:удал[её]н\w*|заблокирован\w*|забанен\w*)",
        "text",
    ),
    (r"탈퇴", "text"),
    (r"정지된", "text"),
    (r"삭제된\s*(?:계정|회원)", "text"),
    (r"(?:账号|帐号|账户|用户)[^。]{0,10}(?:异常|注销|封禁|封停|已删除|被封)", "text"),
    (r"已\s*注销", "text"),
    (r"(?:アカウント|ユーザー)[^。]{0,10}(?:凍結|削除|停止)", "text"),
    (r"cuenta\s+(?:\S+\s+){0,3}(?:suspendida|eliminada|bloqueada|desactivada)", "text"),
    (r"compte\s+(?:\S+\s+){0,3}(?:suspendu|supprimé|désactivé|bloqué)", "text"),
    (r"conta\s+(?:\S+\s+){0,3}(?:suspensa|excluída|desativada|banida)", "text"),
)
_TEXT_SIGNATURES = tuple(re.compile(p, re.I) for p, scope in _SIGNATURES if scope == "text")
_HTML_SIGNATURES = tuple(re.compile(p, re.I) for p, scope in _SIGNATURES if scope == "html")
_INVISIBLE = re.compile("[​-‍⁠﻿]")


def _flat(text: str) -> str:
    """Decode entities and collapse every kind of whitespace (non-breaking too) to one space."""
    return " ".join(_INVISIBLE.sub("", unescape(text)).split())


_BADGE_WORDS = frozenset(
    "banned suspended deactivated deleted terminated locked disabled "
    "zbanowany zablokowany usunięty заблокирован забанен удалён удален".split()
)
_BADGE_CJK = ("정지", "탈퇴", "封禁", "已注销", "凍結")
_BADGE_TOKENS = 3
_BADGE_EDGE = ".,:;!?()[]{}\"'|-–—·•@#*<>/\\"
_BADGE_MAX_NAMES = 20
_JSON_FLAG = re.compile(
    r'"(?:banned|is_banned|suspended|is_suspended|deleted|is_deleted|deactivated)"\s{0,20}:\s{0,20}true',
    re.I,
)
_JSON_NAME_KEY = r'"(?:name|username|login|screen_name|preferredUsername)"\s{0,20}:\s{0,20}"'
JSON_FLAG_DISTANCE = 400


def _badge_word(token: str) -> bool:
    token = token.strip(_BADGE_EDGE).casefold()
    return bool(token) and (token in _BADGE_WORDS or any(w in token for w in _BADGE_CJK))


def _badge(area: str, name: str) -> str:
    """A state word within three tokens of the searched name, before or after it."""
    pattern = re.compile(r"(?<!\w)" + re.escape(name) + r"(?!\w)", re.I)
    for count, match in enumerate(pattern.finditer(area)):
        if count >= _BADGE_MAX_NAMES:
            break
        after = area[match.end() : match.end() + 160].split()[:_BADGE_TOKENS]
        before = area[max(0, match.start() - 160) : match.start()].split()[-_BADGE_TOKENS:]
        if any(_badge_word(t) for t in (*before, *after)):
            return area[max(0, match.start() - 40) : match.end() + 40][:80]
    return ""


def _json_flag(html: str, name: str) -> str:
    """A "banned": true style flag within 400 characters of the name's own key."""
    html = html.replace("&quot;", '"').replace('\\"', '"')
    flags = [m.span() for m in _JSON_FLAG.finditer(html)]
    if not flags:
        return ""
    key = re.compile(_JSON_NAME_KEY + re.escape(name) + '"', re.I)
    for count, match in enumerate(key.finditer(html)):
        if count >= _BADGE_MAX_NAMES:
            break
        for start, end in flags:
            if (
                start - match.end() <= JSON_FLAG_DISTANCE
                and match.start() - end <= JSON_FLAG_DISTANCE
            ):
                return html[start:end][:80]
    return ""


def account_signature(title: str, text: str, html: str = "", name: str = "") -> str:
    """The matched phrase when the page says the account itself is deleted/suspended.

    The window is cut after collapsing whitespace, so markup and non-breaking spaces
    between the navigation and the message cannot push the message out of it. With the
    searched name, a bare state badge next to it ("<name> Banned 0 Posts") counts too,
    and so does a banned/suspended/deleted true flag beside the name key in raw JSON.
    """
    area = _flat(title) + " \n " + _flat(clip_raw(text))[:SIGNATURE_SNIPPET]
    for pattern in _TEXT_SIGNATURES:
        match = pattern.search(area)
        if match:
            return match.group(0)[:80]
    html = clip_raw(html)
    for pattern in _HTML_SIGNATURES:
        match = pattern.search(html)
        if match:
            return match.group(0)[:80]
    if name:
        return _badge(area, name) or _json_flag(html, name)
    return ""


# ------------------------------------------------------------------ facts


@dataclass(frozen=True, slots=True)
class PageFacts:
    status: int | None = 200
    final: str = ""
    title: str = ""
    length: int = 0
    words: Mapping[str, int] = field(default_factory=dict)
    text_len: int = 0
    name_in_title: bool = False
    name_in_text: bool = False
    js_shell: bool = False
    signature: str = ""
    redirects_away: bool = False


def _marker_shell(full: str, raw: str, text_length: int) -> bool:
    """A page whose content is rendered by scripts: framework markers and little text."""
    if bool(_ENABLE_JS.search(raw)) and bool(_EMPTY_ROOT.search(raw)):
        return True
    if text_length >= SHELL_VISIBLE_CHARS:
        return False
    if any(marker in full for marker in _STATE_MARKERS):
        return True
    return bool(_ROOT_DIV.search(full)) and bool(_SCRIPT_SRC.search(full))


def _heavy_shell(raw: str, text_length: int) -> bool:
    """A very large document that is almost all script data and little readable text."""
    if len(raw) < HEAVY_RAW_CHARS or raw.lstrip()[:1] in ("{", "["):
        return False
    if text_length < HEAVY_TEXT_RATIO * len(raw):
        return True
    return text_length < SHELL_VISIBLE_CHARS and len(_SCRIPT_TAG.findall(raw)) >= HEAVY_SCRIPTS


def page_facts(response: TransportResponse, name: str) -> PageFacts:
    view = ResponseView(response)
    full = view.text
    raw = clip_raw(full)
    visible = visible_text(raw)
    text = normalize_content(visible, name)
    title = raw_title(raw)
    # Only what a visitor reads counts: a title is rendered even for an empty shell,
    # and a URL in the body only echoes the requested name.
    folded = name.casefold()
    named = bool(name) and folded in _URLS.sub(" ", visible).casefold()
    titled = bool(name) and folded in title.casefold()
    status = response.status
    requested = normalize_url(response.requested_url, name)
    target = response.final_url or response.requested_url
    location = response.header("Location")
    if status is not None and 300 <= status < 400 and location:
        target = urljoin(response.requested_url, location)
    final = normalize_url(target, name)
    shell = _marker_shell(full, raw, len(text)) or _heavy_shell(raw, len(text))
    return PageFacts(
        status=status,
        final=final,
        title=normalize_content(title, name),
        length=len(text),
        words=_words(text),
        text_len=len(text),
        name_in_title=titled,
        name_in_text=named,
        js_shell=len(text) < SUBSTANTIVE_CHARS or shell,
        signature=account_signature(title, visible, raw, name),
        redirects_away="<n>" in requested and "<n>" not in final,
    )


# ------------------------------------------------------------------ rule outcome


@dataclass(frozen=True, slots=True)
class RuleOutcome:
    present: PredicateState
    absent: PredicateState
    present_content: bool = False
    absent_content: bool = False
    present_status_only: bool = False
    absent_status_only: bool = False


def _status_only(rule: Rule | None) -> bool:
    if rule is None:
        return False
    return all(r.strategy == "status" for r in walk_rules(rule) if not r.children)


def rule_outcome(
    detector: DetectionEngine,
    response: TransportResponse,
    plan: RequestPlan,
    view: ResponseView | None = None,
) -> RuleOutcome | None:
    """Re-evaluate the catalog's present/absent trees; None if a strategy raises."""
    spec = plan.site.detection
    view = view or ResponseView(response)
    empty = Evaluation(PredicateState.FALSE, ())
    try:
        positive = (
            detector.evaluate(
                spec.present,
                view,
                DetectionContext(plan, Polarity.PRESENT, "present", detector.regex_timeout),
            )
            if spec.present
            else empty
        )
        negative = (
            detector.evaluate(
                spec.absent,
                view,
                DetectionContext(plan, Polarity.ABSENT, "absent", detector.regex_timeout),
            )
            if spec.absent
            else empty
        )
    except Exception:
        return None
    return RuleOutcome(
        positive.state,
        negative.state,
        positive.content_signal,
        negative.content_signal,
        _status_only(spec.present),
        _status_only(spec.absent),
    )


def classify_unknown(detection: DetectionResult, rules: RuleOutcome | None) -> str:
    """A, B, C or D (section 0 of the spec); empty when the result is not a candidate."""
    if (
        rules is None
        or detection.state != ExecutionState.OK
        or detection.verdict != Verdict.UNKNOWN
        or detection.response_class != "INSUFFICIENT_EVIDENCE"
        or not detection.reasons
    ):
        return ""
    t, f = PredicateState.TRUE, PredicateState.FALSE
    first = detection.reasons[0]
    if first == "CONTRADICTORY_EVIDENCE":
        return "D" if rules.present == t and rules.absent == t else ""
    if first in ("WEAK_STATUS_ONLY_DEFINITION", "NO_PROFILE_SPECIFIC_EVIDENCE"):
        return "A" if rules.present == t and rules.absent == f else ""
    if detection.reasons == ("INSUFFICIENT_EVIDENCE",):
        if rules.absent == t and rules.present == f:
            return "C"
        if rules.present != t and rules.absent != t:
            return "B"
    return ""


# ------------------------------------------------------------------ comparison


@dataclass(frozen=True, slots=True)
class ControlObservation:
    facts: PageFacts
    rules: RuleOutcome
    name: str
    seed: int
    cached: bool = False
    # Name-independent digests of the control page's title and social meta values; enrichment
    # drops a field equal to one of them (CONTROL_SAME_VALUE).
    digests: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class ControlComparison:
    kind: str
    diffs: tuple[str, ...] = ()
    similarity: float = 0.0
    # The control looks like a missing page: 404/410, the absent rule fires, or it
    # redirects away. Class B relies on this alone.
    absent_like_strict: bool = False
    # The control does not satisfy the present rule. For class A, whose real page did,
    # that is information too; for class B (the real page missed it as well) it is not.
    control_present_miss: bool = False
    control_rule_found: bool = False

    @property
    def absent_like_a(self) -> bool:
        return self.absent_like_strict or self.control_present_miss


def _hit(state: PredicateState) -> bool:
    return state == PredicateState.TRUE


def compare(
    real: PageFacts, real_rules: RuleOutcome, control: ControlObservation | None
) -> ControlComparison:
    if control is None:
        return ControlComparison(CONTROL_UNAVAILABLE)
    other, control_rules = control.facts, control.rules
    diffs: list[str] = []
    if real.status != other.status:
        diffs.append("status")
    if real.final != other.final:
        diffs.append("url")
    if real.title != other.title:
        diffs.append("title")
    if (_hit(real_rules.present), _hit(real_rules.absent)) != (
        _hit(control_rules.present),
        _hit(control_rules.absent),
    ):
        diffs.append("rule")
    longest = max(real.length, other.length)
    length_close = longest == 0 or abs(real.length - other.length) / longest < LENGTH_TOLERANCE
    if not length_close:
        diffs.append("length")
    score = word_similarity(real.words, other.words)
    if score < SIMILARITY_IDENTICAL:
        diffs.append("similarity")
    identical = (
        not {"status", "url", "title"} & set(diffs)
        and length_close
        and score >= SIMILARITY_IDENTICAL
    )
    strong = bool({"status", "url", "title", "rule"} & set(diffs))
    kind = (
        CONTROL_IDENTICAL
        if identical
        else CONTROL_DIFFERS_STRONG
        if strong
        else CONTROL_DIFFERS_WEAK
    )
    strict = other.status in ABSENT_STATUSES or _hit(control_rules.absent) or other.redirects_away
    return ControlComparison(
        kind,
        tuple(diffs),
        score,
        strict,
        not _hit(control_rules.present),
        _hit(control_rules.present) and not _hit(control_rules.absent),
    )


# ------------------------------------------------------------------ decisions


@dataclass(frozen=True, slots=True)
class Decision:
    verdict: Verdict
    reasons: tuple[str, ...]
    strength: str = ""
    level: int = 0
    response_class: str = ""


def _unknown(*reasons: str) -> Decision:
    return Decision(Verdict.UNKNOWN, reasons)


def unavailable(*detail: str) -> Decision:
    return _unknown(CONTROL_UNAVAILABLE, *detail)


def wants_request(klass: str, flags: ControlFlags) -> bool:
    if klass == "A":
        return flags.found
    if klass == "B":
        return flags.absence or flags.stale_rule
    return False


def signature_decision(klass: str, real: PageFacts, flags: ControlFlags) -> Decision | None:
    """Class A is decided by the page alone when it states the account is gone."""
    if flags.signatures and klass == "A" and real.signature:
        return _unknown(ACCOUNT_STATE_SIGNATURE)
    return None


def substantive_a(real: PageFacts, rules: RuleOutcome) -> bool:
    """Class A: is there enough page to tell a profile from an empty 200 shell?

    A title alone never vouches for a status-only rule: a removed account may still
    serve a bare 200 page titled with the name while a missing name returns 404.
    A script-heavy page is not penalised here, only a page without text or name.
    """
    if real.text_len >= SUBSTANTIVE_CHARS or real.name_in_text:
        return True
    return rules.present_content and real.name_in_title


def _positive(verdict: Verdict, reason: str, strength: str, level: int) -> Decision:
    return Decision(verdict, (reason,), strength, level, "PROFILE_CANDIDATE")


def _absence(reason: str, level: int) -> Decision:
    return Decision(Verdict.NOT_FOUND, (reason,), "COMPOSITE", level, "NOT_FOUND")


def _decide_a(
    real: PageFacts, rules: RuleOutcome, cmp: ControlComparison, flags: ControlFlags
) -> Decision:
    early = signature_decision("A", real, flags)
    if early:
        return early
    if cmp.kind == CONTROL_UNAVAILABLE:
        return unavailable()
    if not flags.found:
        return _unknown(CONTROL_INCONCLUSIVE)
    if cmp.kind == CONTROL_IDENTICAL or (
        cmp.control_rule_found and cmp.similarity >= SIMILARITY_IDENTICAL
    ):
        return _unknown(CONTROL_IDENTICAL)
    content, substantive = rules.present_content, substantive_a(real, rules)
    if cmp.kind == CONTROL_DIFFERS_STRONG:
        if substantive and cmp.absent_like_a:
            if content:
                return _positive(Verdict.FOUND, CONTROL_DIFFERS_STRONG, "MODERATE", 2)
            return _positive(Verdict.PROBABLE, CONTROL_DIFFERS_STRONG, "MODERATE", 2)
        # The control passes the same rule and is not a missing page: the rule cannot
        # tell the two names apart unless the pages themselves are really different.
        if (
            substantive
            and content
            and (not cmp.control_rule_found or cmp.similarity < SIMILARITY_DISCRIMINATING)
        ):
            return _positive(Verdict.PROBABLE, CONTROL_DIFFERS_STRONG, "WEAK", 2)
    if substantive and cmp.control_rule_found:
        return _unknown(CONTROL_NONDISCRIMINATING)
    base = CONTROL_DIFFERS_WEAK if cmp.kind == CONTROL_DIFFERS_WEAK else CONTROL_INCONCLUSIVE
    return _unknown(base) if substantive else _unknown(base, NOT_SUBSTANTIVE)


def _decide_b(real: PageFacts, cmp: ControlComparison, flags: ControlFlags) -> Decision:
    if cmp.kind == CONTROL_UNAVAILABLE:
        return unavailable()
    status = real.status or 0
    if cmp.kind == CONTROL_IDENTICAL:
        two_xx = 200 <= status < 300
        if two_xx and real.js_shell:
            return _unknown(CONTROL_IDENTICAL, JS_SHELL)
        away = 300 <= status < 400 and real.redirects_away
        if flags.absence:
            if status in ABSENT_STATUSES or away:
                return _absence(CONTROL_IDENTICAL_ABSENCE, 2)
            if two_xx:  # a soft 404 that is not even a shell is weaker evidence
                return _absence(CONTROL_IDENTICAL_ABSENCE, 1)
        return _unknown(CONTROL_INCONCLUSIVE)
    if (
        flags.stale_rule
        and cmp.kind == CONTROL_DIFFERS_STRONG
        and 200 <= status < 300
        and cmp.absent_like_strict
        and real.name_in_text
        and real.text_len >= SUBSTANTIVE_CHARS
        and not real.js_shell
    ):
        if flags.signatures and real.signature:
            return _unknown(ACCOUNT_STATE_SIGNATURE)
        return _positive(Verdict.PROBABLE, CONTROL_DIFFERS_STALE_RULE, "WEAK", 1)
    return _unknown(CONTROL_INCONCLUSIVE)


def decide_with_control(
    klass: str,
    real: PageFacts,
    rules: RuleOutcome,
    cmp: ControlComparison,
    flags: ControlFlags,
) -> Decision:
    if klass == "A":
        return _decide_a(real, rules, cmp, flags)
    if klass == "B":
        return _decide_b(real, cmp, flags)
    raise ValueError("Control comparison only applies to classes A and B")


def decide_no_request(
    klass: str,
    rules: RuleOutcome,
    status: int | None,
    final_url: str,
    probe_url: str,
    donor_verified: bool,
    flags: ControlFlags,
) -> Decision | None:
    """Classes C and D need no request: only the received response and the catalog."""
    if klass == "C" and flags.status_absence:
        final, probe = urlsplit(final_url), urlsplit(probe_url)
        homepage = final.path in ("", "/") and probe.path not in ("", "/")
        if (
            rules.absent_status_only
            and status in ABSENT_STATUSES
            and donor_verified
            and host_without_www(final.hostname or "") == host_without_www(probe.hostname or "")
            and not homepage
        ):
            return _absence(STATUS_ABSENCE_DONOR_VERIFIED, 1)
    if (
        klass == "D"
        and flags.content_override
        and rules.present_status_only
        and rules.absent_content
    ):
        return _absence(ABSENCE_CONTENT_OVERRIDES_STATUS, 2)
    return None


# ------------------------------------------------------------------ evidence


def comparison_record(
    klass: str,
    real: PageFacts,
    cmp: ControlComparison,
    control: ControlObservation | None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "kind": cmp.kind,
        "class": klass,
        "diffs": list(cmp.diffs),
        "status_real": real.status,
        "title_real": real.title[:120],
        "len_real": real.length,
        "similarity": round(cmp.similarity, 3),
        "absent_like": cmp.absent_like_strict,
        "control_present_miss": cmp.control_present_miss,
    }
    if control is not None:
        record.update(
            status_control=control.facts.status,
            title_control=control.facts.title[:120],
            len_control=control.facts.length,
            control_name=control.name,
            seed=control.seed,
            cached=control.cached,
        )
    return record


def apply_decision(
    detection: DetectionResult, decision: Decision, record: Mapping[str, object]
) -> DetectionResult:
    """Fold a decision into the detection, keeping state and invariants untouched."""
    verdict = decision.verdict
    polarity = (
        Polarity.PRESENT
        if verdict in (Verdict.FOUND, Verdict.PROBABLE)
        else Polarity.ABSENT
        if verdict == Verdict.NOT_FOUND
        else Polarity.CONTEXT
    )
    code = decision.reasons[0]
    evidence = DetectionEvidence(
        "control",
        "control_request",
        polarity,
        PredicateState.TRUE,
        json.dumps(record, ensure_ascii=False, sort_keys=True, default=str),
        locator=code,
    )
    level = decision.level
    weight = level if polarity == Polarity.PRESENT else -level if polarity == Polarity.ABSENT else 0
    signal = EvidenceSignal(
        code,
        "control_request",
        "MODERATE" if level >= 2 else "WEAK",
        weight,
        "control",
        code,
        "control",
    )
    reasons = tuple(dict.fromkeys((*decision.reasons, *detection.reasons)))
    if verdict == Verdict.UNKNOWN:
        return replace(
            detection,
            reasons=reasons,
            evidence=detection.evidence + (evidence,),
            signals=detection.signals + (signal,),
        )
    return replace(
        detection,
        verdict=verdict,
        reasons=decision.reasons,
        confidence=Confidence(
            strength=decision.strength,
            reason="Control-request comparison; no probability model",
        ),
        response_class=decision.response_class,
        evidence_level=level,
        evidence=detection.evidence + (evidence,),
        signals=detection.signals + (signal,),
    )
