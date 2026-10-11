"""Optional username variants (separators, initials, years, leet) with a hard cap.

Every variant is a full scan, so the generator is bounded and opt-in (``--variants``).
Port of the OSINT engine's ``variants.py``; pure text, no I/O.
"""

from __future__ import annotations

import re
import unicodedata

SEPARATORS = ("", ".", "_", "-")
LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5"})
ALLOWED = re.compile(r"^[a-z0-9._-]{2,40}$")


def ascii_fold(text: str) -> str:
    """'Łukasz Żółć' -> 'lukasz zolc' (ł does not decompose under NFKD, so it is mapped first)."""
    text = text.replace("ł", "l").replace("Ł", "L")
    norm = unicodedata.normalize("NFKD", text)
    return "".join(c for c in norm if not unicodedata.combining(c)).lower()


def split_parts(text: str) -> list[str]:
    """'Jan Kowalski' / 'JanKowalski' -> [jan, kowalski]; 'Sampler51' -> [sampler, 51]."""
    text = re.sub(r"(?<=[a-ząćęłńóśźż])(?=[A-ZĄĆĘŁŃÓŚŹŻ])", " ", text.strip())
    text = re.sub(r"(?<=[^\W\d_])(?=\d)|(?<=\d)(?=[^\W\d_])", " ", text)
    return [p for p in re.split(r"[\s._\-]+", ascii_fold(text)) if p]


def _person_tiers(parts: list[str]) -> tuple[list[str], list[str]]:
    """(most common, rarer) patterns of account names."""
    first, last = parts[0], parts[-1]
    common = [f"{first}{sep}{last}" for sep in SEPARATORS]
    common += [f"{first[0]}{sep}{last}" for sep in SEPARATORS]
    rare = [f"{last}{sep}{first}" for sep in SEPARATORS]
    rare += [f"{first}{sep}{last[0]}" for sep in SEPARATORS]
    rare += [f"{last}{sep}{first[0]}" for sep in SEPARATORS]
    rare += [first, last]
    return common, rare


def generate(
    text: str,
    years: list[int] | None = None,
    leet: bool = False,
    limit: int = 20,
) -> list[str]:
    """Variants from most to least likely; the typed name (normalised) always comes first.

    text: one name ('jkowalski') or a person ('Jan Kowalski').
    years: numeric suffixes, e.g. [1990, 90] -> 'jankowalski1990', 'jankowalski90'.
    """
    if limit < 1:
        return []
    parts = split_parts(text)
    if not parts:
        return []
    base = "".join(parts)
    words = [p for p in parts if not p.isdigit()]
    number = "".join(p for p in parts if p.isdigit())
    leet_v = [base.translate(LEET)] if leet else []

    common: list[str]
    rare: list[str]
    if len(words) > 1:
        common, rare = _person_tiers(words)
    else:
        common, rare = (words[:1], []) if words else ([], [])
    core = "".join(words)

    if number and words:
        with_num = [f"{w}{sep}{number}" for w in common[:2] for sep in SEPARATORS]
        front = [f"{number}{sep}{core}" for sep in SEPARATORS]
        with_years = [v for y in years or [] for v in (f"{core}{y}", f"{core}_{y}")]
        candidates = (
            [base]
            + with_num
            + common
            + with_years
            + leet_v
            + front
            + [f"{w}{sep}{number}" for w in common[2:] + rare for sep in ("", "_")]
        )
    else:
        with_years = [v for y in years or [] for v in (f"{base}{y}", f"{base}_{y}")]
        if len(words) > 1:
            # explicit years and leet are a user hint: before the rarer patterns
            candidates = [base] + common + with_years + leet_v + rare
        else:
            candidates = (
                [base]
                + with_years
                + leet_v
                + [
                    base + "_",
                    "_" + base,
                    base + "1",
                    base + "official",
                    "the" + base,
                    "real" + base,
                ]
            )

    typed = re.sub(r"\s+", "", ascii_fold(text))
    out: list[str] = []
    for c in [typed, *candidates]:
        if ALLOWED.match(c) and c not in out:
            out.append(c)
        if len(out) >= limit:
            break
    return out
