"""Country clues from profile metadata: location text, flag emoji, bio script, TLD, site tags.

Offline and opt-in (``--geo``). Port of the OSINT engine's ``geo.py``, adapted to Ultimate's
profile metadata. The result is always a percentage with the source of every clue (site + field):
an inference from clues, never a fact. The built-in dictionary covers countries (EN/PL/native)
and larger cities; an optional larger gazetteer JSON (``{"countries": {...}, "cities": {...}}``,
e.g. built from GeoNames, CC BY 4.0) can be passed explicitly and is not bundled (about 2.7 MB).
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from ultimate_username.domain.models import JSONValue, SearchResult, Verdict
from ultimate_username.registry import SiteRegistry
from ultimate_username.variants import ascii_fold

ISO2 = set(
    """AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI
BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN
CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK
FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM
HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN
KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK
ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP
NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW
SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF
TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI
VN VU WF WS YE YT ZA ZM ZW""".split()
)

US_STATES = set(
    """AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ
NM NY
NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC""".split()
)

# ccTLDs used globally like generic domains say nothing about the country
GENERIC_TLDS = {
    "io",
    "co",
    "tv",
    "me",
    "ai",
    "gg",
    "fm",
    "ly",
    "to",
    "cc",
    "ws",
    "sh",
    "ac",
    "app",
    "so",
    "is",
    "la",
    "am",
    "im",
    "nu",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "vc",
    "sx",
    "pw",
    "lc",
    "gl",
    "ms",
    "st",
    "cx",
}

_BUILTIN_COUNTRIES = {
    "PL": "poland polska rzeczpospolita polen pologne",
    "DE": "germany niemcy deutschland allemagne",
    "UA": "ukraine ukraina украина україна",
    "RU": "russia rosja россия rossiya",
    "BY": "belarus bialorus białoruś беларусь",
    "CZ": "czech republic czechia czechy cesko česko",
    "SK": "slovakia slowacja słowacja slovensko",
    "LT": "lithuania litwa lietuva",
    "GB": "united kingdom uk great britain england scotland wales wielka brytania anglia",
    "US": "united states usa america stany zjednoczone",
    "FR": "france francja",
    "IT": "italy wlochy włochy italia",
    "ES": "spain hiszpania espana españa",
    "NL": "netherlands holandia nederland holland",
    "IE": "ireland irlandia",
    "NO": "norway norwegia norge",
    "SE": "sweden szwecja sverige",
    "AT": "austria osterreich österreich",
    "CA": "canada kanada",
    "AU": "australia",
    "BR": "brazil brazylia brasil",
    "IN": "india indie",
    "CN": "china chiny",
    "JP": "japan japonia",
    "TR": "turkey turcja turkiye türkiye",
}
_MULTIWORD = {
    "united kingdom",
    "great britain",
    "united states",
    "czech republic",
    "wielka brytania",
    "stany zjednoczone",
}
_BUILTIN_CITIES = {
    "PL": "warszawa warsaw krakow kraków cracow wroclaw wrocław poznan poznań gdansk gdańsk "
    "lodz łódź szczecin lublin katowice bialystok białystok gdynia czestochowa częstochowa "
    "rzeszow rzeszów torun toruń "
    "bydgoszcz kielce olsztyn opole radom sopot zakopane",
    "DE": "berlin munich münchen hamburg frankfurt cologne köln",
    "GB": "london manchester birmingham edinburgh glasgow",
    "UA": "kyiv kiev lviv lwow lwów kharkiv odesa odessa",
    "RU": "moscow moskwa москва saint petersburg petersburg",
    "US": "new york los angeles chicago san francisco seattle boston",
    "FR": "paris paryż lyon marseille",
}


def _builtin() -> tuple[dict[str, str], dict[str, str]]:
    countries: dict[str, str] = {}
    cities: dict[str, str] = {}
    for cc, names in _BUILTIN_COUNTRIES.items():
        for multi in _MULTIWORD:
            if multi in names:
                countries[ascii_fold(multi)] = cc
                names = names.replace(multi, "")
        for n in names.split():
            countries[ascii_fold(n)] = cc
    for cc, names in _BUILTIN_CITIES.items():
        for multi in ("los angeles", "new york", "san francisco", "saint petersburg"):
            if multi in names:
                cities[multi] = cc
                names = names.replace(multi, "")
        for n in names.split():
            cities[ascii_fold(n)] = cc
    return countries, cities


class Gazetteer:
    def __init__(self, path: str | Path | None = None) -> None:
        self.countries, self.cities = _builtin()
        if path:
            doc = json.loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                raise ValueError("gazetteer: expected a JSON object")
            countries, cities = (doc.get("countries", {}), doc.get("cities", {}))
            if not (isinstance(countries, dict) and isinstance(cities, dict)):
                raise ValueError("gazetteer: 'countries' and 'cities' must be objects")
            for table in (countries, cities):
                if not all(isinstance(k, str) and isinstance(v, str) for k, v in table.items()):
                    raise ValueError("gazetteer: entries must map text to a country code")
            self.countries.update(countries)
            for k, v in cities.items():
                self.cities.setdefault(k, v)

    def resolve(self, text: str) -> tuple[str, float, str] | None:
        """(country code, confidence 0-1, what matched) or None."""
        if not text:
            return None
        flag = flag_country(text)
        if flag:
            return flag, 0.9, "flag emoji"
        raw_parts = [p.strip() for p in re.split(r"[,/|;·•()\n]+", text) if p.strip()]
        for raw in reversed(raw_parts):  # kraj zwykle na końcu: "Kraków, Poland"
            if not re.fullmatch(r"[A-Z]{2}", raw):
                continue
            if raw in US_STATES:
                # "San Jose, CA" to Kalifornia, nie Kanada: miasto z USA obok skrótu rozstrzyga
                others = [self.cities.get(ascii_fold(p)) for p in raw_parts if p != raw]
                if "US" in others:
                    return "US", 0.85, f"{raw} (US state)"
                if raw in ISO2 and raw not in {"IN", "ME"}:
                    return raw, 0.4, f"{raw} (ambiguous: country or US state)"
                continue
            if raw in ISO2 and raw not in {"IT", "TO", "AT"}:
                return raw, 0.8, raw
        folded = [ascii_fold(p) for p in raw_parts] or [ascii_fold(text)]
        for part in reversed(folded):
            if part in self.countries:
                return self.countries[part], 1.0, part
        for part in folded:
            if part in self.cities:
                return self.cities[part], 0.85, part
        orig = re.findall(r"[\w']+", text)
        words = [ascii_fold(w) for w in orig]
        grams = [(" ".join(words[i : i + 2]), orig[i]) for i in range(len(words) - 1)] + list(
            zip(words, orig, strict=True)
        )
        for g, _ in grams:
            if len(g) > 3 and g in self.countries:
                return self.countries[g], 0.9, g
        for g, first in grams:
            # miasto w środku tekstu tylko pisane wielką literą: "somewhere nice" to nie Nicea
            if len(g) > 3 and g in self.cities and (first[:1].isupper() or not first[:1].isascii()):
                return self.cities[g], 0.7, g
        return None


def flag_country(text: str) -> str | None:
    """🇵🇱 = dwa znaki 'regional indicator' -> 'PL'."""
    m = re.search("([\U0001f1e6-\U0001f1ff])([\U0001f1e6-\U0001f1ff])", text)
    if not m:
        return None
    cc = chr(ord(m.group(1)) - 0x1F1E6 + 65) + chr(ord(m.group(2)) - 0x1F1E6 + 65)
    return cc if cc in ISO2 else None


def language_country(text: str) -> tuple[str, str] | None:
    """Słaba wskazówka z pisowni: (kraj, opis). Tylko znaki jednoznaczne dla języka."""
    if not text:
        return None
    if re.search(r"[ąćęłńśźżĄĆĘŁŃŚŹŻ]", text):
        return "PL", "Polish characters in text"
    if re.search(r"[іїєґІЇЄҐ]", text):
        return "UA", "Ukrainian letters in text"
    if re.search(r"[ыэъЫЭЪ]", text):
        return "RU", "Russian letters in text"
    if re.search(r"[řůŘŮ]", text):
        return "CZ", "Czech characters in text"
    return None


def tld_country(url: str) -> str | None:
    host = urlsplit(url).netloc.lower().split(":")[0]
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in GENERIC_TLDS or len(tld) != 2:
        return None
    cc = "GB" if tld == "uk" else tld.upper()
    return cc if cc in ISO2 else None


WEIGHTS = {
    "location": 1.0,
    "nationality": 1.0,
    "language": 0.4,
    "page_lang": 0.1,
    "tld": 0.15,
    "tag": 0.1,
}

# Only languages that point to one country; ambiguous ones (en, de, es, fr, pt, nl) are skipped.
_PAGE_LANG = {
    "pl": "PL",
    "cs": "CZ",
    "sk": "SK",
    "uk": "UA",
    "lt": "LT",
    "lv": "LV",
    "et": "EE",
    "hu": "HU",
    "ro": "RO",
    "bg": "BG",
    "hr": "HR",
    "sl": "SI",
    "ja": "JP",
    "tr": "TR",
}


@dataclass(frozen=True, slots=True)
class GeoSource:
    """One matched profile: where it was found and the metadata fields that were observed."""

    site: str
    profile_url: str
    fields: Mapping[str, str]
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GeoHint:
    country: str
    weight: float
    site: str
    field: str  # metadata field (or profile_url / tags) the clue comes from
    signal: str  # key of WEIGHTS
    detail: str  # what matched, e.g. 'Kraków' or '.pl'


def page_lang_country(value: str) -> str | None:
    """'pl-PL' -> PL (region subtag), 'cs' -> CZ (unambiguous language), otherwise None."""
    tag = value.strip().replace("_", "-")
    if not re.fullmatch(r"[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*", tag):
        return None
    lang, *rest = tag.split("-")
    for part in rest:
        if re.fullmatch(r"[A-Za-z]{2}", part) and part.upper() in ISO2:
            return part.upper()
    return _PAGE_LANG.get(lang.lower())


def source_hints(source: GeoSource, gaz: Gazetteer) -> list[GeoHint]:
    hints: list[GeoHint] = []
    for field in ("location", "nationality"):
        value = source.fields.get(field)
        hit = gaz.resolve(value) if value else None
        if value and hit:
            country, confidence, matched = hit
            hints.append(
                GeoHint(
                    country,
                    WEIGHTS[field] * confidence,
                    source.site,
                    field,
                    field,
                    matched[:60] or value[:60],
                )
            )
    tld = tld_country(source.profile_url)
    for field in ("bio", "display_name"):
        lang = language_country(source.fields.get(field, ""))
        # a national service's own page text would double-count with its own domain
        if lang and lang[0] != tld:
            hints.append(
                GeoHint(lang[0], WEIGHTS["language"], source.site, field, "language", lang[1])
            )
            break
    page_lang = source.fields.get("page_lang") or source.fields.get("language")
    plc = page_lang_country(page_lang) if page_lang else None
    if page_lang and plc and plc != tld:
        hints.append(
            GeoHint(
                plc, WEIGHTS["page_lang"], source.site, "page_lang", "page_lang", page_lang[:20]
            )
        )
    if tld:
        hints.append(
            GeoHint(tld, WEIGHTS["tld"], source.site, "profile_url", "tld", "." + tld.lower())
        )
    elif "global" not in {t.lower() for t in source.tags}:
        # a country tag on a global service (e.g. global + de) describes the operator, not the user
        tags = [
            t.upper()
            for t in source.tags
            if len(t) == 2 and t.upper() in ISO2 and t.upper() != "US"
        ]
        if len(tags) == 1:
            hints.append(GeoHint(tags[0], WEIGHTS["tag"], source.site, "tags", "tag", tags[0]))
    return hints


def strength(score: float) -> str:
    return "strong" if score >= 1.5 else "medium" if score >= 0.5 else "weak"


def aggregate(hints: Iterable[GeoHint], top: int = 3) -> list[JSONValue]:
    """Countries ranked by summed weight. ``percent`` is the share of the votes (which country),
    ``strength`` says how far to trust it: a lone .pl domain is 100% of the votes but weak."""
    score: dict[str, float] = defaultdict(float)
    by_country: dict[str, list[GeoHint]] = defaultdict(list)
    for hint in hints:
        score[hint.country] += hint.weight
        by_country[hint.country].append(hint)
    total = sum(score.values())
    if not total:
        return []
    ranked = sorted(score.items(), key=lambda kv: -kv[1])[:top]
    out: list[JSONValue] = []
    for country, value in ranked:
        evidence: list[JSONValue] = [
            {
                "site": h.site,
                "field": h.field,
                "signal": h.signal,
                "weight": round(h.weight, 2),
                "detail": h.detail,
            }
            for h in by_country[country][:8]
        ]
        out.append(
            {
                "country": country,
                "percent": round(100 * value / total),
                "score": round(value, 2),
                "strength": strength(value),
                "evidence": evidence,
            }
        )
    return out


def sources_from_results(
    results: Iterable[SearchResult], registry: SiteRegistry
) -> list[GeoSource]:
    """Metadata of confirmed hits (FOUND/PROBABLE) as geo input; conflicting fields are dropped."""
    sources: list[GeoSource] = []
    for result in results:
        if not result.attempts or result.detection.verdict not in (Verdict.FOUND, Verdict.PROBABLE):
            continue
        metadata = result.profile_metadata
        fields = {
            f.name: f.value
            for f in metadata.fields + metadata.extra_fields
            if isinstance(f.value, str) and f.name not in metadata.conflicts
        }
        entry = registry.get(result.site_id)
        definition = entry.definition if entry else None
        sources.append(
            GeoSource(
                definition.name if definition else result.site_id,
                result.profile_url,
                fields,
                definition.tags if definition else (),
            )
        )
    return sources


def geo_section(
    sources: Iterable[GeoSource], gazetteer: Gazetteer | None = None, top: int = 3
) -> dict[str, JSONValue]:
    """The ``geo`` section of the output document."""
    gaz = gazetteer or Gazetteer()
    hints: list[GeoHint] = []
    count = 0
    for source in sources:
        count += 1
        hints.extend(source_hints(source, gaz))
    return {
        "profiles_considered": count,
        "countries": aggregate(hints, top),
        "note": "Inference from clues (location, language, domain, tags), not a fact.",
    }
