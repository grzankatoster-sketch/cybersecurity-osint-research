"""Kraj z poszlak: tekst lokalizacji, flaga emoji, język bio, domena serwisu. Offline.

Pełny słownik miast/krajów: scripts/build_geo.py -> data/geo.json (GeoNames, CC BY 4.0).
Bez niego działa wbudowany słownik podstawowy (kraje EN/PL/natywnie + większe miasta PL).
Wynik to zawsze procent z uzasadnieniem — wniosek z poszlak, nie fakt."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .variants import ascii_fold

ISO2 = set("""AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW
BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE
KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV
MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC
SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ
VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW""".split())

US_STATES = set("""AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY
NC ND OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC""".split())

# ccTLD używane globalnie jak domeny ogólne — nie świadczą o kraju
GENERIC_TLDS = {"io", "co", "tv", "me", "ai", "gg", "fm", "ly", "to", "cc", "ws", "sh", "ac", "app", "so", "is",
                "la", "am", "im", "nu", "tk", "ml", "ga", "cf", "gq", "vc", "sx", "pw", "lc", "gl", "ms", "st", "cx"}

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
_MULTIWORD = {"united kingdom", "great britain", "united states", "czech republic", "wielka brytania",
              "stany zjednoczone"}
_BUILTIN_CITIES = {
    "PL": "warszawa warsaw krakow kraków cracow wroclaw wrocław poznan poznań gdansk gdańsk lodz łódź szczecin "
          "lublin katowice bialystok białystok gdynia czestochowa częstochowa rzeszow rzeszów torun toruń "
          "bydgoszcz kielce olsztyn opole radom sopot zakopane",
    "DE": "berlin munich münchen hamburg frankfurt cologne köln",
    "GB": "london manchester birmingham edinburgh glasgow",
    "UA": "kyiv kiev lviv lwow lwów kharkiv odesa odessa",
    "RU": "moscow moskwa москва saint petersburg petersburg",
    "US": "new york los angeles chicago san francisco seattle boston",
    "FR": "paris paryż lyon marseille",
}


def _builtin() -> tuple[dict, dict]:
    countries, cities = {}, {}
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
    def __init__(self, path: str | Path | None = None):
        self.countries, self.cities = _builtin()
        if path and Path(path).exists():
            doc = json.loads(Path(path).read_text(encoding="utf-8"))
            self.countries.update(doc.get("countries", {}))
            for k, v in doc.get("cities", {}).items():
                self.cities.setdefault(k, v)

    def resolve(self, text: str) -> tuple[str, float, str] | None:
        """(kod kraju, pewność 0–1, co dopasowano) albo None."""
        if not text:
            return None
        flag = flag_country(text)
        if flag:
            return flag, 0.9, "flaga emoji"
        raw_parts = [p.strip() for p in re.split(r"[,/|;·•()\n]+", text) if p.strip()]
        for raw in reversed(raw_parts):                       # kraj zwykle na końcu: "Kraków, Poland"
            if not re.fullmatch(r"[A-Z]{2}", raw):
                continue
            if raw in US_STATES:
                # "San Jose, CA" to Kalifornia, nie Kanada: miasto z USA obok skrótu rozstrzyga
                others = [self.cities.get(ascii_fold(p)) for p in raw_parts if p != raw]
                if "US" in others:
                    return "US", 0.85, f"{raw} (stan USA)"
                if raw in ISO2 and raw not in {"IN", "ME"}:
                    return raw, 0.4, f"{raw} (niejednoznaczne: kraj albo stan USA)"
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
        grams = [(" ".join(words[i:i + 2]), orig[i]) for i in range(len(words) - 1)] + list(zip(words, orig))
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
    m = re.search("([\U0001F1E6-\U0001F1FF])([\U0001F1E6-\U0001F1FF])", text)
    if not m:
        return None
    cc = chr(ord(m.group(1)) - 0x1F1E6 + 65) + chr(ord(m.group(2)) - 0x1F1E6 + 65)
    return cc if cc in ISO2 else None


def language_country(text: str) -> tuple[str, str] | None:
    """Słaba wskazówka z pisowni: (kraj, opis). Tylko znaki jednoznaczne dla języka."""
    if not text:
        return None
    if re.search(r"[ąćęłńśźżĄĆĘŁŃŚŹŻ]", text):
        return "PL", "polskie znaki w tekście"
    if re.search(r"[іїєґІЇЄҐ]", text):
        return "UA", "ukraińskie litery w tekście"
    if re.search(r"[ыэъЫЭЪ]", text):
        return "RU", "rosyjskie litery w tekście"
    if re.search(r"[řůŘŮ]", text):
        return "CZ", "czeskie znaki w tekście"
    return None


def tld_country(url: str) -> str | None:
    host = urlsplit(url).netloc.lower().split(":")[0]
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in GENERIC_TLDS or len(tld) != 2:
        return None
    cc = "GB" if tld == "uk" else tld.upper()
    return cc if cc in ISO2 else None


@dataclass
class Evidence:
    country: str
    weight: float
    note: str          # np. 'GitHub: lokalizacja "Kraków"'
    personal: bool = False   # note zawiera surową daną osobową z profilu (lokalizacja, narodowość) — nie do stdout


WEIGHTS = {"location": 1.0, "nationality": 1.0, "language": 0.4, "page_lang": 0.1, "tld": 0.15, "tag": 0.1}


def profile_evidence(site_name: str, profile_url: str, profile: dict, site_tags: list[str],
                     gaz: Gazetteer) -> list[Evidence]:
    ev: list[Evidence] = []
    for field in ("location", "nationality"):
        val = profile.get(field)
        hit = gaz.resolve(val) if val else None
        if hit:
            cc, conf, matched = hit
            ev.append(Evidence(cc, WEIGHTS[field] * conf, f'{site_name}: {field} "{val[:60]}"', personal=True))
    tld = tld_country(profile_url)
    lang = language_country(" ".join(filter(None, (profile.get("bio"), profile.get("name")))))
    # język strony krajowego serwisu to zwykle jego własny opis (RamblerDating: rosyjski og:description),
    # nie tekst użytkownika — nie liczymy podwójnie z domeną tego samego kraju (pomiar 03.10.2026)
    if lang and lang[0] != tld:
        ev.append(Evidence(lang[0], WEIGHTS["language"], f"{site_name}: {lang[1]}"))
    if tld:
        ev.append(Evidence(tld, WEIGHTS["tld"], f"{site_name}: domena .{tld.lower()}"))
    elif "global" not in {t.lower() for t in site_tags}:
        # tag kraju przy serwisie globalnym (np. Codeberg: global + de) opisuje operatora, nie użytkownika
        tags = [t.upper() for t in site_tags if len(t) == 2 and t.upper() in ISO2 and t.upper() != "US"]
        if len(tags) == 1:
            ev.append(Evidence(tags[0], WEIGHTS["tag"], f"{site_name}: serwis krajowy ({tags[0]})"))
    return ev


def aggregate(evidence: list[Evidence], top: int = 3) -> list[dict]:
    """[{country, percent, evidence:[...]}] posortowane; procent = udział w sumie wag."""
    if not evidence:
        return []
    score, notes, public = defaultdict(float), defaultdict(list), defaultdict(list)
    for e in evidence:
        score[e.country] += e.weight
        notes[e.country].append(e.note)
        if not e.personal:
            public[e.country].append(e.note)
    total = sum(score.values())
    ranked = sorted(score.items(), key=lambda kv: -kv[1])[:top]
    # udział w głosach mówi „który kraj”, siła mówi „jak bardzo wierzyć”: sama domena .pl to 100% głosów, ale słabo
    return [{"country": cc, "percent": round(100 * s / total), "score": round(s, 2), "strength": strength(s),
             "evidence": notes[cc][:8], "evidence_public": public[cc][:8]} for cc, s in ranked]


def strength(score: float) -> str:
    return "mocna" if score >= 1.5 else "średnia" if score >= 0.5 else "słaba"
