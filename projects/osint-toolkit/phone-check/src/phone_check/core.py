"""Analiza numeru wylacznie z danych wbudowanych w biblioteke phonenumbers (offline)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

import phonenumbers
from phonenumbers import PhoneNumberFormat, PhoneNumberType, carrier, geocoder, timezone

UKE_URL = "https://numeracja.uke.gov.pl/"

# Jedno zrodlo prawdy dla domyslnego regionu (ISO) i jezyka opisow; uzywane przez core, dorks i CLI.
DEFAULT_REGION = "PL"
DEFAULT_LANG = "pl"

TYPE_PL = {
    PhoneNumberType.FIXED_LINE: "stacjonarny",
    PhoneNumberType.MOBILE: "komórkowy",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "stacjonarny lub komórkowy",
    PhoneNumberType.TOLL_FREE: "bezpłatny (infolinia)",
    PhoneNumberType.PREMIUM_RATE: "o podwyższonej opłacie (premium)",
    PhoneNumberType.SHARED_COST: "o współdzielonym koszcie",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.PERSONAL_NUMBER: "osobisty",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.UAN: "UAN (numer uniwersalny)",
    PhoneNumberType.VOICEMAIL: "poczta głosowa",
    PhoneNumberType.UNKNOWN: "nieznany",
}

CARRIER_NOTE_PL = (
    "Operator z planu numeracji to pierwotny przydział puli numerów. W Polsce numer mógł zostać "
    "przeniesiony do innej sieci (przenoszenie numerów), więc to NIE jest pewny aktualny operator. "
    f"Aktualnego operatora sprawdź ręcznie w bazie UKE: {UKE_URL}"
)
CARRIER_NOTE_GENERIC = (
    "Operator z planu numeracji to pierwotny przydział puli numerów; w wielu krajach numery można "
    "przenosić między sieciami, więc dane mogą być nieaktualne."
)


@dataclass
class PhoneInfo:
    input: str
    region_hint: str
    parsed: bool = False
    possible: bool = False
    valid: bool = False
    error: str | None = None
    country_code: int | None = None
    region: str | None = None  # kod kraju ISO, np. PL
    country_name: str | None = None
    geo_description: str | None = None
    line_type: str | None = None  # nazwa polska
    line_type_code: str | None = None  # nazwa maszynowa, np. MOBILE
    carrier: str | None = None
    carrier_note: str | None = None
    carrier_check_url: str | None = None
    timezones: list[str] = field(default_factory=list)
    e164: str | None = None
    international: str | None = None
    national: str | None = None
    rfc3966: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _clean(text: str | None) -> str | None:
    text = (text or "").strip()
    return text or None


def normalize_region(region: str | None) -> str:
    """Kod regionu ISO wielkimi literami; pusty/None => DEFAULT_REGION."""
    return (region or DEFAULT_REGION).strip().upper() or DEFAULT_REGION


def normalize_lang(lang: str | None) -> str:
    """Kod jezyka malymi literami; pusty/None => DEFAULT_LANG."""
    return (lang or DEFAULT_LANG).strip().lower() or DEFAULT_LANG


def analyze(raw: str, region: str = DEFAULT_REGION, lang: str = DEFAULT_LANG) -> PhoneInfo:
    """Zwraca PhoneInfo dla numeru w dowolnym formacie. Nie rzuca wyjatkow dla zlego wejscia."""
    region = normalize_region(region)
    lang = normalize_lang(lang)
    info = PhoneInfo(input=raw, region_hint=region)
    try:
        num = phonenumbers.parse(raw, region)
    except phonenumbers.NumberParseException as exc:
        info.error = f"nie da się sparsować: {exc}"
        return info

    info.parsed = True
    info.possible = (
        phonenumbers.is_possible_number_with_reason(num) == phonenumbers.ValidationResult.IS_POSSIBLE
    )
    info.valid = phonenumbers.is_valid_number(num)
    info.country_code = num.country_code
    region_code = phonenumbers.region_code_for_number(num)
    non_geo = {
        phonenumbers.REGION_CODE_FOR_NON_GEO_ENTITY,
        phonenumbers.UNKNOWN_REGION,
    }
    info.region = region_code if region_code and region_code not in non_geo else None

    if info.region:
        info.country_name = _clean(geocoder.country_name_for_number(num, lang))
    # Opis geograficzny i operator tylko dla poprawnych numerow (dla niepoprawnych bywa mylacy).
    if info.valid:
        info.geo_description = _clean(geocoder.description_for_number(num, lang))
        info.carrier = _clean(carrier.name_for_number(num, lang))
        info.timezones = [t for t in timezone.time_zones_for_number(num) if t != "Etc/Unknown"]
        ntype = phonenumbers.number_type(num)
        info.line_type_code = PhoneNumberType.to_string(ntype)
        info.line_type = TYPE_PL.get(ntype, info.line_type_code)
        if info.region == "PL":
            info.carrier_note = CARRIER_NOTE_PL
            info.carrier_check_url = UKE_URL
        else:
            info.carrier_note = CARRIER_NOTE_GENERIC
    if info.possible or info.valid:
        info.e164 = phonenumbers.format_number(num, PhoneNumberFormat.E164)
        info.international = phonenumbers.format_number(num, PhoneNumberFormat.INTERNATIONAL)
        info.national = phonenumbers.format_number(num, PhoneNumberFormat.NATIONAL)
        info.rfc3966 = phonenumbers.format_number(num, PhoneNumberFormat.RFC3966)
    if not info.valid:
        info.error = (
            "numer możliwy długościowo, ale niepoprawny w planie numeracji"
            if info.possible
            else "numer niepoprawny (zła długość lub prefiks)"
        )
    return info


def format_text(info: PhoneInfo) -> str:
    """Czytelny opis jednego numeru (po polsku)."""
    yn = lambda b: "tak" if b else "nie"  # noqa: E731
    lines = [f"Numer:            {info.input}", f"Region domyślny:  {info.region_hint}"]
    if not info.parsed:
        lines.append(f"Wynik:            {info.error}")
        return "\n".join(lines)
    lines += [
        f"Poprawny:         {yn(info.valid)}",
        f"Możliwy:          {yn(info.possible)}",
    ]
    if info.error and not info.valid:
        lines.append(f"Uwaga:            {info.error}")
    if info.country_code is not None:
        kraj = info.region or "?"
        if info.country_name:
            kraj += f" ({info.country_name})"
        lines.append(f"Kraj:             {kraj}, kierunkowy +{info.country_code}")
    if info.valid:
        lines.append(f"Region geogr.:    {info.geo_description or '(brak danych)'}")
        lines.append(f"Typ linii:        {info.line_type}")
        lines.append(f"Operator (plan):  {info.carrier or '(brak danych w planie numeracji)'}")
        if info.carrier_note:
            lines.append(f"  Adnotacja:      {info.carrier_note}")
        lines.append(f"Strefy czasowe:   {', '.join(info.timezones) or '(brak)'}")
    if info.e164:
        lines += [
            f"E.164:            {info.e164}",
            f"Międzynarodowy:   {info.international}",
            f"Krajowy:          {info.national}",
            f"RFC3966:          {info.rfc3966}",
        ]
    return "\n".join(lines)
