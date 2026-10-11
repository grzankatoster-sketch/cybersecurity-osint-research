"""Normalizacja wartości encji. Dwa węzły wskazujące tę samą rzecz dostają ten sam klucz (scalanie).

normalize(typ, surowa_wartość) -> (klucz, wartość_do_pokazania). Błędne dane = ValueError.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from enum import Enum
from urllib.parse import parse_qsl, urlencode, urlsplit


class EntityType(str, Enum):
    PERSON = "person"
    USERNAME = "username"
    EMAIL = "email"
    DOMAIN = "domain"
    IP = "ip"
    PHONE = "phone"
    ORGANIZATION = "organization"
    URL = "url"
    PHOTO = "photo"        # plik zdjęcia z metadanymi EXIF (import z exif-map)
    PARCEL = "parcel"      # działka ewidencyjna (import z ULDK); to geometria i położenie, nie właściciel


LABELS_PL = {
    EntityType.PERSON: "Osoba (imię i nazwisko)",
    EntityType.USERNAME: "Nazwa użytkownika",
    EntityType.EMAIL: "E-mail",
    EntityType.DOMAIN: "Domena",
    EntityType.IP: "Adres IP",
    EntityType.PHONE: "Telefon",
    EntityType.ORGANIZATION: "Organizacja",
    EntityType.URL: "URL",
    EntityType.PHOTO: "Zdjęcie (plik)",
    EntityType.PARCEL: "Działka ewidencyjna",
}
_PARCEL_RE = re.compile(r"[0-9]{6}_[0-9]\.[0-9]{4}\.(AR_[0-9]{1,3}\.)?[0-9]{1,6}(/[0-9]{1,6})?")

MAX_VALUE_LEN = 2048
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_EMAIL_LOCAL_RE = re.compile(r"^[^@\s<>()\[\],;:\\\"]{1,64}$")
_TRACKING_PARAMS = {"fbclid", "gclid", "igshid", "mc_cid", "mc_eid", "ref", "ref_src", "si", "feature"}
# aliasy hostów, które są tym samym serwisem
HOST_ALIASES = {
    "twitter.com": "x.com", "mobile.twitter.com": "x.com", "m.facebook.com": "facebook.com",
    "mbasic.facebook.com": "facebook.com", "fb.com": "facebook.com", "m.youtube.com": "youtube.com",
    "youtu.be": "youtube.com", "mobile.x.com": "x.com",
}


def fold(text: str) -> str:
    """'Łukasz Żółć' -> 'lukasz zolc' (ł nie rozkłada się w NFKD, więc osobno)."""
    text = text.replace("ł", "l").replace("Ł", "L")
    norm = unicodedata.normalize("NFKD", text)
    return "".join(c for c in norm if not unicodedata.combining(c)).casefold()


def _clean_text(raw: str) -> str:
    text = unicodedata.normalize("NFC", str(raw))
    text = "".join(c for c in text if unicodedata.category(c) != "Cc" or c in " \t")
    return re.sub(r"\s+", " ", text).strip()


def normalize_domain(raw: str) -> str:
    d = str(raw).strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = re.split(r"[/?#]", d, maxsplit=1)[0]
    if "@" in d:
        d = d.rsplit("@", 1)[1]
    d = d.split(":")[0].rstrip(".").removeprefix("*.")
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"nieprawidłowa domena: {raw!r}") from exc
    labels = d.split(".")
    if len(d) > 253 or len(labels) < 2 or not all(_LABEL_RE.match(x) for x in labels):
        raise ValueError(f"nieprawidłowa domena: {raw!r}")
    return d


def normalize_ip(raw: str) -> str:
    text = str(raw).strip().strip("[]").split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValueError(f"nieprawidłowy adres IP: {raw!r}") from exc
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(addr)


def normalize_email(raw: str) -> str:
    text = str(raw).strip().lower()
    if text.startswith("mailto:"):
        text = text[7:]
    if text.count("@") != 1:
        raise ValueError(f"nieprawidłowy e-mail: {raw!r}")
    local, domain = text.split("@")
    if not _EMAIL_LOCAL_RE.match(local):
        raise ValueError(f"nieprawidłowy e-mail: {raw!r}")
    return f"{local}@{normalize_domain(domain)}"


def normalize_phone(raw: str, region: str = "PL") -> str:
    """Do postaci +<cyfry>. Bez + wymagany jest region PL (9 cyfr); resztę rozstrzyga phone-check."""
    text = re.sub(r"[\s().\-/]", "", str(raw).strip())
    if text.startswith("00"):
        text = "+" + text[2:]
    if text.startswith("+"):
        digits = text[1:]
    elif region.upper() == "PL" and re.fullmatch(r"\d{9}", text):
        digits = "48" + text
    else:
        raise ValueError(f"numer bez kodu kraju: podaj format międzynarodowy +... ({raw!r})")
    if not digits.isdigit() or not 7 <= len(digits) <= 15:
        raise ValueError(f"nieprawidłowy numer telefonu: {raw!r}")
    return "+" + digits


def normalize_url(raw: str) -> tuple[str, str]:
    text = str(raw).strip()
    if re.search(r"\s", text):
        raise ValueError(f"nieprawidłowy URL (spacje): {raw!r}")
    if "://" not in text:
        text = "https://" + text
    parts = urlsplit(text)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValueError(f"nieprawidłowy URL (tylko http/https): {raw!r}")
    host = parts.hostname.lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"nieprawidłowy URL: {raw!r}") from exc
    if not re.fullmatch(r"[a-z0-9._-]+|[0-9a-f:.]+", host):
        raise ValueError(f"nieprawidłowy host w URL: {raw!r}")
    host = host.removeprefix("www.")
    host = HOST_ALIASES.get(host, host)
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f"nieprawidłowy URL: {raw!r}") from exc
    default = {"http": 80, "https": 443}[parts.scheme.lower()]
    netloc = f"[{host}]" if ":" in host else host
    if port and port != default:
        netloc += f":{port}"
    path = parts.path.rstrip("/")
    query = urlencode(sorted(
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not k.lower().startswith("utm_") and k.lower() not in _TRACKING_PARAMS
    ))
    key = netloc + path + (f"?{query}" if query else "")
    display = f"{parts.scheme.lower()}://{key}"   # bez danych logowania w adresie i bez fragmentu
    return key, display


def normalize(etype: EntityType, raw: str, region: str = "PL") -> tuple[str, str]:
    """-> (klucz, wartość do pokazania)."""
    if raw is None or not str(raw).strip():
        raise ValueError("pusta wartość")
    if len(str(raw)) > MAX_VALUE_LEN:
        raise ValueError("wartość za długa")
    if etype is EntityType.DOMAIN:
        d = normalize_domain(raw)
        return d, d
    if etype is EntityType.IP:
        ip = normalize_ip(raw)
        return ip, ip
    if etype is EntityType.EMAIL:
        e = normalize_email(raw)
        return e, e
    if etype is EntityType.PHONE:
        p = normalize_phone(raw, region)
        return p, p
    if etype is EntityType.URL:
        return normalize_url(raw)
    text = _clean_text(raw)
    if etype is EntityType.USERNAME:
        text = text.lstrip("@")
        if not text or " " in text:
            raise ValueError(f"nieprawidłowa nazwa użytkownika: {raw!r}")
        return text.casefold(), text
    if etype is EntityType.PERSON:
        if len(text) < 3:
            raise ValueError("za krótkie imię i nazwisko")
        return fold(text), text
    if etype is EntityType.ORGANIZATION:
        key = fold(text).strip(" .,;")
        if not key:
            raise ValueError("pusta nazwa organizacji")
        return key, text
    if etype is EntityType.PHOTO:
        if not text:
            raise ValueError("pusta ścieżka zdjęcia")
        display = text.replace("\\", "/")
        return display.casefold(), display
    if etype is EntityType.PARCEL:
        if not _PARCEL_RE.fullmatch(text):
            raise ValueError(f"nieprawidłowy identyfikator działki: {raw!r}")
        return text, text
    raise ValueError(f"nieobsługiwany typ: {etype}")


def is_public_ip(ip: str) -> bool:
    """Czy adres ma sens w publicznych bazach (RDAP/BGP). Prywatne, loopback, link-local itd. nie mają."""
    return ipaddress.ip_address(ip).is_global


_GRAVATAR_RE = re.compile(r"gravatar\.com/avatar/([0-9a-f]{64}|[0-9a-f]{32})", re.IGNORECASE)


def avatar_hash_from_url(url: str) -> str:
    """Skrót awatara z jego ADRESU (nie z treści obrazu): dla Gravatara jest to skrót adresu e-mail z URL-a,
    dla reszty SHA-256 hosta i ścieżki bez zapytania (rozmiar/wersja). Ten sam skrót = ten sam plik pod tym samym
    adresem; różne adresy tego samego obrazu nie zostaną dopasowane (brak fałszywych trafień kosztem czułości)."""
    import hashlib

    m = _GRAVATAR_RE.search(url)
    if m:
        return m.group(1).lower()
    parts = urlsplit(url.strip())
    basis = (parts.netloc.lower() + parts.path).encode("utf-8")
    return "u-" + hashlib.sha256(basis).hexdigest()[:32]
