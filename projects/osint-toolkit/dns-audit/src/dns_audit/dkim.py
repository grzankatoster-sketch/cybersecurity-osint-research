"""Parser rekordu DKIM i oszacowanie dlugosci klucza RSA (bez zewnetrznych bibliotek)."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field

DEFAULT_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2",
    "mail", "dkim", "email", "smtp", "mandrill", "mxvault", "everlytickey1",
    "smtpapi", "dkim1", "dkim2", "zoho", "scph0123", "pm", "mta", "key1", "key2",
)


KNOWN_KEY_TYPES = ("rsa", "ed25519")


@dataclass
class DkimKey:
    raw: str
    version: str | None = None
    key_type: str = "rsa"
    revoked: bool = False
    testing: bool = False
    key_bits: int | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        """Klucz aktywny, bez bledow, znanego typu i z poprawnie odczytana dlugoscia."""
        return (not self.revoked and not self.errors and self.key_type in KNOWN_KEY_TYPES
                and self.key_bits is not None)


def is_dkim(txt: str) -> bool:
    tags, _dups = _tags(txt)
    if "p" not in tags:
        return False
    return tags.get("v", "DKIM1").upper() == "DKIM1"


def _tags(raw: str) -> tuple[dict[str, str], list[str]]:
    """Tagi 'k=v; k=v' oraz lista powtorzonych nazw (powtorzony tag unieważnia rekord, RFC 6376 3.2)."""
    out: dict[str, str] = {}
    dups: list[str] = []
    for part in raw.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip().lower()
            if k in out:
                if k not in dups:
                    dups.append(k)
                continue
            out[k] = v.strip()
    return out, dups


def parse_dkim(raw: str) -> DkimKey:
    tags, dups = _tags(raw)
    key = DkimKey(raw=raw.strip(), version=tags.get("v"), key_type=tags.get("k", "rsa").lower())
    key.errors.extend(f"powtorzony tag {k}" for k in dups)
    key.testing = "y" in [x.strip() for x in tags.get("t", "").split(":")]
    p = "".join(tags.get("p", "").split())
    if not p:
        key.revoked = True
        return key
    if key.key_type not in KNOWN_KEY_TYPES:
        key.errors.append(f"nieznany typ klucza k={key.key_type}")
        return key
    try:
        der = base64.b64decode(p + "=" * (-len(p) % 4), validate=True)
    except (binascii.Error, ValueError):
        key.errors.append("klucz p= nie jest poprawnym base64")
        return key
    if key.key_type == "ed25519":
        if len(der) == 32:
            key.key_bits = 256
        else:
            key.errors.append(f"klucz ed25519 musi miec dokladnie 32 bajty (jest {len(der)})")
    else:
        key.key_bits = rsa_key_bits(der)
        if key.key_bits is None:
            key.errors.append("nie udalo sie odczytac dlugosci klucza RSA")
    return key


def _tlv(buf: bytes, pos: int) -> tuple[int, int, int]:
    tag = buf[pos]
    length = buf[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    if pos + length > len(buf):
        raise ValueError("DER poza zakresem")
    return tag, pos, pos + length


def _rsa_modulus_bits(buf: bytes, pos: int, end: int) -> int | None:
    """Odczyt `n` i `e` (dwa INTEGER) od pos; zwraca dlugosc modulu tylko gdy wykladnik jest obecny."""
    tag, ns, ne = _tlv(buf, pos)
    if tag != 0x02 or ne > end:
        return None
    tag_e, es, ee = _tlv(buf, ne)
    if tag_e != 0x02 or ee > end or ee == es:
        return None
    return int.from_bytes(buf[ns:ne], "big").bit_length()


def rsa_key_bits(der: bytes) -> int | None:
    """Dlugosc modulu RSA z SubjectPublicKeyInfo (lub golego PKCS#1); wymaga obecnego wykladnika."""
    try:
        tag, start, end = _tlv(der, 0)
        if tag != 0x30:
            return None
        tag2, _s2, e2 = _tlv(der, start)
        if tag2 == 0x02:  # PKCS#1: SEQUENCE { n, e }
            return _rsa_modulus_bits(der, start, end)
        if tag2 != 0x30:
            return None
        tag3, s3, e3 = _tlv(der, e2)  # BIT STRING
        if tag3 != 0x03 or e3 > end:
            return None
        inner = der[s3 + 1:e3]
        tag4, s4, e4 = _tlv(inner, 0)
        if tag4 != 0x30:
            return None
        return _rsa_modulus_bits(inner, s4, e4)
    except (IndexError, ValueError):
        return None
