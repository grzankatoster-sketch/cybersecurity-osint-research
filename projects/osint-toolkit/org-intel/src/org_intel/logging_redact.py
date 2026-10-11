"""Logowanie z redakcja: e-maile, JWT, naglowki Authorization/Bearer, hibp-api-key, password=/token=, ciagi hex 32+."""

from __future__ import annotations

import logging
import re

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_AUTH_HEADER = re.compile(r"(?i)\b(authorization|proxy-authorization)(\s*[:=]\s*)(?:(?:bearer|basic)\s+)?[^\s,;]+")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_API_KEY_HEADER = re.compile(r"(?i)\b(hibp-api-key)(\s*[:=]\s*)[^\s,;]+")
_SECRET_ASSIGN = re.compile(
    r"(?i)\b(password|passwd|pwd|pass|token|access_token|refresh_token|api_key|apikey|secret)(\s*[=:]\s*)"
    r"(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_VERIFICATION = re.compile(r"(org-intel-verification=)[^\s\"']+")
_HEX = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,}(?![0-9A-Fa-f])")
_EMAIL = re.compile(r"([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")


def mask_email(email: str) -> str:
    """'jan.kowalski@example.test' -> 'j***@example.test'."""
    m = _EMAIL.fullmatch(email.strip())
    if not m:
        return "***"
    return f"{m.group(1)}***@{m.group(2)}"


def mask_emails(text: str) -> str:
    """Maskuje adresy e-mail w tekscie: 'kontakt jan@example.test' -> 'kontakt j***@example.test'."""
    return _EMAIL.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)


def redact(text: str) -> str:
    text = _JWT.sub("[JWT]", text)
    text = _AUTH_HEADER.sub(r"\1\2[REDACTED]", text)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    text = _API_KEY_HEADER.sub(r"\1\2[REDACTED]", text)
    text = _VERIFICATION.sub(r"\1[REDACTED]", text)
    text = _SECRET_ASSIGN.sub(r"\1\2[REDACTED]", text)
    text = _HEX.sub("[HEX]", text)
    return _EMAIL.sub(r"\1***@\2", text)


class RedactingFilter(logging.Filter):
    """Redaguje komunikat po zlozeniu z argumentami (msg % args), wiec chroni tez wartosci przekazane jako args."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            message = str(record.msg)
        record.msg = redact(message)
        record.args = ()
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


def get_logger(name: str = "org_intel") -> logging.Logger:
    logger = logging.getLogger(name)
    if not any(isinstance(f, RedactingFilter) for f in logger.filters):
        logger.addFilter(RedactingFilter())
    return logger


def make_handler(stream=None, level: int = logging.INFO) -> logging.Handler:
    """Handler na stderr z filtrem redakcji (chroni rowniez rekordy z loggerow potomnych)."""
    handler = logging.StreamHandler(stream)
    handler.setLevel(level)
    handler.addFilter(RedactingFilter())
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    return handler
