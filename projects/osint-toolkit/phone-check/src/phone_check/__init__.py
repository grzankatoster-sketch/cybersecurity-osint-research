"""phone-check: offline walidator numeru telefonu (parsowanie + metadane z planu numeracji)."""

from .core import PhoneInfo, analyze
from .dorks import dork_variants

__all__ = ["PhoneInfo", "analyze", "dork_variants"]
