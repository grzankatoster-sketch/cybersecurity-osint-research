from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

GPS_WARNING = "Ten plik ujawnia lokalizacje (GPS w metadanych)."


@dataclass
class PhotoMeta:
    path: str
    source: str = "pillow"  # "pillow" | "exiftool"
    taken: str | None = None  # ISO: YYYY-MM-DDTHH:MM:SS (czas lokalny aparatu, bez strefy)
    taken_field: str | None = None  # z jakiego pola EXIF pochodzi czas
    make: str | None = None
    model: str | None = None
    software: str | None = None
    lat: float | None = None
    lon: float | None = None
    altitude: float | None = None  # metry n.p.m. (ujemne = ponizej)
    direction: float | None = None  # stopnie 0-360 (kierunek, w ktorym skierowany aparat)
    width: int | None = None
    height: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def has_gps(self) -> bool:
        return self.lat is not None and self.lon is not None

    @property
    def camera(self) -> str:
        make = (self.make or "").strip()
        model = (self.model or "").strip()
        if make and model.lower().startswith(make.lower()):
            return model
        return f"{make} {model}".strip()

    @property
    def warning(self) -> str | None:
        return GPS_WARNING if self.has_gps else None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["camera"] = self.camera
        d["has_gps"] = self.has_gps
        d["warning"] = self.warning
        return d
