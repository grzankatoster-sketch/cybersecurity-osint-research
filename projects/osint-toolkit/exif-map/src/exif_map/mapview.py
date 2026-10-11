"""Mapa HTML (folium): znacznik na plik (miniatura, nazwa, czas) + linia trasy w kolejnosci czasu."""

from __future__ import annotations

import base64
import html
import io
from pathlib import Path

import folium
from PIL import Image, ImageOps

from .gps import format_coords, suspicious_reason
from .models import PhotoMeta

_BANNER_STYLE = (
    "position:fixed;bottom:8px;left:50%;transform:translateX(-50%);z-index:9999;background:#fff3cd;"
    "border:1px solid #d39e00;padding:4px 10px;font:12px sans-serif;border-radius:4px;max-width:90%;text-align:center"
)
BANNER_TILES = (
    f'<div style="{_BANNER_STYLE}">'
    "Mapa zawiera dokladne lokalizacje Twoich zdjec - nie publikuj jej.<br>"
    "Po otwarciu przegladarka laczy sie z OpenStreetMap (kafelki) i CDN (Leaflet): serwery widza Twoje IP "
    "i ogladany obszar. Tryb bez kafelkow: --no-tiles.</div>"
)
BANNER_NO_TILES = (
    f'<div style="{_BANNER_STYLE}">'
    "Mapa zawiera dokladne lokalizacje Twoich zdjec - nie publikuj jej.<br>"
    "Tryb --no-tiles: bez kafelkow OpenStreetMap (tylko punkty i trasa). Biblioteka Leaflet nadal ladowana z CDN, "
    "wiec przegladarka laczy sie z siecia (ujawnia IP).</div>"
)
BANNER = BANNER_TILES


def _esc(text: str) -> str:
    """Escape niezaufanego tekstu dla folium: HTML + znaki specjalne literalow szablonowych JS.

    folium wstawia tooltip/popup do literalu szablonowego JS (backtick), gdzie `${...}` jest wykonywane,
    a backtick i backslash zmieniaja skladnie; html.escape tego nie neutralizuje. Zamiana na encje HTML
    (&#36; &#96; &#92;) zachowuje wyswietlany tekst, a w kodzie JS nie ma tych znakow.
    """
    return html.escape(text).replace("$", "&#36;").replace("`", "&#96;").replace("\\", "&#92;")


def _thumbnail_b64(path: str, size: int = 220) -> str | None:
    try:
        with Image.open(path) as im:
            im = ImageOps.exif_transpose(im)
            im.thumbnail((size, size))
            if im.mode not in ("RGB", "L"):
                im = im.convert("RGB")
            buf = io.BytesIO()
            im.save(buf, format="JPEG", quality=70)  # nowy JPEG: bez EXIF
        return base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception:
        return None


def _popup_html(m: PhotoMeta, order: int | None, thumbnails: bool = True) -> str:
    name = _esc(Path(m.path).name)
    parts = [f"<b>{name}</b>"]
    if order is not None:
        parts[0] = f"#{order} " + parts[0]
    parts.append(_esc((m.taken or "brak czasu").replace("T", " ")))
    if m.camera:
        parts.append(_esc(m.camera))
    parts.append(_esc(format_coords(m.lat, m.lon)))
    if m.altitude is not None:
        parts.append(f"wys. {m.altitude:.0f} m")
    if m.direction is not None:
        parts.append(f"kierunek {m.direction:.0f}&deg;")
    reason = suspicious_reason(m.lat, m.lon)
    if reason is not None:
        parts.append("UWAGA: " + _esc(reason))
    thumb = _thumbnail_b64(m.path) if thumbnails else None
    img = f'<img src="data:image/jpeg;base64,{thumb}" style="max-width:220px;display:block;margin-top:4px">' if thumb else ""
    return "<br>".join(parts) + img


def build_map(items: list[PhotoMeta], out_path: Path, thumbnails: bool = True, tiles: bool = True) -> int:
    """Zapisuje mape HTML. Zwraca liczbe znacznikow (0 = brak GPS, plik nie jest tworzony).

    tiles=False: bez kafelkow OpenStreetMap (sama siatka punktow i trasa); Leaflet nadal z CDN."""
    points = [m for m in items if m.has_gps]
    if not points:
        return 0
    timed = sorted((m for m in points if m.taken), key=lambda m: m.taken)
    order = {id(m): i for i, m in enumerate(timed, 1)}

    fmap = folium.Map(location=[points[0].lat, points[0].lon], zoom_start=13, control_scale=True,
                      tiles="OpenStreetMap" if tiles else None)
    for m in points:
        n = order.get(id(m))
        label = Path(m.path).name + (f" | {m.taken.replace('T', ' ')}" if m.taken else "")
        reason = suspicious_reason(m.lat, m.lon)
        if reason is not None:
            label = "[?] " + label
        marker_kwargs = {}
        if reason is not None:
            marker_kwargs["icon"] = folium.Icon(color="orange", icon="question-sign")
        folium.Marker(
            [m.lat, m.lon],
            tooltip=_esc(label),
            popup=folium.Popup(_popup_html(m, n, thumbnails), max_width=260),
            **marker_kwargs,
        ).add_to(fmap)
    if len(timed) >= 2:
        folium.PolyLine([(m.lat, m.lon) for m in timed], weight=3, opacity=0.8, tooltip="Trasa wg czasu").add_to(fmap)
    lats, lons = [m.lat for m in points], [m.lon for m in points]
    if len(points) > 1 and (max(lats) != min(lats) or max(lons) != min(lons)):
        fmap.fit_bounds([[min(lats), min(lons)], [max(lats), max(lons)]], padding=(30, 30))
    fmap.get_root().html.add_child(folium.Element(BANNER_TILES if tiles else BANNER_NO_TILES))
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fmap.save(str(out_path))
    return len(points)


def count_suspicious(items: list[PhotoMeta]) -> int:
    """Liczba punktow z GPS, dla ktorych suspicious_reason zwraca powod."""
    return sum(1 for m in items if m.has_gps and suspicious_reason(m.lat, m.lon) is not None)
