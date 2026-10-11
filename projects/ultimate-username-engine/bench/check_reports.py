"""F5.5: sprawdzenie raportów HTML w Playwright (Chromium): otwiera się, brak błędów konsoli/strony, brak żądań sieciowych."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright


def main(paths: list[str]) -> int:
    out, bad = [], 0
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for path in paths:
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            msgs, errors, requests = [], [], []
            page.on("console", lambda m: msgs.append((m.type, m.text)))
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("request", lambda r: requests.append(r.url) if not r.url.startswith("file:") else None)
            url = Path(path).resolve().as_uri()
            resp = page.goto(url)
            page.wait_for_load_state("load")
            shot = Path(path).with_suffix(".png")
            page.screenshot(path=str(shot), full_page=False)
            rec = {"file": path, "title": page.title(), "console_errors": [t for k, t in msgs if k == "error"],
                   "page_errors": errors, "external_requests": requests, "rows": page.locator("tr").count(),
                   "screenshot": str(shot)}
            bad += bool(rec["console_errors"] or rec["page_errors"] or rec["external_requests"])
            out.append(rec)
            page.close()
        browser.close()
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
