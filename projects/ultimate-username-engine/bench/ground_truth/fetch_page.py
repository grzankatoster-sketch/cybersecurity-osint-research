"""Narzędzie weryfikatora holdoutu: pobiera stronę i drukuje zwięzły dowód (JSON).

Użycie:
    .uee-tools\\Scripts\\python.exe bench\\ground_truth\\fetch_page.py URL [--nick NICK] [--js] [--chars 1500]
--js       renderuje stronę w Chromium (Playwright, headless) zamiast zwykłego GET
--nick     szuka nicka w treści (bez rozróżniania wielkości liter) i zwraca fragmenty wokół trafień

Wynik: final_url, status, title, text_len, nick_hits (liczba), snippets (fragmenty wokół nicka),
head (początek widocznego tekstu), markers (login/captcha/cloudflare/404 w treści). Nic nie zapisuje na dysk.
"""
from __future__ import annotations

import argparse
import html
import json
import re
import sys
import urllib.error
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/141.0.0.0 Safari/537.36")
MARKERS = {
    "captcha": r"captcha|hcaptcha|recaptcha|are you a robot|verify you are human",
    "cloudflare": r"cf-chl|just a moment|attention required|cloudflare ray id",
    "login_wall": r"log ?in to (see|view|continue)|sign in to (see|view|continue)|please log ?in|you must be logged in",
    "not_found_text": r"page not found|user not found|404|doesn.t exist|does not exist|no such user|profile not found|nie znaleziono",
}


def visible_text(raw: str) -> tuple[str, str]:
    title = re.search(r"<title[^>]*>(.*?)</title>", raw, re.I | re.S)
    body = re.sub(r"<(script|style|noscript)[^>]*>.*?</\1>", " ", raw, flags=re.I | re.S)
    body = re.sub(r"<[^>]+>", " ", body)
    return (html.unescape(title.group(1)).strip() if title else ""), re.sub(r"\s+", " ", html.unescape(body)).strip()


def http_get(url: str) -> tuple[str, int | None, str, str | None]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.8"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.geturl(), r.status, r.read(3_000_000).decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        return e.geturl() or url, e.code, e.read(3_000_000).decode("utf-8", "replace"), None
    except Exception as e:  # noqa: BLE001 - dowód błędu sieci
        return url, None, "", f"{type(e).__name__}: {e}"[:300]


def js_get(url: str) -> tuple[str, int | None, str, str | None]:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page(user_agent=UA, locale="en-US")
            resp = page.goto(url, wait_until="domcontentloaded", timeout=30000)
            try:
                page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:  # noqa: BLE001 - strony z ciągłym ruchem
                pass
            return page.url, resp.status if resp else None, page.content(), None
        except Exception as e:  # noqa: BLE001
            return url, None, "", f"{type(e).__name__}: {e}"[:300]
        finally:
            browser.close()


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("--nick")
    ap.add_argument("--js", action="store_true")
    ap.add_argument("--chars", type=int, default=1500)
    a = ap.parse_args()
    final, status, raw, err = (js_get if a.js else http_get)(a.url)
    title, text = visible_text(raw)
    out = {"url": a.url, "mode": "js" if a.js else "http", "final_url": final, "status": status, "error": err,
           "title": title[:200], "text_len": len(text), "head": text[: a.chars]}
    if a.nick:
        hits = [m.start() for m in re.finditer(re.escape(a.nick), text, re.I)]
        out["nick_hits"] = len(hits)
        out["nick_in_raw_html"] = len(re.findall(re.escape(a.nick), raw, re.I))
        out["snippets"] = [text[max(0, i - 120): i + 160] for i in hits[:4]]
    low = (title + " " + text[:20000]).lower()
    out["markers"] = [k for k, rx in MARKERS.items() if re.search(rx, low)]
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
