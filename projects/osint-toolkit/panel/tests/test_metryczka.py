"""Metryczka wyniku (status, czas UTC, skrót, kanał, decyzja), asystent i dziennik sprawy, eksport GraphML/Maltego.
Bez sieci i bez podprocesów narzędzi."""
import json
import re
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import app  # noqa: E402

UE_OK = "Sprawdzono 10 serwisów w 3 s: znaleziono 2 (pokazano ≥0.5: 2), brak 8, błędy 0, nieobsługiwane 0."
UE_ERR = "Sprawdzono 10 serwisów w 3 s: znaleziono 0 (pokazano ≥0.5: 0), brak 6, błędy 4, nieobsługiwane 0."
UE_NONE = "Sprawdzono 10 serwisów w 3 s: znaleziono 0 (pokazano ≥0.5: 0), brak 10, błędy 0, nieobsługiwane 0."


@pytest.mark.parametrize("tool,code,out,err,meta,expected", [
    ("username", 0, UE_OK, "", None, "found"),
    ("username", 0, UE_NONE, "", None, "no_result"),
    ("username", 0, UE_ERR, "", None, "partial"),            # bledy/blokady serwisow: nie brak wyniku
    ("username", 3, "", "Proxy niedostępne (x) — skan przerwany", None, "error"),
    ("username", 3, UE_OK, "Proxy przestało działać ... Raport częściowy zapisany.", None, "partial"),
    ("username", -1, "[+] trafienie", "Przekroczono limit czasu (600 s).", None, "partial"),
    ("username", -1, "", "Przekroczono limit czasu (600 s).", None, "error"),
    ("dns", 0, "x", "", None, "found"),
    ("dns", 3, "", "Proxy/DoH niedostępne", None, "error"),
    ("phone", 1, "x", "", None, "no_result"),
    ("phone", 2, "", "x", None, "error"),
    ("hibp", 0, "a.pl: brak nowych wyciekow (lacznie 0)", "", None, "no_result"),
    ("hibp", 0, "a.pl: brak nowych wyciekow (lacznie 3)", "", None, "found"),
    ("hibp", 3, "", "Blad: Limit zapytan HIBP (429)", None, "blocked"),
    ("hibp", 3, "", "Blad sieci: timeout", None, "error"),
    ("exif", 1, "", "Brak obslugiwanych plikow", None, "no_result"),
    ("harvester", 0, "[*] Hosts found: 0\n", "Source crtsh finished in 1.00s: status=failed; results=0", None,
     "partial"),
    ("harvester", 0, "[*] Hosts found: 0\n", "Source crtsh finished in 1.00s: status=completed; results=0", None,
     "no_result"),
    ("meta", 0, "", "", {"status": "not_configured"}, "blocked"),
    ("meta", 0, "", "", {"status": "rate_limited"}, "blocked"),
    ("meta", 0, "", "", {"status": "manual"}, "partial"),
    ("meta", 0, "", "", None, "error"),
    # przeglad 05.10: brak podsumowania, Wayback, nieznane kody, DNS niepelny, HIBP baseline i katalog, EXIF
    ("username", 0, "", "", None, "error"),                                   # brak podsumowania = nieznany
    ("username", 1, "Traceback ...", "", None, "error"),
    ("username", 7, UE_OK, "", None, "error"),
    ("username", 0, "Archiwum: 2 profili z zrzutami, 0 błędów archiwum.", "", None, "found"),
    ("username", 0, "Archiwum: 0 profili z zrzutami, 20 błędów archiwum.", "", None, "partial"),
    ("username", 0, "Archiwum: 0 profili z zrzutami, 0 błędów archiwum.", "", None, "no_result"),
    ("username", 0, UE_OK + "\nArchiwum: 0 profili z zrzutami, 3 błędów archiwum.", "", None, "partial"),
    ("dns", 0, "DKIM: nie udało się sprawdzić 2 z 5 selektorów", "", None, "partial"),
    ("hibp", 0, "a.pl: pierwsze uruchomienie (baseline), wyciekow zrodlowych: 0", "", None, "no_result"),
    ("hibp", 0, "a.pl: pierwsze uruchomienie (baseline), wyciekow zrodlowych: 4", "", None, "found"),
    ("hibp", 0, "Katalog HIBP: 900 wyciekow (pokazano 20, ...)", "", None, "found"),
    ("hibp", 0, "nieoczekiwany tekst", "", None, "error"),
    ("exif", 0, "Plikow: 3, z GPS: 1, z bledem: 1. Silnik: x", "", None, "partial"),
    ("exif", 0, "Plikow: 3, z GPS: 1, z bledem: 0. Silnik: x", "", None, "found"),
    ("harvester", 0, "[*] Hosts found: 0\n", "status=rate-limited; results=0\nstatus=rate-limited", None, "blocked"),
    ("harvester", 0, "Source crtsh finished: status=failed; results=0\n[*] Hosts found: 0\n", "", None, "partial"),
])
def test_classify_never_turns_failure_into_no_result(tool, code, out, err, meta, expected):
    assert app.classify(tool, code, out, err, meta)[0] == expected


def test_envelope_has_every_evidence_field(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "OUT", tmp_path)
    (tmp_path / "dns_a.html").write_text("<p>raport</p>", encoding="utf-8")
    env = app.envelope("dns", ["a.pl", "--proxy", "socks5h://127.0.0.1:9150"], {"domain": "a.pl"}, 0, "wynik", "",
                       "dns_a.html", None)
    assert set(env) == {"zrodlo", "identyfikator", "url", "czas_utc", "status", "status_label", "uwaga", "kanal",
                        "ograniczenia", "sha256", "dowod", "decyzja"}
    assert env["identyfikator"] == "a.pl" and env["url"] == "/wyniki/dns_a.html" and env["status"] == "found"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00", env["czas_utc"])
    assert re.fullmatch(r"[0-9a-f]{64}", env["sha256"]) and env["kanal"].startswith("Tor")
    assert env["ograniczenia"] and "Sprawa" in env["decyzja"]
    direct = app.envelope("dns", ["a.pl", "--direct"], {"domain": "a.pl"}, 0, "wynik", "", None, None)
    assert direct["kanal"] == "bezpośrednio" and direct["url"] == "" and direct["sha256"] != env["sha256"]
    exif = app.envelope("exif", [], {"path": r"C:\\Users\\ktos\\zdjecia\\a.jpg"}, 0, "x", "", None, None)
    assert exif["identyfikator"] == "a.jpg" and exif["kanal"].startswith("offline")   # bez pelnej sciezki


def test_envelope_identifier_for_meta_and_hibp_catalog():
    q = app.envelope("meta", [], {"op": "threads_search", "query": "osint"}, 0, "", "", None, {"status": "found"})
    assert q["identyfikator"] == "osint"
    assert app.envelope("hibp", [], {"limit": "5"}, 0, "Katalog HIBP: 9 wyciekow", "", None, None)["identyfikator"] \
        == "katalog HIBP"


def test_password_check_has_envelope_without_password(monkeypatch):
    class Proc:
        returncode, stdout, stderr = 0, '{"count": 3}', ""
    monkeypatch.setattr(app.subprocess, "run", lambda *a, **k: Proc())
    r = app.check_password_proc("tajne-haslo-123")
    m = r["metryczka"]
    assert m["status"] == "found" and m["czas_utc"].endswith("+00:00") and len(m["sha256"]) == 64
    assert "tajne-haslo-123" not in json.dumps(r, ensure_ascii=False)


def test_scan_is_full_only_when_every_step_is_certain(monkeypatch, tmp_path):
    monkeypatch.setattr(app, "OUT", tmp_path)
    plan = {"dns": "found", "hibp_domain": "partial", "harvester": "found"}

    def fake_run(action, params):
        st = plan[action]
        return {"code": 0, "seconds": 0, "report": None, "stdout": "", "stderr": "",
                "metryczka": {"status": st, "status_label": app.RESULT_STATUS[st], "zrodlo": "z", "czas_utc": "t",
                              "kanal": "k", "sha256": "0" * 64, "identyfikator": "a.pl", "uwaga": "",
                              "ograniczenia": "o", "dowod": "d", "decyzja": "brak"}}
    monkeypatch.setattr(app, "run_tool", fake_run)
    w = app.run_scan("a.pl", "domena")
    assert w["podsumowanie"]["wynik"] == "niepelny" and w["podsumowanie"]["statusy"] == {"found": 2, "partial": 1}
    html_report = (tmp_path / w["report"].rsplit("/", 1)[1]).read_text(encoding="utf-8")
    assert "wynik częściowy" in html_report and "SHA-256" in html_report and "Decyzja operatora" in html_report
    plan["hibp_domain"] = "no_result"
    assert app.run_scan("a.pl", "domena")["podsumowanie"]["wynik"] == "pelny"


@pytest.mark.parametrize("proxy,note", [
    ("socks5h://127.0.0.1:abc", "nieprawidłowy"),
    ("socks5h://user:SEKRET@203.0.113.9:1080", "nie sprawdzano"),
])
def test_lab_proxy_check_never_fails_or_connects_outside(monkeypatch, proxy, note):
    calls = []
    monkeypatch.setattr(app, "PANEL_PROXY", proxy)
    monkeypatch.setattr(app, "_port_open", lambda h, p, timeout=0.3: calls.append(h) or False)
    env = app.lab_environment()
    tor = next(d for d in env["dependencies"] if d["name"] == "Kanał Tor/proxy")
    assert note in tor["note"] and "SEKRET" not in json.dumps(env) and "203.0.113.9" not in calls


def test_assistant_and_audit_actions(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "SPRAWY", tmp_path)
    (tmp_path / "s1").mkdir()
    for f in ("graph.json", "audit.jsonl"):
        (tmp_path / "s1" / f).write_text("{}", encoding="utf-8")
    tool, args, _ = app.build_command("sprawa_asystent", {"sprawa": "s1"})
    assert tool == "sprawa" and args[0] == "asystent" and "--ai" not in args
    assert app.build_command("sprawa_asystent", {"sprawa": "s1", "ai": True})[1][-1] == "--ai"
    with pytest.raises(app.BadField):
        app.build_command("sprawa_asystent", {"sprawa": "s1", "ai": "true"})
    assert app.build_command("sprawa_dziennik", {"sprawa": "s1"})[1][-2:] == ["--limit", "200"]


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _get(url, token=None):
    req = urllib.request.Request(url, headers={"X-Panel-Token": token} if token else {})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def test_case_export_download_requires_token_and_stays_in_case(server, tmp_path, monkeypatch):
    monkeypatch.setattr(app, "SPRAWY", tmp_path)
    case = tmp_path / "s1"
    case.mkdir()
    for f, body in (("graph.json", "{}"), ("audit.jsonl", "{}"), ("graph.graphml", "<graphml/>"),
                    ("maltego.csv", "source_type,source_value\n")):
        (case / f).write_text(body, encoding="utf-8")
    assert _get(server + "/api/sprawa_plik?sprawa=s1&typ=graphml")[0] == 403
    status, body, headers = _get(server + "/api/sprawa_plik?sprawa=s1&typ=maltego", app.TOKEN)
    assert status == 200 and body.startswith(b"source_type") and "s1_maltego.csv" in headers["Content-Disposition"]
    assert _get(server + "/api/sprawa_plik?sprawa=s1&typ=graphml", app.TOKEN)[1] == b"<graphml/>"
    for bad in ("sprawa=..&typ=graphml", "sprawa=s1&typ=json", "sprawa=s1&typ=audit", "sprawa=nie&typ=graphml"):
        assert _get(server + "/api/sprawa_plik?" + bad, app.TOKEN)[0] == 400
    assert json.loads(_get(server + "/api/sprawa_plik?sprawa=s1&typ=json", app.TOKEN)[1])["error"].startswith("typ")
