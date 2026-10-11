import json

import pytest
from conftest import good_domain
from dns_audit.analyze import analyze
from dns_audit.cli import main, normalize_domain
from dns_audit.collector import collect
from dns_audit.report import build_report, render_html, render_json, render_text


def make_report():
    d = collect("example.org", good_domain(), ["default"])
    return build_report(d, analyze(d))


def test_normalize_domain():
    assert normalize_domain("HTTPS://Example.COM/path?x=1") == "example.com"
    assert normalize_domain("user@example.com") == "example.com"
    assert normalize_domain("example.com.") == "example.com"
    assert normalize_domain("zażółć.pl") == "xn--za-gwa-0ya4a1d.pl" or normalize_domain("zażółć.pl").startswith("xn--")
    for bad in ("", "localhost", "a b.com", "-x.com", "exa_mple.com"):
        with pytest.raises(ValueError):
            normalize_domain(bad)


def test_render_text_contains_sections():
    text = render_text(make_report(), width=100)
    assert "AUDYT DNS I POCZTY: example.org" in text
    assert "ZEBRANE DANE" in text and "USTALENIA" in text
    assert "Podsumowanie:" in text
    assert "Microsoft 365" in text


def test_render_json_roundtrip():
    data = json.loads(render_json(make_report()))
    assert data["domain"] == "example.org"
    assert set(data["counts"]) == {"OK", "INFO", "WARN", "FAIL"}
    assert all(f["severity"] in data["counts"] for f in data["findings"])
    assert data["summary"]["spf"]["lookups"] == 1
    assert data["summary"]["dmarc"]["p"] == "reject"


def test_render_html_escapes():
    d = collect("example.org", good_domain().add("example.org", "TXT", "v=spf1 -all", "<script>alert(1)</script>"), [])
    html = render_html(build_report(d, analyze(d)))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert html.startswith("<!doctype html>")


def test_cli_text_json_html(tmp_path, capsys):
    r = good_domain()
    out_html = tmp_path / "r.html"
    assert main(["example.org", "--html", str(out_html), "--selectors", "x,y"], resolver=r) == 0
    assert "USTALENIA" in capsys.readouterr().out
    assert out_html.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert ("x._domainkey.example.org", "TXT") in r.calls

    assert main(["example.org", "--json", "--only-selectors", "--selectors", "only"], resolver=good_domain()) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["dkim_selectors_checked"] == 1


def test_cli_bad_input(capsys):
    assert main(["not a domain"], resolver=good_domain()) == 2
    assert main(["example.org", "--only-selectors"], resolver=good_domain()) == 2
    assert main(["example.org", "--resolver", "dns.google"]) == 2


# --- poprawki z przegladu kodu ---------------------------------------------------

def test_render_text_neutralizes_control_characters():
    r = good_domain().add("example.org", "TXT", "v=spf1 -all", "evil\x1b[2Jtext\x07\x9b")
    d = collect("example.org", r, [])
    text = render_text(build_report(d, analyze(d)), width=100)
    assert not any((ord(c) < 32 and c not in "\n\t") or 0x7F <= ord(c) <= 0x9F for c in text)
    assert "\\x1b[2Jtext\\x07\\x9b" in text


@pytest.mark.parametrize("bad", ["0", "-1", "nan", "inf", "abc"])
def test_cli_rejects_invalid_timeout(bad):
    with pytest.raises(SystemExit) as exc:
        main(["example.org", "--timeout", bad], resolver=good_domain())
    assert exc.value.code == 2


def test_cli_html_write_failure_keeps_report(tmp_path, capsys):
    target = tmp_path / "missing-dir" / "r.html"
    assert main(["example.org", "--html", str(target)], resolver=good_domain()) == 1
    cap = capsys.readouterr()
    assert "USTALENIA" in cap.out and "Zapisano raport HTML" not in cap.out
    assert "HTML" in cap.err


def test_cli_html_write_is_atomic(tmp_path, capsys, monkeypatch):
    import os
    target = tmp_path / "r.html"
    target.write_text("STARY", encoding="utf-8")

    def boom(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    assert main(["example.org", "--html", str(target)], resolver=good_domain()) == 1
    assert target.read_text(encoding="utf-8") == "STARY"
    assert [p.name for p in tmp_path.iterdir()] == ["r.html"]  # brak porzuconych plikow tymczasowych
    assert "USTALENIA" in capsys.readouterr().out
    monkeypatch.undo()
    assert main(["example.org", "--html", str(target)], resolver=good_domain()) == 0
    assert target.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert [p.name for p in tmp_path.iterdir()] == ["r.html"]
