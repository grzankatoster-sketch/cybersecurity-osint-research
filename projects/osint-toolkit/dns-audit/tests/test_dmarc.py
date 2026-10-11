from dns_audit.dmarc import is_dmarc, parse_dmarc


def test_full_record():
    r = parse_dmarc("v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:a@x.org, mailto:b@x.org; adkim=s")
    assert r.p == "quarantine" and r.sp == "reject" and r.pct == 50
    assert r.rua == ["mailto:a@x.org", "mailto:b@x.org"]
    assert r.adkim == "s" and r.aspf == "r"
    assert not r.errors


def test_defaults():
    r = parse_dmarc("v=DMARC1; p=none")
    assert r.pct == 100 and r.sp is None and r.rua == []


def test_case_and_spaces():
    r = parse_dmarc("v=DMARC1;p=REJECT;rua=mailto:x@y.org;")
    assert r.p == "reject"
    assert is_dmarc("v=DMARC1;p=none") and is_dmarc("v = DMARC1; p=none")
    assert not is_dmarc("v=spf1 -all")


def test_errors():
    assert parse_dmarc("v=DMARC1; p=bogus").errors
    assert parse_dmarc("v=DMARC1; p=none; pct=200").errors
    assert parse_dmarc("v=DMARC1").errors  # brak p i rua
    assert any("powtorzony" in e for e in parse_dmarc("v=DMARC1; p=none; p=reject").errors)


def test_p_missing_but_rua_allowed():
    assert not parse_dmarc("v=DMARC1; rua=mailto:a@x.org").errors
