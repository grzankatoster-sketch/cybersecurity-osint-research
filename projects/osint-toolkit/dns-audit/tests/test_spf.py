from dns_audit.spf import count_lookups, is_spf, parse_spf, select_spf


def test_is_spf():
    assert is_spf("v=spf1 -all")
    assert is_spf("V=SPF1 include:x -all")
    assert not is_spf("v=spf10 -all")
    assert not is_spf("google-site-verification=v=spf1")


def test_parse_mechanisms_and_qualifiers():
    r = parse_spf("v=spf1 ip4:192.0.2.0/24 a mx:mail.example.com/24 include:_spf.google.com ~all")
    names = [(t.qualifier, t.mechanism, t.value) for t in r.terms]
    assert names == [
        ("+", "ip4", "192.0.2.0/24"),
        ("+", "a", None),
        ("+", "mx", "mail.example.com"),
        ("+", "include", "_spf.google.com"),
        ("~", "all", None),
    ]
    assert r.all_qualifier == "~"
    assert not r.errors


def test_parse_redirect_and_errors():
    r = parse_spf("v=spf1 redirect=_spf.example.com")
    assert r.redirect == "_spf.example.com"
    assert r.all_qualifier is None
    bad = parse_spf("v=spf1 foo:bar include: -all")
    assert len(bad.errors) == 2


def test_all_qualifiers():
    for q in "+-~?":
        assert parse_spf(f"v=spf1 {q}all").all_qualifier == q
    assert parse_spf("v=spf1 all").all_qualifier == "+"


def test_select_spf():
    assert select_spf(["foo", "v=spf1 -all", "v=spf1 ~all"]) == ["v=spf1 -all", "v=spf1 ~all"]


def _fetch(zone):
    return lambda name: zone.get(name, [])


def test_lookup_count_recursive():
    zone = {
        "a.example": ["v=spf1 include:b.example include:c.example mx -all"],
        "b.example": ["v=spf1 a ip4:1.2.3.4 -all"],
        "c.example": ["v=spf1 exists:%{i}.x.example ~all"],
    }
    top = parse_spf("v=spf1 include:a.example a -all")
    res = count_lookups("example.org", top, _fetch(zone))
    # include a, include b, a, include c, exists, mx, a (top) = 7
    assert res.count == 7
    assert res.effective_all == "-"
    assert not res.errors


def test_lookup_over_limit_and_missing_include():
    zone = {f"i{n}.example": ["v=spf1 a mx -all"] for n in range(5)}
    top = parse_spf("v=spf1 " + " ".join(f"include:i{n}.example" for n in range(5)) + " include:gone.example -all")
    res = count_lookups("example.org", top, _fetch(zone))
    assert res.count == 6 + 10
    assert res.over_limit
    assert any("gone.example" in e and "PermError" in e for e in res.errors)


def test_redirect_counts_and_gives_effective_all():
    zone = {"policy.example": ["v=spf1 ip4:1.1.1.1 -all"]}
    res = count_lookups("example.org", parse_spf("v=spf1 redirect=policy.example"), _fetch(zone))
    assert res.count == 1
    assert res.effective_all == "-"


def test_redirect_ignored_when_all_present():
    res = count_lookups("example.org", parse_spf("v=spf1 ~all redirect=x.example"), _fetch({}))
    assert res.count == 0 and res.effective_all == "~"


def test_loop_detected():
    zone = {"a.example": ["v=spf1 include:b.example -all"], "b.example": ["v=spf1 include:a.example -all"]}
    res = count_lookups("example.org", parse_spf("v=spf1 include:a.example -all"), _fetch(zone))
    assert any("petla" in e for e in res.errors)
    assert res.count < 10


def test_fetch_failure_reported():
    res = count_lookups("example.org", parse_spf("v=spf1 include:x.example -all"), lambda n: None)
    assert any("nie udalo sie" in e for e in res.errors)


def test_ptr_flagged():
    res = count_lookups("example.org", parse_spf("v=spf1 ptr -all"), _fetch({}))
    assert res.uses_ptr and res.count == 1


# --- poprawki z przegladu kodu ---------------------------------------------------

from dns_audit.spf import MAX_EXPANSIONS  # noqa: E402


def test_budget_limits_fetches_and_reports_error():
    zone = {f"n{i}.example": ["v=spf1 ip4:192.0.2.1 -all"] for i in range(MAX_EXPANSIONS + 10)}
    calls = []

    def fetch(name):
        calls.append(name)
        return zone.get(name, [])

    top = parse_spf("v=spf1 " + " ".join(f"include:n{i}.example" for i in range(MAX_EXPANSIONS + 10)) + " -all")
    res = count_lookups("example.org", top, fetch)
    assert len(calls) <= MAX_EXPANSIONS
    assert res.budget_exceeded
    assert any("przekroczono budżet analizy" in e for e in res.errors)


def test_diamond_graph_is_memoized():
    # 9 poziomow, kazdy wezel dolacza dwa kolejne: bez memo ~1000 odwiedzin, z memo 18 domen
    zone = {}
    for lvl in range(9):
        nxt = " ".join(f"include:{c}{lvl + 1}.example" for c in "xy")
        for c in "xy":
            zone[f"{c}{lvl}.example"] = [f"v=spf1 {nxt} -all"]
    for c in "xy":
        zone[f"{c}9.example"] = ["v=spf1 ip4:192.0.2.1 -all"]
    calls = []

    def fetch(name):
        calls.append(name)
        return zone.get(name, [])

    res = count_lookups("example.org", parse_spf("v=spf1 include:x0.example include:y0.example -all"), fetch)
    assert len(calls) <= 20
    assert not res.budget_exceeded
    assert res.over_limit


def test_counting_stops_at_first_all():
    calls = []

    def fetch(name):
        calls.append(name)
        return ["v=spf1 -all"]

    res = count_lookups("example.org", parse_spf("v=spf1 -all include:x.example a mx"), fetch)
    assert res.count == 0 and not calls and not res.includes


def test_child_syntax_errors_propagated_with_domain():
    zone = {"child.example": ["v=spf1 foo:bar ip4:999.1.1.1 -all"]}
    res = count_lookups("example.org", parse_spf("v=spf1 include:child.example -all"), _fetch(zone))
    assert len(res.syntax_errors) == 2
    assert all("child.example" in e for e in res.syntax_errors)


def test_ip_and_cidr_validation():
    bad = [
        "ip4:999.1.1.1", "ip4:192.0.2.0/33", "ip4:2001:db8::1", "ip4:192.0.2.1/255.255.255.0",
        "ip6:zzz", "ip6:2001:db8::/129", "ip6:192.0.2.1",
        "a/999", "mx/33", "a//129", "mx:mail.example.com/24//129", "a/x", "a:",
    ]
    for tok in bad:
        assert parse_spf(f"v=spf1 {tok} -all").errors, tok
    good = [
        "ip4:192.0.2.1", "ip4:192.0.2.0/24", "ip6:2001:db8::/32", "ip6:2001:db8::1",
        "a", "a/24", "a//64", "a/24//64", "a:x.example/24//64", "mx:mail.example.com/24",
    ]
    for tok in good:
        assert not parse_spf(f"v=spf1 {tok} -all").errors, tok
