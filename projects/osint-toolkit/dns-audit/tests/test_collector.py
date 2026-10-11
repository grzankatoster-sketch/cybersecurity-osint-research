from conftest import FakeResolver, good_domain
from dns_audit.collector import collect, merge_selectors
from dns_audit.dkim import DEFAULT_SELECTORS
from dns_audit.resolver import Status


def test_merge_selectors():
    s = merge_selectors(["Custom", "default", " x._domainkey "])
    assert s[: len(DEFAULT_SELECTORS)] == list(DEFAULT_SELECTORS)
    assert s[-2:] == ["custom", "x"]
    assert merge_selectors(["a"], use_defaults=False) == ["a"]


def test_collect_queries_everything():
    r = good_domain()
    r.add("google._domainkey.example.org", "TXT", "v=DKIM1; p=AAAA")
    d = collect("Example.org.", r, ["google", "custom"])
    assert d.domain == "example.org"
    assert d.a.ok and d.mx.ok and d.dmarc.ok and d.mta_sts.ok and d.bimi.ok
    assert d.dkim["google"].ok and not d.dkim["custom"].ok
    assert ("_dmarc.example.org", "TXT") in r.calls
    assert ("_smtp._tls.example.org", "TXT") in r.calls
    assert ("default._bimi.example.org", "TXT") in r.calls
    assert ("custom._domainkey.example.org", "TXT") in r.calls
    assert d.mx_hosts == {"mx1.mail.example": True, "mx2.mail.example": True}
    assert d.spf_lookups.count == 1 and d.spf_lookups.effective_all == "-"


def test_mx_host_without_address_and_errors():
    r = FakeResolver().add("example.org", "MX", "10 ghost.example.", "20 flaky.example.")
    r.fail("flaky.example", "A")
    d = collect("example.org", r, [])
    assert d.mx_hosts == {"ghost.example": False, "flaky.example": None}


def test_exception_from_resolver_is_contained():
    class Boom(FakeResolver):
        def query(self, name, rtype):
            raise RuntimeError("boom")

    d = collect("example.org", Boom(), ["a"])
    assert d.a.status is Status.ERROR and d.a.failed
    assert d.spf_lookups is None


def test_spf_include_fetch_failure_is_error_not_missing():
    r = FakeResolver().add("example.org", "TXT", "v=spf1 include:down.example -all")
    r.fail("down.example", "TXT")
    d = collect("example.org", r, [])
    assert any("nie udalo sie pobrac" in e for e in d.spf_lookups.errors)
