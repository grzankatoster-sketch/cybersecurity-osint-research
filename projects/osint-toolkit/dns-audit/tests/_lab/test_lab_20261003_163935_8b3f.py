from conftest import good_domain
from dns_audit.analyze import analyze
from dns_audit.collector import collect
from dns_audit.models import Severity
from dns_audit.resolver import Status

D = "example.org"


def run(r):
    return analyze(collect(D, r, ["default"]))


def bimi_problems(findings):
    return [f for f in findings if f.area == "BIMI" and f.severity in (Severity.WARN, Severity.FAIL)]


def test_bimi_without_dmarc_is_warned():
    r = good_domain()
    # _dmarc nie istnieje (NXDOMAIN): pewny brak DMARC, wiec BIMI nie moze zadzialac
    del r.zone[(f"_dmarc.{D}", "TXT")]
    f = run(r)
    assert any(x.area == "BIMI" for x in f)
    assert bimi_problems(f), [(x.severity, x.title) for x in f if x.area == "BIMI"]


def test_bimi_dmarc_query_failed_is_not_treated_as_missing():
    r = good_domain().fail(f"_dmarc.{D}", "TXT", Status.TIMEOUT)
    f = run(r)
    assert bimi_problems(f) == []
