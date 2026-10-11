"""Redirect SPF, ktorego celu nie udalo sie pobrac (blad DNS), to stan nieznany, nie 'brak all/redirect'."""

from dns_audit.analyze import analyze
from dns_audit.collector import collect
from dns_audit.models import Severity
from dns_audit.resolver import DnsAnswer, Status


class _Resolver:
    description = "fake"

    def __init__(self):
        self.zone = {}

    def add(self, name, rtype, *records, ad=False):
        self.zone[(name.lower(), rtype)] = DnsAnswer(Status.OK, tuple(records), ad)
        return self

    def fail(self, name, rtype, status=Status.TIMEOUT):
        self.zone[(name.lower(), rtype)] = DnsAnswer(status, error="fake")
        return self

    def query(self, name, rtype):
        key = (name.rstrip(".").lower(), rtype.upper())
        if key in self.zone:
            return self.zone[key]
        if any(k[0] == key[0] for k in self.zone):
            return DnsAnswer(Status.NODATA)
        return DnsAnswer(Status.NXDOMAIN)


def _domain(status):
    d = "example.org"
    r = _Resolver()
    r.add(d, "A", "192.0.2.1").add(d, "AAAA", "2001:db8::1")
    r.add(d, "NS", "ns1.dns.example.", "ns2.dns.example.")
    r.add(d, "SOA", "ns1.dns.example. hostmaster.example.org. 2026100301 7200 3600 1209600 300")
    r.add(d, "MX", "10 mx1.mail.example.")
    r.add("mx1.mail.example", "A", "192.0.2.10")
    r.add(d, "TXT", "v=spf1 redirect=_spf.mail.example")
    r.fail("_spf.mail.example", "TXT", status)
    r.add(f"_dmarc.{d}", "TXT", "v=DMARC1; p=reject; rua=mailto:dmarc@example.org")
    return r


def _spf_findings(status):
    data = collect("example.org", _domain(status), [])
    return [f for f in analyze(data) if f.area == "SPF"]


def test_redirect_fetch_failure_is_not_reported_as_missing_all_or_redirect():
    for status in (Status.TIMEOUT, Status.SERVFAIL, Status.ERROR):
        spf = _spf_findings(status)
        # blad pobrania celu redirect jest zgloszony jako blad zapytania
        assert any("nie udalo sie pobrac" in f.title for f in spf), [f.title for f in spf]
        # ale rekord MA redirect: twierdzenie o braku all/redirect jest falszywe (UNKNOWN != BAD)
        wrong = [f for f in spf if "ani redirect" in f.title]
        assert not wrong, f"{status}: blad DNS zamieniony w wynik negatywny: {[f.title for f in wrong]}"
        # i nie wolno zalecac dopisania '-all' na podstawie bledu sieci
        assert not any(
            f.severity in (Severity.WARN, Severity.FAIL) and "Dodaj '-all'" in (f.recommendation or "")
            for f in spf
        ), [(f.severity, f.title) for f in spf]
