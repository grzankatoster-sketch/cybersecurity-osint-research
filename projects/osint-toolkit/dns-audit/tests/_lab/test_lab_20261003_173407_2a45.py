"""Wiele rekordow BIMI na default._bimi: specyfikacja BIMI traktuje to jak brak rekordu, wiec nie moze byc OK."""

from dns_audit.analyze import analyze
from dns_audit.collector import DomainData
from dns_audit.models import Severity
from dns_audit.resolver import DnsAnswer, Status

D = "example.org"


def ok(*records, ad=False):
    return DnsAnswer(Status.OK, tuple(records), ad)


def nodata():
    return DnsAnswer(Status.NODATA)


def domain_data(bimi: DnsAnswer) -> DomainData:
    return DomainData(
        domain=D,
        a=ok("192.0.2.1"),
        aaaa=ok("2001:db8::1"),
        ns=ok("ns1.dns.example.", "ns2.dns.example."),
        soa=ok("ns1.dns.example. hostmaster.example.org. 2026100301 7200 3600 1209600 300"),
        mx=ok("10 mx1.mail.example.", "20 mx2.mail.example."),
        txt=ok("v=spf1 ip4:192.0.2.0/24 -all"),
        caa=ok('0 issue "letsencrypt.org"', '0 iodef "mailto:sec@example.org"'),
        dnskey=ok("257 3 13 AAAA", ad=True),
        ds=ok("12345 13 2 ABCDEF"),
        dmarc=ok("v=DMARC1; p=reject; rua=mailto:dmarc@example.org"),
        mta_sts=ok("v=STSv1; id=20260101"),
        tls_rpt=ok("v=TLSRPTv1; rua=mailto:tls@example.org"),
        bimi=bimi,
        mx_hosts={"mx1.mail.example": True, "mx2.mail.example": True},
        dkim={"default": nodata()},
        dkim_control=nodata(),
    )


def bimi_findings(bimi: DnsAnswer):
    return [f for f in analyze(domain_data(bimi)) if f.area == "BIMI"]


def test_single_bimi_record_is_ok():
    f = bimi_findings(ok("v=BIMI1; l=https://example.org/logo.svg"))
    assert any(x.severity is Severity.OK for x in f), f


def test_multiple_bimi_records_are_not_ok():
    f = bimi_findings(ok(
        "v=BIMI1; l=https://example.org/logo.svg",
        "v=BIMI1; l=https://example.org/other.svg",
    ))
    assert not any(x.severity is Severity.OK for x in f), f
    assert any(x.severity in (Severity.WARN, Severity.FAIL) for x in f), f
