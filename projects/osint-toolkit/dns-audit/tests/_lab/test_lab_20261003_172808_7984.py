"""DMARC bez tagu p, ale z rua: wg RFC 7489 6.6.3 obowiazuje p=none (tylko monitoring)."""

from dns_audit.analyze import analyze
from dns_audit.collector import DomainData
from dns_audit.models import Severity
from dns_audit.resolver import DnsAnswer, Status

D = "example.org"


def ok(*records, ad=False):
    return DnsAnswer(Status.OK, tuple(records), ad)


def domain(dmarc_record):
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
        dmarc=ok(dmarc_record),
        mta_sts=ok("v=STSv1; id=20260101"),
        tls_rpt=ok("v=TLSRPTv1; rua=mailto:tls@example.org"),
        bimi=ok("v=BIMI1; l=https://example.org/logo.svg"),
        mx_hosts={"mx1.mail.example": True, "mx2.mail.example": True},
        dkim={"default": DnsAnswer(Status.NXDOMAIN)},
        dkim_control=DnsAnswer(Status.NXDOMAIN),
    )


def sev(findings, area):
    return [f.severity for f in findings if f.area == area]


def test_dmarc_without_p_but_with_rua_is_monitoring_only():
    findings = analyze(domain("v=DMARC1; rua=mailto:dmarc@example.org"))
    # kontrola: jawne p=none daje ostrzezenie o braku ochrony
    explicit = analyze(domain("v=DMARC1; p=none; rua=mailto:dmarc@example.org"))
    assert Severity.WARN in sev(explicit, "DMARC")
    # brak p przy poprawnym rua = p=none (RFC 7489 6.6.3): ta sama ocena, nie cisza
    assert Severity.WARN in sev(findings, "DMARC"), [
        (f.severity.value, f.title) for f in findings if f.area == "DMARC"
    ]


def test_bimi_warns_when_effective_dmarc_policy_is_none():
    findings = analyze(domain("v=DMARC1; rua=mailto:dmarc@example.org"))
    assert Severity.WARN in sev(findings, "BIMI"), [
        (f.severity.value, f.title) for f in findings if f.area == "BIMI"
    ]
