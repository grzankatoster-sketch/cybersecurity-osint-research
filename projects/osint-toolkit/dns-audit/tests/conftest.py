"""Falszywy resolver: DNS za interfejsem, testy bez sieci."""

import pytest

from dns_audit.resolver import DnsAnswer, Status


class FakeResolver:
    description = "fake"

    def __init__(self):
        self.zone: dict[tuple[str, str], DnsAnswer] = {}
        self.calls: list[tuple[str, str]] = []

    @staticmethod
    def _k(name, rtype):
        return (name.rstrip(".").lower(), rtype.upper())

    def add(self, name, rtype, *records, ad=False):
        self.zone[self._k(name, rtype)] = DnsAnswer(Status.OK, tuple(records), ad)
        return self

    def fail(self, name, rtype, status=Status.TIMEOUT):
        self.zone[self._k(name, rtype)] = DnsAnswer(status, error="fake")
        return self

    def query(self, name, rtype):
        key = self._k(name, rtype)
        self.calls.append(key)
        if key in self.zone:
            return self.zone[key]
        # nazwa istnieje z innym typem -> NODATA, inaczej NXDOMAIN
        if any(k[0] == key[0] for k in self.zone):
            return DnsAnswer(Status.NODATA)
        return DnsAnswer(Status.NXDOMAIN)


def good_domain(r: FakeResolver | None = None, domain="example.org") -> FakeResolver:
    r = r or FakeResolver()
    r.add(domain, "A", "192.0.2.1").add(domain, "AAAA", "2001:db8::1")
    r.add(domain, "NS", "ns1.dns.example.", "ns2.dns.example.")
    r.add(domain, "SOA", "ns1.dns.example. hostmaster.example.org. 2026100301 7200 3600 1209600 300")
    r.add(domain, "MX", "10 mx1.mail.example.", "20 mx2.mail.example.")
    r.add("mx1.mail.example", "A", "192.0.2.10").add("mx2.mail.example", "A", "192.0.2.11")
    r.add(domain, "TXT", "v=spf1 include:_spf.mail.example -all", "google-site-verification=abc", "MS=ms12345678", "hello world")
    r.add("_spf.mail.example", "TXT", "v=spf1 ip4:192.0.2.0/24 -all")
    r.add(domain, "CAA", '0 issue "letsencrypt.org"', '0 iodef "mailto:sec@example.org"')
    r.add(domain, "DNSKEY", "257 3 13 AAAA", ad=True)
    r.add(domain, "DS", "12345 13 2 ABCDEF")
    r.add(f"_dmarc.{domain}", "TXT", "v=DMARC1; p=reject; rua=mailto:dmarc@example.org")
    r.add(f"_mta-sts.{domain}", "TXT", "v=STSv1; id=20260101")
    r.add(f"_smtp._tls.{domain}", "TXT", "v=TLSRPTv1; rua=mailto:tls@example.org")
    r.add(f"default._bimi.{domain}", "TXT", "v=BIMI1; l=https://example.org/logo.svg")
    return r


@pytest.fixture
def fake():
    return FakeResolver()


@pytest.fixture
def good():
    return good_domain()
