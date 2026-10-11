"""Specyfikacja: wykrywanie wildcard DNS (A/MX) i jego wplyw na MX oraz DMARC sp."""

from conftest import FakeResolver, good_domain
from dns_audit.analyze import analyze
from dns_audit.collector import collect
from dns_audit.models import Severity
from dns_audit.report import build_report, render_text
from dns_audit.resolver import DnsAnswer, Status

D = 'example.org'


class WildResolver(FakeResolver):
    """FakeResolver z wildcardem: nieznana nazwa pod baza dostaje odpowiedz wildcard danego typu."""

    def __init__(self):
        super().__init__()
        self.wild: dict[tuple[str, str], DnsAnswer] = {}

    def add_wild(self, base, rtype, *records):
        self.wild[self._k(base, rtype)] = DnsAnswer(Status.OK, tuple(records))
        return self

    def fail_wild(self, base, rtype, status=Status.TIMEOUT):
        self.wild[self._k(base, rtype)] = DnsAnswer(status, error='fake')
        return self

    def query(self, name, rtype):
        key = self._k(name, rtype)
        if key not in self.zone:
            for (base, t), ans in self.wild.items():
                if t == key[1] and key[0].endswith('.' + base):
                    self.calls.append(key)
                    return ans
        return super().query(name, rtype)


def wild_domain():
    return good_domain(WildResolver())


def run(r):
    return analyze(collect(D, r, ['default']))


def pick(findings, area):
    return [f for f in findings if f.area == area]


def test_collector_probes_random_label_for_a_and_mx():
    r = wild_domain()
    d = collect(D, r, ['default'])
    probes = [k for k in r.calls if k[0].startswith('dnsaudit-') and k[0].endswith('.' + D) and '_domainkey' not in k[0]]
    assert {t for _, t in probes} == {'A', 'MX'}
    assert all(n.count('.') == D.count('.') + 1 for n, _ in probes)  # jedna losowa etykieta pod apeksem
    assert set(d.wildcard) == {'A', 'MX'}
    assert d.wildcard['A'].status is Status.NXDOMAIN


def test_no_wildcard_gives_ok_and_keeps_good_domain_clean():
    f = run(wild_domain())
    w = pick(f, 'Wildcard')
    assert len(w) == 1 and w[0].severity is Severity.OK and 'Brak wildcard' in w[0].title
    assert not [x for x in f if x.severity in (Severity.WARN, Severity.FAIL)]
    assert not any('fałszywie dodatni' in x.title for x in f)


def test_wildcard_a_is_warned_with_addresses():
    r = wild_domain().add_wild(D, 'A', '192.0.2.99')
    w = pick(run(r), 'Wildcard')
    assert any(x.severity is Severity.WARN and '192.0.2.99' in x.title and 'A' in x.title for x in w)
    assert not any('Brak wildcard' in x.title for x in w)


def test_mx_host_in_domain_flagged_as_possible_false_positive():
    r = wild_domain().add_wild(D, 'A', '192.0.2.99')
    r.add(D, 'MX', '10 mail.example.org.', '20 mx1.mail.example.')  # mail.example.org rozwiazuje sie tylko przez wildcard
    mx = pick(run(r), 'MX')
    flagged = [x for x in mx if 'fałszywie dodatni' in x.title]
    assert len(flagged) == 1 and flagged[0].severity is Severity.INFO
    assert 'mail.example.org' in flagged[0].title
    assert not any(x.severity is Severity.FAIL and 'mail.example.org' in x.title for x in mx)


def test_mx_host_not_flagged_without_wildcard():
    r = wild_domain()
    r.add(D, 'MX', '10 mail.example.org.').add('mail.example.org', 'A', '192.0.2.10')
    assert not any('fałszywie dodatni' in x.title for x in run(r))


def test_wildcard_mx_with_reject_policy_is_info():
    r = wild_domain().add_wild(D, 'MX', '10 catchall.mail.example.')  # DMARC p=reject, brak sp -> sp=reject
    w = [x for x in pick(run(r), 'Wildcard') if 'Wildcard MX' in x.title]
    assert len(w) == 1 and w[0].severity is Severity.INFO


def test_wildcard_mx_with_weak_subdomain_policy_is_warn():
    r = wild_domain().add_wild(D, 'MX', '10 catchall.mail.example.')
    r.add(f'_dmarc.{D}', 'TXT', 'v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.org')
    w = [x for x in pick(run(r), 'Wildcard') if 'Wildcard MX' in x.title]
    assert len(w) == 1 and w[0].severity is Severity.WARN


def test_wildcard_mx_without_dmarc_is_warn():
    r = wild_domain().add_wild(D, 'MX', '10 catchall.mail.example.')
    r.zone.pop((f'_dmarc.{D}', 'TXT'))
    w = [x for x in pick(run(r), 'Wildcard') if 'Wildcard MX' in x.title]
    assert len(w) == 1 and w[0].severity is Severity.WARN


def test_wildcard_mx_with_dmarc_query_failed_is_info_not_negative():
    r = wild_domain().add_wild(D, 'MX', '10 catchall.mail.example.')
    r.fail(f'_dmarc.{D}', 'TXT', Status.SERVFAIL)
    w = [x for x in pick(run(r), 'Wildcard') if 'Wildcard MX' in x.title]
    assert len(w) == 1 and w[0].severity is Severity.INFO
    assert 'nie udało się sprawdzić DMARC' in w[0].title


def test_failed_probes_are_unknown_not_absence():
    r = wild_domain().fail_wild(D, 'A').fail_wild(D, 'MX', Status.SERVFAIL)
    w = pick(run(r), 'Wildcard')
    assert w and all(x.severity is Severity.INFO for x in w)
    assert any('Niepełne sprawdzenie wildcard' in x.title for x in w)
    assert not any('Brak wildcard' in x.title for x in w)


def test_partial_failure_reports_found_and_unknown_separately():
    r = wild_domain().add_wild(D, 'A', '192.0.2.99').fail_wild(D, 'MX')
    w = pick(run(r), 'Wildcard')
    assert any(x.severity is Severity.WARN and '192.0.2.99' in x.title for x in w)
    assert any(x.severity is Severity.INFO and 'Niepełne sprawdzenie wildcard' in x.title and 'MX' in x.title for x in w)
    assert not any(x.severity is Severity.OK for x in w)


def test_wildcard_visible_in_text_and_json_report():
    r = wild_domain().add_wild(D, 'A', '192.0.2.99')
    d = collect(D, r, ['default'])
    rep = build_report(d, analyze(d))
    text = render_text(rep, width=200)
    assert 'Wildcard' in text and '192.0.2.99' in text
    assert any(f['area'] == 'Wildcard' and f['severity'] == 'WARN' for f in rep.to_dict()['findings'])
