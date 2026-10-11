from conftest import FakeResolver, good_domain
from dns_audit.analyze import analyze, parse_caa, parse_mx, parse_soa
from dns_audit.collector import collect
from dns_audit.models import Severity
from dns_audit.resolver import DnsAnswer, Status
from test_dkim import txt_for

D = "example.org"


def run(r, selectors=("default",)):
    return analyze(collect(D, r, list(selectors)))


def pick(findings, area):
    return [f for f in findings if f.area == area]


def has(findings, area, severity, text):
    return any(f.area == area and f.severity == severity and text in f.title for f in findings)


def test_nxdomain():
    f = run(FakeResolver())
    assert len(f) == 1 and f[0].severity == Severity.FAIL and "NXDOMAIN" in f[0].title


def test_good_domain_has_no_fail_or_warn():
    r = good_domain().add(f"default._domainkey.{D}", "TXT", txt_for(2048))
    bad = [x for x in run(r) if x.severity in (Severity.FAIL, Severity.WARN)]
    assert bad == [], bad


def test_spf_missing_fail_when_mail():
    r = good_domain().add(D, "TXT", "google-site-verification=x")
    assert has(run(r), "SPF", Severity.FAIL, "Brak rekordu SPF")


def test_spf_all_variants():
    for qual, severity in (("+all", Severity.FAIL), ("?all", Severity.WARN), ("~all", Severity.INFO), ("-all", Severity.OK)):
        r = good_domain().add(D, "TXT", f"v=spf1 ip4:192.0.2.1 {qual}")
        assert has(run(r), "SPF", severity, qual), qual


def test_spf_no_all():
    r = good_domain().add(D, "TXT", "v=spf1 ip4:192.0.2.1")
    assert has(run(r), "SPF", Severity.WARN, "nie kończy się")


def test_spf_multiple_records():
    r = good_domain().add(D, "TXT", "v=spf1 -all", "v=spf1 ~all")
    assert has(run(r), "SPF", Severity.FAIL, "Wiele rekordów SPF")


def test_spf_over_10_lookups():
    r = good_domain()
    includes = " ".join(f"include:s{i}.example" for i in range(11))
    r.add(D, "TXT", f"v=spf1 {includes} -all")
    for i in range(11):
        r.add(f"s{i}.example", "TXT", "v=spf1 ip4:192.0.2.5 -all")
    assert has(run(r), "SPF", Severity.FAIL, "11 lookupów")


def test_spf_near_limit_warn():
    r = good_domain()
    includes = " ".join(f"include:s{i}.example" for i in range(9))
    r.add(D, "TXT", f"v=spf1 {includes} -all")
    for i in range(9):
        r.add(f"s{i}.example", "TXT", "v=spf1 ip4:192.0.2.5 -all")
    assert has(run(r), "SPF", Severity.WARN, "9/10")


def test_dmarc_missing_and_policies():
    r = good_domain()
    r.zone.pop((f"_dmarc.{D}", "TXT"))
    assert has(run(r), "DMARC", Severity.FAIL, "Brak rekordu DMARC")
    for pol, severity in (("none", Severity.WARN), ("quarantine", Severity.INFO), ("reject", Severity.OK)):
        r.add(f"_dmarc.{D}", "TXT", f"v=DMARC1; p={pol}; rua=mailto:a@example.org")
        assert has(run(r), "DMARC", severity, f"p={pol}"), pol


def test_dmarc_details():
    r = good_domain().add(f"_dmarc.{D}", "TXT", "v=DMARC1; p=reject; sp=none; pct=25")
    f = run(r)
    assert has(f, "DMARC", Severity.WARN, "pct=25")
    assert has(f, "DMARC", Severity.WARN, "sp=none")
    assert has(f, "DMARC", Severity.INFO, "rua")


def test_dmarc_query_failure_is_not_missing():
    r = good_domain().fail(f"_dmarc.{D}", "TXT")
    f = run(r)
    assert not has(f, "DMARC", Severity.FAIL, "Brak")
    assert has(f, "DMARC", Severity.INFO, "Nie udało się sprawdzić")


def test_dnssec_variants():
    r = good_domain()
    assert has(run(r), "DNSSEC", Severity.OK, "flaga AD")
    r.add(D, "DNSKEY", "257 3 13 AAAA", ad=False)
    assert has(run(r), "DNSSEC", Severity.INFO, "flagi AD")
    r.zone.pop((D, "DS"))
    assert has(run(r), "DNSSEC", Severity.WARN, "brak rekordu DS")
    r.zone.pop((D, "DNSKEY"))
    assert has(run(r), "DNSSEC", Severity.WARN, "Brak DNSSEC")
    r.add(D, "DS", "1 13 2 AA")
    assert has(run(r), "DNSSEC", Severity.FAIL, "DS")


def test_dnssec_weak_algorithm():
    r = good_domain().add(D, "DNSKEY", "257 3 5 AAAA")
    assert has(run(r), "DNSSEC", Severity.WARN, "RSASHA1")


def test_dkim_found_and_weak():
    r = good_domain()
    r.add(f"default._domainkey.{D}", "TXT", txt_for(1024))
    r.add(f"google._domainkey.{D}", "TXT", txt_for(2048))
    f = run(r, ["default", "google", "s1"])
    assert has(f, "DKIM", Severity.WARN, "1024")
    assert has(f, "DKIM", Severity.OK, "RSA 2048")


def test_dkim_not_found_is_info_only():
    f = run(good_domain())
    assert {x.severity for x in pick(f, "DKIM")} == {Severity.INFO}


def test_dkim_wildcard_detected():
    class Wild(FakeResolver):
        def query(self, name, rtype):
            if "._domainkey." in name:
                return DnsAnswer(Status.OK, (txt_for(2048),))
            return super().query(name, rtype)

    assert has(run(good_domain(Wild())), "DKIM", Severity.WARN, "Wildcard")


def test_non_mail_domain_null_mx():
    r = FakeResolver()
    r.add(D, "A", "192.0.2.1").add(D, "NS", "ns1.x.", "ns2.x.")
    r.add(D, "SOA", "ns1.x. h.x. 1 2 3 4 5")
    r.add(D, "MX", "0 .")
    r.add(D, "TXT", "v=spf1 -all")
    f = run(r)
    assert has(f, "MX", Severity.OK, "Null MX")
    assert not pick(f, "DKIM") and not pick(f, "MTA-STS") and not pick(f, "BIMI")
    assert has(f, "DMARC", Severity.WARN, "Brak rekordu DMARC")  # WARN, nie FAIL


def test_mx_problems():
    r = good_domain().add(D, "MX", "10 ghost.example.", "20 192.0.2.7")
    r.add("192.0.2.7", "A", "192.0.2.7")
    f = run(r)
    assert has(f, "MX", Severity.FAIL, "ghost.example")
    assert has(f, "MX", Severity.FAIL, "adres IP")


def test_mx_provider_detected():
    r = good_domain().add(D, "MX", "1 aspmx.l.google.com.")
    r.add("aspmx.l.google.com", "A", "192.0.2.9")
    assert has(run(r), "MX", Severity.OK, "Google Workspace")


def test_caa_missing_info_and_present_ok():
    r = good_domain()
    assert has(run(r), "CAA", Severity.OK, "letsencrypt.org")
    r.zone.pop((D, "CAA"))
    assert has(run(r), "CAA", Severity.INFO, "Brak lokalnego rekordu CAA")


def test_ns_single_warn():
    r = good_domain().add(D, "NS", "ns1.x.")
    assert has(run(r), "NS", Severity.WARN, "jeden serwer")


def test_mta_sts_tls_rpt_bimi_missing():
    r = good_domain()
    for k in (f"_mta-sts.{D}", f"_smtp._tls.{D}", f"default._bimi.{D}"):
        r.zone.pop((k, "TXT"))
    f = run(r)
    assert has(f, "MTA-STS", Severity.INFO, "Brak MTA-STS")
    assert has(f, "TLS-RPT", Severity.INFO, "Brak TLS-RPT")
    assert has(f, "BIMI", Severity.INFO, "Brak BIMI")


def test_bimi_requires_enforced_dmarc():
    r = good_domain().add(f"_dmarc.{D}", "TXT", "v=DMARC1; p=none; rua=mailto:a@example.org")
    assert has(run(r), "BIMI", Severity.WARN, "p=none")


def test_verification_listed_by_service():
    t = [x for x in run(good_domain()) if x.area == "TXT"]
    assert any("Google" in x.title and "Microsoft 365" in x.title for x in t)
    assert any("Nierozpoznane rekordy TXT: 1" in x.title for x in t)


def test_parsers():
    assert parse_mx(["20 b.example.", "10 a.example."]) == [(10, "a.example"), (20, "b.example")]
    assert parse_caa(['0 issue "letsencrypt.org"', '128 iodef "mailto:a@b.c"']) == [
        ("issue", "letsencrypt.org"), ("iodef", "mailto:a@b.c")]
    assert parse_soa(["ns. h. 5 1 2 3 4"])["serial"] == 5


def test_dkim_wildcard_revoked_is_info():
    class Null(FakeResolver):
        def query(self, name, rtype):
            if "._domainkey." in name:
                return DnsAnswer(Status.OK, ("v=DKIM1; p=",))
            return super().query(name, rtype)

    f = run(good_domain(Null()))
    assert has(f, "DKIM", Severity.INFO, "Wildcard")
    assert not any(x.severity in (Severity.WARN, Severity.FAIL) for x in pick(f, "DKIM"))


def test_dkim_revoked_collapsed():
    r = good_domain()
    r.add(f"s1._domainkey.{D}", "TXT", "v=DKIM1; p=").add(f"s2._domainkey.{D}", "TXT", "v=DKIM1; p=")
    f = [x for x in run(r, ["s1", "s2"]) if x.area == "DKIM"]
    assert len(f) == 1 and "s1, s2" in f[0].title and f[0].severity == Severity.INFO


# --- poprawki z przegladu kodu ---------------------------------------------------

from dns_audit.report import build_report, summary_rows  # noqa: E402


def sev(findings, area, severity):
    return [f for f in findings if f.area == area and f.severity == severity]


def test_spf_stops_counting_at_all_no_false_over_limit():
    r = good_domain()
    r.add(D, "TXT", "v=spf1 -all " + " ".join(f"include:s{i}.example" for i in range(12)))
    f = run(r)
    assert not sev(f, "SPF", Severity.FAIL), f
    assert has(f, "SPF", Severity.OK, "0/10")


def test_spf_child_syntax_error_is_fail_with_domain():
    r = good_domain().add("_spf.mail.example", "TXT", "v=spf1 foo:bar -all")
    f = run(r)
    assert any(x.severity == Severity.FAIL and "_spf.mail.example" in x.title and "składni" in x.title for x in pick(f, "SPF")), f


def test_spf_budget_exceeded_is_explicit_fail():
    r = good_domain()
    r.add(D, "TXT", "v=spf1 " + " ".join(f"include:s{i}.example" for i in range(60)) + " -all")
    for i in range(60):
        r.add(f"s{i}.example", "TXT", "v=spf1 ip4:192.0.2.5 -all")
    f = run(r)
    assert has(f, "SPF", Severity.FAIL, "przekroczono budżet analizy")


def test_spf_invalid_ip_reported():
    r = good_domain().add(D, "TXT", "v=spf1 ip4:999.1.1.1 a/999 -all")
    assert len(sev(run(r), "SPF", Severity.FAIL)) == 2


def test_dnssec_ds_present_dnskey_timeout_is_info_not_fail():
    r = good_domain().fail(D, "DNSKEY")
    f = pick(run(r), "DNSSEC")
    assert [x.severity for x in f] == [Severity.INFO] and "Nie udało się sprawdzić" in f[0].title
    assert not any("usuń DS" in x.recommendation for x in f)


def test_dnssec_dnskey_present_ds_timeout_is_info_not_warn():
    r = good_domain().fail(D, "DS", Status.SERVFAIL)
    f = pick(run(r), "DNSSEC")
    assert [x.severity for x in f] == [Severity.INFO] and "Nie udało się sprawdzić" in f[0].title


def test_dnssec_ad_from_ds_alone_does_not_confirm_validation():
    r = good_domain().add(D, "DNSKEY", "257 3 13 AAAA", ad=False).add(D, "DS", "12345 13 2 ABCDEF", ad=True)
    f = run(r)
    assert not has(f, "DNSSEC", Severity.OK, "flaga AD")
    assert has(f, "DNSSEC", Severity.INFO, "flagi AD")
    d = collect(D, r, [])
    assert build_report(d, analyze(d)).summary["dnssec"]["ad_flag"] is False


def test_dkim_ed25519_bad_key_is_warn_not_ok():
    r = good_domain().add(f"default._domainkey.{D}", "TXT", "v=DKIM1; k=ed25519; p=YQ==")
    f = pick(run(r), "DKIM")
    assert any(x.severity == Severity.WARN for x in f)
    assert not any(x.severity == Severity.OK for x in f)


def test_dkim_unknown_type_is_warn_not_ok():
    r = good_domain().add(f"default._domainkey.{D}", "TXT", "v=DKIM1; k=foo; p=QUJD")
    f = pick(run(r), "DKIM")
    assert any(x.severity == Severity.WARN and "foo" in x.title for x in f)
    assert not any(x.severity == Severity.OK for x in f)


def test_dkim_duplicate_tags_warn():
    r = good_domain().add(f"default._domainkey.{D}", "TXT", txt_for(2048, "k=rsa; "))
    f = pick(run(r), "DKIM")
    assert any(x.severity == Severity.WARN and "powtorzony tag" in x.title for x in f)
    assert not any(x.severity == Severity.OK for x in f)


class _Wild(FakeResolver):
    """Wildcard na _domainkey zwracajacy `wild`; `special` nadpisuje wybrane selektory."""

    def __init__(self, wild, special=None):
        super().__init__()
        self.wild, self.special = wild, special or {}

    def query(self, name, rtype):
        if "._domainkey." in name:
            sel = name.split(".", 1)[0]
            return DnsAnswer(Status.OK, (self.special.get(sel, self.wild),))
        return super().query(name, rtype)


def test_dkim_wildcard_does_not_hide_explicit_selector():
    r = good_domain(_Wild(txt_for(2048)))
    d = collect(D, r, ["default", "mine"], explicit_selectors=["mine"])
    f = analyze(d)
    assert has(f, "DKIM", Severity.WARN, "Wildcard")
    assert has(f, "DKIM", Severity.OK, "'mine'")
    assert not any("'default'" in x.title for x in pick(f, "DKIM"))
    assert [k["selector"] for k in build_report(d, f).summary["dkim"]] == ["mine"]


def test_dkim_wildcard_does_not_hide_selector_differing_from_wildcard():
    r = good_domain(_Wild(txt_for(2048), {"k1": txt_for(1024)}))
    f = run(r, ["default", "k1"])
    assert has(f, "DKIM", Severity.WARN, "Wildcard")
    assert has(f, "DKIM", Severity.WARN, "'k1'")


def test_dkim_partial_query_failures_reported():
    r = good_domain().add(f"default._domainkey.{D}", "TXT", txt_for(2048)).fail(f"google._domainkey.{D}", "TXT")
    f = run(r, ["default", "google"])
    assert has(f, "DKIM", Severity.OK, "RSA 2048")
    assert has(f, "DKIM", Severity.INFO, "Niepełne sprawdzenie")


def test_dkim_partial_failures_when_none_found_reported():
    r = good_domain().fail(f"google._domainkey.{D}", "TXT")
    f = run(r, ["default", "google"])
    assert has(f, "DKIM", Severity.INFO, "Niepełne sprawdzenie")


def test_dkim_wildcard_control_failure_reported():
    class CtlFail(FakeResolver):
        def query(self, name, rtype):
            if name.startswith("dnsaudit-"):
                return DnsAnswer(Status.TIMEOUT, error="x")
            return super().query(name, rtype)

    f = run(good_domain(CtlFail()))
    assert has(f, "DKIM", Severity.INFO, "kontroli wildcard")


def test_dkim_evaluated_when_mx_lookup_fails():
    r = good_domain().fail(D, "MX").add(f"default._domainkey.{D}", "TXT", txt_for(2048))
    f = run(r)
    assert has(f, "DKIM", Severity.OK, "RSA 2048")
    assert pick(f, "MTA-STS") and pick(f, "TLS-RPT")


def test_dkim_evaluated_when_no_mx_but_not_null_mx():
    r = good_domain()
    r.zone.pop((D, "MX"))
    r.add(f"default._domainkey.{D}", "TXT", txt_for(2048))
    assert has(run(r), "DKIM", Severity.OK, "RSA 2048")


def test_caa_issue_and_issuewild_separate():
    r = good_domain().add(D, "CAA", '0 issuewild ";"')
    f = run(r)
    assert has(f, "CAA", Severity.OK, "issuewild: zabronione")
    assert has(f, "CAA", Severity.OK, "issue: brak wpisu")
    assert not any("zabrania wystawiania" in x.title for x in pick(f, "CAA"))
    r.add(D, "CAA", '0 issue "letsencrypt.org; accounturi=https://x.example/acct/1"', '0 issuewild ";"')
    assert has(run(r), "CAA", Severity.OK, "issue: letsencrypt.org; issuewild: zabronione")
    r.add(D, "CAA", '0 issue ";"')
    assert has(run(r), "CAA", Severity.OK, "issue: zabronione; issuewild: brak wpisu")


def test_caa_absent_message_mentions_inheritance():
    r = good_domain()
    r.zone.pop((D, "CAA"))
    t = pick(run(r), "CAA")[0].title
    assert "lokalnego rekordu CAA" in t and "dziedziczyć" in t and "dowolny urząd" not in t


def test_mta_sts_exact_version_and_multiple_records():
    r = good_domain().add(f"_mta-sts.{D}", "TXT", "v=STSv10; id=1")
    assert has(run(r), "MTA-STS", Severity.INFO, "Brak MTA-STS")
    r.add(f"_mta-sts.{D}", "TXT", "v=STSv1; id=1", "v=STSv1; id=2")
    f = run(r)
    assert has(f, "MTA-STS", Severity.WARN, "Wiele rekordów")
    assert not sev(f, "MTA-STS", Severity.OK)


def test_tls_rpt_exact_version_and_multiple_records():
    r = good_domain().add(f"_smtp._tls.{D}", "TXT", "v=TLSRPTv10; rua=mailto:a@example.org")
    assert has(run(r), "TLS-RPT", Severity.INFO, "Brak TLS-RPT")
    r.add(f"_smtp._tls.{D}", "TXT", "v=TLSRPTv1; rua=mailto:a@example.org", "v=TLSRPTv1; rua=mailto:b@example.org")
    f = run(r)
    assert has(f, "TLS-RPT", Severity.WARN, "Wiele rekordów")
    assert not sev(f, "TLS-RPT", Severity.OK)


def test_summary_uses_same_record_selector_as_analysis():
    r = good_domain().add(f"_mta-sts.{D}", "TXT", "  v=STSv1; id=77 ")
    d = collect(D, r, [])
    assert has(analyze(d), "MTA-STS", Severity.OK, "id=77")
    assert build_report(d, analyze(d)).summary["mta_sts"]["id"] == "77"


def test_dmarc_missing_message_mentions_org_domain_inheritance():
    r = good_domain()
    r.zone.pop((f"_dmarc.{D}", "TXT"))
    t = pick(run(r), "DMARC")[0].title
    assert "brak rekordu na tej nazwie; polityka może być dziedziczona z domeny organizacyjnej" in t


def test_report_keeps_failed_status_instead_of_not_found():
    r = good_domain().fail(f"default._domainkey.{D}", "TXT").fail(D, "CAA").fail(f"_dmarc.{D}", "TXT", Status.SERVFAIL)
    d = collect(D, r, ["default"])
    rows = dict(summary_rows(build_report(d, analyze(d)).summary))
    assert "nie udało się sprawdzić" in rows["DKIM"] and "nie znaleziono" not in rows["DKIM"]
    assert "nie udało się sprawdzić" in rows["CAA"]
    assert "nie udało się sprawdzić" in rows["DMARC"]
    assert rows["A"] != "nie udało się sprawdzić"
