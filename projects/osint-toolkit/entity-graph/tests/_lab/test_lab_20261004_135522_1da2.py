"""Specyfikacja: email_classify - offline klasyfikacja e-maila (rola, domena jednorazowa, alias plus)."""
import json

from entity_graph.engine import Options, investigate, new_graph
from entity_graph.guardrails import AuditLog, verify_audit
from entity_graph.model import Node, Status
from entity_graph.normalize import EntityType as T
from entity_graph.transforms import REGISTRY

EML = lambda v: Node.make(T.EMAIL, v)  # noqa: E731


class CountingFetcher:
    """Fetcher, ktory liczy wywolania i od razu je zglasza - transformacja offline nie moze go uzyc."""

    def __init__(self):
        self.count = 0

    def get(self, url, headers=None):
        self.count += 1
        raise AssertionError(f"niespodziewane zapytanie sieciowe: {url}")


def classify(make_ctx, address):
    ctx = make_ctx()
    counter = CountingFetcher()
    ctx.fetch = counter
    r = REGISTRY["email_classify"].run(EML(address), ctx)
    assert counter.count == 0
    assert ctx.runner.calls == []
    return r


def test_registered_as_offline_email_transform():
    t = REGISTRY["email_classify"]
    assert t.inputs == (T.EMAIL,)
    assert t.network is False


def test_builtin_lists_are_frozensets_with_expected_entries():
    from entity_graph.transforms.email import DISPOSABLE_DOMAINS, ROLE_LOCALPARTS
    assert isinstance(ROLE_LOCALPARTS, frozenset) and isinstance(DISPOSABLE_DOMAINS, frozenset)
    for p in ("admin", "administrator", "info", "kontakt", "contact", "abuse", "noreply", "no-reply",
              "postmaster", "hostmaster", "webmaster", "support", "sales", "biuro", "office", "security", "hr"):
        assert p in ROLE_LOCALPARTS, p
    for d in ("mailinator.com", "10minutemail.com", "guerrillamail.com", "yopmail.com", "temp-mail.org",
              "trashmail.com", "sharklasers.com", "dispostable.com"):
        assert d in DISPOSABLE_DOMAINS, d


def test_plain_personal_address_all_false_no_nodes(make_ctx):
    r = classify(make_ctx, "jan.kowalski@example.com")
    assert r.status is Status.FOUND
    assert r.node_attrs == {"role_account": False, "disposable": False,
                            "base_address": "jan.kowalski@example.com"}
    assert r.nodes == [] and r.edges == []


def test_role_account_exact_local_part(make_ctx):
    for addr in ("admin@firma.pl", "Kontakt@Firma.pl", "abuse@firma.pl", "noreply@firma.pl", "no-reply@firma.pl"):
        r = classify(make_ctx, addr)
        assert r.status is Status.FOUND
        assert r.node_attrs["role_account"] is True, addr
        assert r.node_attrs["disposable"] is False
        assert r.nodes == [] and r.edges == []
    # tylko dokladne dopasowanie lokalnej czesci, nie podciag
    assert classify(make_ctx, "jan.admin@firma.pl").node_attrs["role_account"] is False
    assert classify(make_ctx, "administratorka@firma.pl").node_attrs["role_account"] is False


def test_disposable_domain_exact(make_ctx):
    r = classify(make_ctx, "xyz123@mailinator.com")
    assert r.status is Status.FOUND
    assert r.node_attrs["disposable"] is True and r.node_attrs["role_account"] is False
    assert r.node_attrs["base_address"] == "xyz123@mailinator.com"
    assert classify(make_ctx, "x@YOPmail.com").node_attrs["disposable"] is True
    assert classify(make_ctx, "x@example.com").node_attrs["disposable"] is False
    assert classify(make_ctx, "x@gmail.com").node_attrs["disposable"] is False


def test_plus_alias_creates_base_node_and_alias_of_edge(make_ctx):
    node = EML("jan+sklep@example.com")
    r = classify(make_ctx, "jan+sklep@example.com")
    assert r.status is Status.FOUND
    assert r.node_attrs["base_address"] == "jan@example.com"
    assert r.node_attrs["role_account"] is False and r.node_attrs["disposable"] is False
    [base] = r.nodes
    assert base.type is T.EMAIL and base.key == "jan@example.com"
    assert "email_classify" in base.sources
    [edge] = r.edges
    assert edge.src == node.id and edge.dst == base.id
    assert edge.relation == "alias_of" and edge.source == "email_classify"
    assert edge.confidence == 0.9
    assert "plus_addressing" in edge.evidence


def test_plus_alias_split_on_first_plus_and_role_from_base(make_ctx):
    r = classify(make_ctx, "admin+a+b@firma.pl")
    assert r.node_attrs["base_address"] == "admin@firma.pl"
    assert r.node_attrs["role_account"] is True
    assert [n.key for n in r.nodes] == ["admin@firma.pl"]
    # pusty tag tez jest aliasem adresu bazowego
    r = classify(make_ctx, "jan+@example.com")
    assert r.node_attrs["base_address"] == "jan@example.com"
    assert [e.relation for e in r.edges] == ["alias_of"]


def test_plus_alias_on_disposable_domain_keeps_flag(make_ctx):
    r = classify(make_ctx, "ola+test@mailinator.com")
    assert r.node_attrs == {"role_account": False, "disposable": True, "base_address": "ola@mailinator.com"}
    assert [n.key for n in r.nodes] == ["ola@mailinator.com"]


def test_leading_plus_is_not_alias(make_ctx):
    r = classify(make_ctx, "+tag@example.com")
    assert r.status is Status.FOUND
    assert r.node_attrs["base_address"] == "+tag@example.com"
    assert r.nodes == [] and r.edges == []


def test_engine_offline_runs_classify_and_records_alias(make_ctx, tmp_path):
    ctx = make_ctx()
    counter = CountingFetcher()
    ctx.fetch = counter
    audit = AuditLog(tmp_path / "audit.jsonl", "ala")
    audit.start("audyt własnej firmy X", [], {})
    g = new_graph("audyt własnej firmy X", "ala", "", [], {}, "2026-10-04")
    investigate(g, [EML("admin+faktury@mailinator.com")], ctx, audit, Options(offline=True))
    assert counter.count == 0 and ctx.runner.calls == []
    runs = {(r.transform, r.node_id): r.status for r in g.runs}
    assert runs[("email_classify", "email:admin+faktury@mailinator.com")] is Status.FOUND
    seed = g.nodes["email:admin+faktury@mailinator.com"]
    assert seed.attrs["role_account"] is True and seed.attrs["disposable"] is True
    assert seed.attrs["base_address"] == "admin@mailinator.com"
    assert "email:admin@mailinator.com" in g.nodes
    alias = [e for e in g.edges.values() if e.relation == "alias_of"]
    assert len(alias) == 1
    assert alias[0].src == "email:admin+faktury@mailinator.com" and alias[0].dst == "email:admin@mailinator.com"
    ok_, msg = verify_audit(audit.path)
    assert ok_, msg
    events = [json.loads(l) for l in audit.path.read_text(encoding="utf-8").splitlines()]
    assert any(ev.get("event") == "transform" and ev.get("transform") == "email_classify"
               and ev.get("status") == "FOUND" for ev in events)


def test_engine_only_email_classify(make_ctx, tmp_path):
    ctx = make_ctx()
    audit = AuditLog(tmp_path / "audit.jsonl", "ala")
    audit.start("audyt własnej firmy X", [], {})
    g = new_graph("audyt własnej firmy X", "ala", "", [], {}, "2026-10-04")
    investigate(g, [EML("jan@example.com")], ctx, audit, Options(only=frozenset({"email_classify"})))
    assert [r.transform for r in g.runs] == ["email_classify"]
    assert ctx.fetch.calls == []
    assert g.nodes["email:jan@example.com"].attrs["base_address"] == "jan@example.com"
    assert not [e for e in g.edges.values() if e.relation == "alias_of"]
