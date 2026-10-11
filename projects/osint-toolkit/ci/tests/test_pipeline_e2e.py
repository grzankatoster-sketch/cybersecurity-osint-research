"""E2E pipeline'u: rejestry (fixtury) -> adapter -> org-intel (ingest, export) -> entity-graph import-org-intel ->
pliki sprawy (graph.json, audit.jsonl, graph.graphml, report.html, maltego.csv) -> `export --maltego`.

Wylacznie dane syntetyczne (fikcyjne firmy z poprawnymi sumami kontrolnymi i adresy w domenie example.test), zero sieci
(gniazda zablokowane w procesie testu i w kazdym podprocesie CLI, patrz conftest.py). Lancuch uruchamia sie JEDEN raz
na modul (fixture `pipe`); testy regresji pracuja na kopiach sprawy w wlasnych katalogach tymczasowych."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from conftest import FEED_AVAILABLE, FEED_FIXTURES, HIBP_FIXTURES, ROOT, Runner
from entity_graph import cli as eg_cli
from entity_graph.guardrails import AuditLog, verify_audit
from entity_graph.model import Graph

PURPOSE = "due diligence kontrahenta na zlecenie klienta, sprawa 2026/57 (test E2E, dane syntetyczne)"
KRS_A, KRS_B, KRS_C = "0000999001", "0000999002", "0000999003"
PERSON_NAME = "Jan Przykladowy"
PERSON_EMAIL = "jan.przykladowy@example.test"
CATALOG_EMAIL = "poszkodowani@example.test"
GRAPHML = "{http://graphml.graphdrawing.org/xmlns}"
EMAIL_RE = re.compile(r"[\w.+*-]+@[\w-]+(?:\.[\w-]+)+")
UNMASKED_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
CASE_FILES = ("graph.json", "audit.jsonl", "graph.graphml", "report.html", "maltego.csv")

REGISTRY_FILES = (
    "krs_aktualny_0000999001.json",
    "krs_pelny_0000999002_historia_nazw.json",
    "krs_aktualny_0000999002_likwidacja.json",
    "krs_pelny_0000999003_wykreslony.json",
    "gus_regon_777000225.json",
    "ceidg_nip_1234563218.json",
)

# Wlasny format wejsciowy org-intel: osoba z publicznym e-mailem i incydent z e-mailem w opisie (zrodla z proweniencja).
OWN_INPUT = {
    "sources": [
        {
            "key": "www",
            "name": "Odpis z rejestru (syntetyczny): organ reprezentacji",
            "url": f"https://prs.ms.gov.pl/krs/odpis/{KRS_A}",
            "source_type": "official_registry",
            "license": "dane publiczne",
            "retrieved_at": "2026-10-05T10:05:00Z",
            "reliability": "high",
        },
        {
            "key": "cert",
            "name": "Komunikat CERT (syntetyczny)",
            "url": "https://cert.pl/posts/2026/10/demo-wyciek-stealer",
            "source_type": "cert_advisory",
            "license": "CC BY 4.0",
            "retrieved_at": "2026-10-05T10:10:00Z",
            "reliability": "high",
        },
    ],
    "persons": [
        {
            "name": PERSON_NAME,
            "role": "Prezes Zarzadu",
            "organization": KRS_A,
            "public_email": PERSON_EMAIL,
            "sources": ["www"],
            "evidence_quote": f"Prezes Zarzadu: {PERSON_NAME}, {PERSON_EMAIL}",
        }
    ],
    "incidents": [
        {
            "name": "CertIncident",
            "incident_date": "2026-09-20",
            "published_date": "2026-09-25",
            "affected_domain": "example.test",
            "affected_accounts_count": 100,
            "data_classes": ["Email addresses"],
            "status": ["verified"],
            "description": f"Kontakt dla poszkodowanych: {CATALOG_EMAIL}",
            "sources": ["cert"],
        }
    ],
}


# ------------------------------------------------------------------ pomocnicze


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(folder: Path) -> dict[str, str]:
    """Nazwa -> skrot SHA-256 dla wszystkich plikow w katalogu (do dowodu 'bez zmian')."""
    return {p.name: sha(p) for p in sorted(folder.iterdir()) if p.is_file()}


def write_json(path: Path, data) -> Path:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def make_case(folder: Path) -> Path:
    """Sprawa jak w testach entity-graph: graph.json z celem + dziennik audytu z wpisem startowym."""
    folder.mkdir(parents=True)
    Graph({"purpose": PURPOSE}).save(folder / "graph.json")
    AuditLog(folder / "audit.jsonl", "ala").start(PURPOSE, [], {})
    return folder


def import_args(case: Path, source: Path, *extra: object) -> list[str]:
    return ["import-org-intel", "--input", str(source), "--case", str(case), "--operator", "ala", *map(str, extra)]


def load_graph(case: Path) -> Graph:
    return Graph.load(case / "graph.json")


def case_text(case: Path) -> dict[str, str]:
    return {name: (case / name).read_text(encoding="utf-8") for name in CASE_FILES}


class Pipe:
    """Wynik jednorazowego uruchomienia lancucha (sciezki plikow i kody wyjscia kolejnych krokow)."""

    def __init__(self, base: Path):
        self.runner = Runner(base)
        self.base = base
        self.codes: dict[str, int] = {}
        self.out: dict[str, str] = {}

    def step(self, name: str, proc) -> None:
        self.codes[name] = proc.returncode
        self.out[name] = proc.stdout + proc.stderr


def build_registry_inputs(folder: Path) -> list[Path]:
    """Fixtury rejestrow z repo; do wyniku KRS A dopisane claimy o osobach (zarzad, wspolnik, prokurent): adapter
    ma je pominac, nie przeniesc."""
    folder.mkdir(parents=True)
    paths = []
    for name in REGISTRY_FILES:
        data = json.loads((FEED_FIXTURES / name).read_text(encoding="utf-8"))
        if name == "krs_aktualny_0000999001.json":
            for predicate, value in (
                ("krs.zarzad_czlonek", f"{PERSON_NAME}, Prezes Zarzadu"),
                ("krs.wspolnik", "Anna Wymyslona 51%"),
                ("krs.prokurent", "Piotr Zmyslony"),
            ):
                extra = copy.deepcopy(data["claims"][0])
                extra.update(predicate=predicate, original_value=value, normalized_value=value, locator="$.x")
                data["claims"].append(extra)
        paths.append(write_json(folder / name, data))
    return paths


@pytest.fixture(scope="module")
def pipe(tmp_path_factory) -> Pipe:
    if not FEED_AVAILABLE:
        pytest.skip("osint-poland registry adapter is not part of the public repository")
    base = tmp_path_factory.mktemp("pipeline")
    p = Pipe(base)
    r = p.runner
    inputs = build_registry_inputs(base / "registry")

    # 1. adapter: wyniki konektorow rejestrow -> plik wejsciowy org-intel (nowy plik, --strict)
    feed_args: list[object] = []
    for path in inputs:
        feed_args += ["--input", path]
    p.feed = base / "feed.json"
    p.feed_report = base / "feed_report.json"
    p.step(
        "adapter",
        r.feed(*feed_args, "--out", p.feed, "--report", p.feed_report, "--include-sole-proprietors", "--strict"),
    )

    # 2. org-intel ingest: wynik adaptera, wlasny format (osoba + e-mail), katalog HIBP (z e-mailem w opisie)
    p.store = base / "data" / "store.json"
    own = write_json(base / "own_format.json", OWN_INPUT)
    catalog = json.loads((HIBP_FIXTURES / "hibp_api.json").read_text(encoding="utf-8"))
    catalog[0]["Description"] += f" Kontakt: {CATALOG_EMAIL}"
    p.catalog = write_json(base / "hibp_api_email.json", catalog)
    monitor = HIBP_FIXTURES / "hibp_monitor.json"
    for name, src in (
        ("ingest_feed", p.feed),
        ("ingest_own", own),
        ("ingest_catalog", p.catalog),
        ("ingest_monitor", monitor),
    ):
        p.step(name, r.org_intel("ingest", src, "--store", p.store))

    # 3. org-intel export (e-maile domyslnie maskowane; drugi eksport z pelnymi adresami: wejscie "najgorszego" przypadku)
    p.export = base / "export.json"
    p.export_full = base / "export_full.json"
    p.step("export", r.org_intel("export", "--format", "json", "--out", p.export, "--store", p.store))
    p.step(
        "export_full",
        r.org_intel("export", "--format", "json", "--include-emails", "--out", p.export_full, "--store", p.store),
    )

    # 4. sprawa + entity-graph import-org-intel --strict (--report poza katalogiem sprawy)
    p.case = make_case(base / "sprawa")
    p.import_report = base / "import_report.json"
    p.step(
        "import",
        r.eg(*import_args(p.case, p.export, "--strict", "--report", p.import_report)),
    )

    # 5. eksport Maltego z gotowego graph.json
    p.maltego = base / "maltego_export.csv"
    p.step("export_maltego", r.eg("export", p.case / "graph.json", "--maltego", p.maltego))
    return p


# ------------------------------------------------------------------ 1. lancuch end-to-end


def test_pipeline_every_step_succeeds(pipe):
    failed = {k: (c, pipe.out[k][-400:]) for k, c in pipe.codes.items() if c != 0}
    assert not failed, failed
    assert list(pipe.codes) == [
        "adapter",
        "ingest_feed",
        "ingest_own",
        "ingest_catalog",
        "ingest_monitor",
        "export",
        "export_full",
        "import",
        "export_maltego",
    ]


def test_pipeline_made_no_network_attempts(pipe):
    assert pipe.runner.attempts() == []


def test_adapter_output_is_org_intel_input_without_people(pipe):
    feed = json.loads(pipe.feed.read_text(encoding="utf-8"))
    assert len(feed["organizations"]) == 5 and "persons" not in feed
    blob = json.dumps(feed, ensure_ascii=False)
    assert not any(n in blob for n in (PERSON_NAME, "Wymyslona", "Zmyslony", "Prywatna"))
    report = json.loads(pipe.feed_report.read_text(encoding="utf-8"))
    assert report["counts"]["skipped_person_claims"] == 3


def test_org_intel_export_has_registry_and_catalog_records_with_sources(pipe):
    data = json.loads(pipe.export.read_text(encoding="utf-8"))
    by_krs = {o["krs"]: o for o in data["organizations"] if o.get("krs")}
    assert {KRS_A, KRS_B, KRS_C} <= set(by_krs)
    assert by_krs[KRS_A]["status"] == "aktywna" and by_krs[KRS_B]["status"] == "w_likwidacji"
    assert len(data["incidents"]) >= 4
    source_ids = {s["id"] for s in data["sources"]}
    assert source_ids and all(s["url"].startswith("https://") and s["retrieved_at"] for s in data["sources"])
    for record in (*data["organizations"], *data["incidents"]):
        assert record["source_ids"] and set(record["source_ids"]) <= source_ids  # kazdy rekord ma zrodlo


def test_case_has_all_files_and_verified_audit_chain(pipe):
    for name in CASE_FILES:
        assert (pipe.case / name).is_file(), name
    ok, msg = verify_audit(pipe.case / "audit.jsonl")
    assert ok, msg
    events = [json.loads(line) for line in (pipe.case / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [e.get("event") for e in events if e.get("event") == "org_intel_import"] == ["org_intel_import"] * 2
    ET.parse(pipe.case / "graph.graphml")  # poprawny XML
    assert "<html" in (pipe.case / "report.html").read_text(encoding="utf-8").lower()


def test_graph_contains_registry_companies_and_incidents_with_provenance(pipe):
    g = load_graph(pipe.case)
    companies = {n.attrs["krs"]: n for n in g.nodes.values() if n.attrs.get("kind") == "company" and n.attrs.get("krs")}
    assert {KRS_A, KRS_B, KRS_C} <= set(companies)
    assert companies[KRS_C].attrs["status"] == "wykreslona" and "registered_address" not in companies[KRS_C].attrs
    breaches = [n for n in g.nodes.values() if n.attrs.get("kind") == "breach"]
    assert breaches
    for node in (*companies.values(), *breaches):
        prov = node.attrs.get("provenance")
        assert prov and all(str(p.get("source_url_original", "")).startswith("https://") for p in prov), node.id
        assert all(p.get("retrieved_at") and p.get("source_type") for p in prov), node.id


def test_maltego_export_matches_the_case_file_and_keeps_provenance(pipe):
    exported = pipe.maltego.read_text(encoding="utf-8")
    assert exported.splitlines() == (pipe.case / "maltego.csv").read_text(encoding="utf-8").splitlines()
    assert "maltego.Organization" in exported and exported.count("\n") > 5


def test_report_has_no_personal_data(pipe):
    report = json.loads(pipe.import_report.read_text(encoding="utf-8"))
    assert report["refused"] is False and report["rejected_records"] == 0 and report["strict"] is True
    assert report["skipped_people"] >= 1
    assert not EMAIL_RE.search(json.dumps(report, ensure_ascii=False))
    assert PERSON_NAME not in json.dumps(report, ensure_ascii=False)


# ------------------------------------------------------------------ 2. osoby i e-maile nie trafiaja do grafu


def assert_only_masked_emails(name: str, text: str) -> None:
    """Zadnych adresow e-mail, takze czesciowo zamaskowanych przez org-intel (`p***@example.test`): importer
    entity-graph zastepuje je w calosci znacznikiem, wiec w plikach sprawy nie ma zadnego adresu (EMAIL_RE obejmuje
    tez lokalna czesc z `*`; samo `@`, np. CSS `@media` w report.html, nie jest adresem)."""
    assert not UNMASKED_EMAIL_RE.search(text), f"{name}: pelny adres e-mail"
    assert not EMAIL_RE.search(text), f"{name}: adres e-mail (takze zamaskowany) w pliku sprawy"
    assert PERSON_EMAIL not in text and CATALOG_EMAIL not in text, name


def _assert_no_people_or_emails(case: Path) -> None:
    g = load_graph(case)
    types = {n.type.value for n in g.nodes.values()}
    assert not types & {"person", "email"}, types
    for name, text in case_text(case).items():
        assert_only_masked_emails(name, text)
        assert PERSON_NAME not in text and "Anna Wymyslona" not in text and "Piotr Zmyslony" not in text, name
    assert_only_masked_emails("kropki.svg", (case / "kropki.svg").read_text(encoding="utf-8"))


def test_people_and_emails_never_reach_the_case_files(pipe):
    _assert_no_people_or_emails(pipe.case)
    assert "@" not in pipe.maltego.read_text(encoding="utf-8")  # CSV dla Maltego: zadnych adresow, nawet zamaskowanych


def test_people_and_full_emails_in_export_are_skipped_not_imported(pipe, runner, tmp_path):
    """Najgorszy przypadek: eksport z --include-emails (pelny adres osoby) -> importer pomija osobe i adres."""
    assert PERSON_EMAIL in pipe.export_full.read_text(encoding="utf-8")  # wejscie faktycznie zawiera pelny e-mail
    case = make_case(tmp_path / "sprawa_full")
    proc = runner.eg(*import_args(case, pipe.export_full, "--strict", "--json"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    rep = json.loads(proc.stdout)
    assert rep["skipped_people"] >= 1 and rep["rejected_records"] == 0
    assert PERSON_EMAIL not in proc.stdout and not EMAIL_RE.search(proc.stdout)
    _assert_no_people_or_emails(case)


# ------------------------------------------------------------------ 3. ponowny import jest idempotentny


def test_second_import_is_idempotent_and_leaves_graph_files_byte_identical(pipe, runner, tmp_path):
    case = make_case(tmp_path / "sprawa")
    first = runner.eg(*import_args(case, pipe.export, "--strict", "--json"))
    assert first.returncode == 0, first.stdout + first.stderr
    before = snapshot(case)
    second = runner.eg(*import_args(case, pipe.export, "--strict", "--json"))
    assert second.returncode == 0, second.stdout + second.stderr
    rep = json.loads(second.stdout)
    assert rep["nodes_created"] == 0 and rep["edges_created"] == 0
    after = snapshot(case)
    for name in ("graph.json", "graph.graphml", "maltego.csv", "report.html", "kropki.svg"):
        assert after[name] == before[name], name
    assert verify_audit(case / "audit.jsonl")[0]


# ------------------------------------------------------------------ 4. --report nie ruszy plikow sprawy


@pytest.mark.parametrize("target", ["graph.json", "audit.jsonl", "maltego.csv", "graph.graphml", "report.html"])
def test_report_pointing_at_a_case_file_is_refused_and_case_stays_byte_identical(pipe, tmp_path, target, capsys):
    case = tmp_path / "sprawa"
    shutil.copytree(pipe.case, case)
    before = snapshot(case)
    code = eg_cli.main(import_args(case, pipe.export, "--report", case / target))
    assert code == 2, capsys.readouterr()
    assert snapshot(case) == before  # zadnego pliku sprawy nie zmieniono, nic nie dopisano
    assert sorted(p.name for p in case.iterdir()) == sorted(before)
    ok, msg = verify_audit(case / "audit.jsonl")
    assert ok, msg
    assert "zastrzeżona" in capsys.readouterr().err


def test_report_on_graph_json_in_a_fresh_case_refuses_before_any_change(pipe, tmp_path, capsys):
    case = make_case(tmp_path / "sprawa")
    before = snapshot(case)
    assert eg_cli.main(import_args(case, pipe.export, "--report", case / "graph.json")) == 2
    assert snapshot(case) == before and verify_audit(case / "audit.jsonl")[0]
    capsys.readouterr()


def test_report_path_via_dotdot_in_case_dir_is_refused(pipe, tmp_path, capsys):
    case = make_case(tmp_path / "sprawa")
    before = snapshot(case)
    sneaky = tmp_path / "inny" / ".." / "sprawa" / "audit.jsonl"
    (tmp_path / "inny").mkdir()
    assert eg_cli.main(import_args(case, pipe.export, "--report", sneaky)) == 2
    assert snapshot(case) == before
    capsys.readouterr()


# ------------------------------------------------------------------ 5. --dry-run nie zapisuje zmian


def test_dry_run_writes_nothing_to_the_case(pipe, runner, tmp_path):
    case = make_case(tmp_path / "sprawa")
    before = snapshot(case)
    proc = runner.eg(*import_args(case, pipe.export, "--dry-run", "--strict", "--json"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    rep = json.loads(proc.stdout)
    assert rep["dry_run"] is True and rep["nodes_created"] > 0  # raport pokazuje, co BY sie stalo
    assert snapshot(case) == before  # bajtowo: graph.json, audit.jsonl; nie powstal zaden nowy plik
    assert verify_audit(case / "audit.jsonl")[0]
    again = runner.eg(*import_args(case, pipe.export, "--strict", "--json"))  # po dry-runie import dziala normalnie
    assert again.returncode == 0 and json.loads(again.stdout)["nodes_created"] == rep["nodes_created"]


def test_dry_run_with_report_writes_only_the_report(pipe, runner, tmp_path):
    case = make_case(tmp_path / "sprawa")
    before = snapshot(case)
    report = tmp_path / "raport_dry.json"
    proc = runner.eg(*import_args(case, pipe.export, "--dry-run", "--report", report))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert snapshot(case) == before
    assert json.loads(report.read_text(encoding="utf-8"))["dry_run"] is True


# ------------------------------------------------------------------ 6. cudzy plik tymczasowy raportu


def test_foreign_temp_file_of_report_is_refused_and_left_untouched(pipe, tmp_path, capsys):
    """Plik `.{raport}.{pid}.tmp` istnieje przed uruchomieniem (pid = proces testu, bo import idzie w procesie)."""
    case = make_case(tmp_path / "sprawa")
    before = snapshot(case)
    out = tmp_path / "raporty"
    out.mkdir()
    report = out / "raport.json"
    foreign = out / f".raport.json.{os.getpid()}.tmp"
    foreign.write_text("cudzy plik: nie wolno go usunac ani nadpisac", encoding="utf-8")
    code = eg_cli.main(import_args(case, pipe.export, "--dry-run", "--report", report))
    assert code == 2
    assert foreign.read_text(encoding="utf-8") == "cudzy plik: nie wolno go usunac ani nadpisac"
    assert not report.exists() and sorted(p.name for p in out.iterdir()) == [foreign.name]
    assert snapshot(case) == before  # --dry-run: sprawa nietknieta
    assert "plik tymczasowy" in capsys.readouterr().err


# ------------------------------------------------------------------ 7. importer samodzielny, bez eksportu Maltego

_STANDALONE = (
    "import sys\n"
    "from entity_graph import sprawa\n"
    "sprawa.CASE_FILES = frozenset(sprawa.CASE_FILES - {'maltego.csv'})  # wersja sprawy bez eksportu Maltego\n"
    "from entity_graph import cli\n"
    "case, source, report = sys.argv[1:4]\n"
    "dry = cli.main(['import-org-intel', '--input', source, '--case', case, '--operator', 'ala', '--dry-run',\n"
    "                '--strict', '--report', report])\n"
    "refused = cli.main(['import-org-intel', '--input', source, '--case', case, '--operator', 'ala',\n"
    "                    '--report', case + '/maltego.csv'])\n"
    "real = cli.main(['import-org-intel', '--input', source, '--case', case, '--operator', 'ala', '--strict'])\n"
    "print('CODES', dry, refused, real)\n"
)


def test_importer_works_when_case_files_do_not_list_maltego_csv(pipe, runner, tmp_path):
    """Importer nie zalezy od eksportu Maltego: dry-run i import dzialaja przy sprawa.CASE_FILES bez maltego.csv, a
    nazwa maltego.csv pozostaje zastrzezona dla --report niezaleznie od wersji CASE_FILES."""
    case = make_case(tmp_path / "sprawa")
    proc = runner.run_code(_STANDALONE, case, pipe.export, tmp_path / "dry.json")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "CODES 0 2 0" in proc.stdout
    assert json.loads((tmp_path / "dry.json").read_text(encoding="utf-8"))["dry_run"] is True


def test_importer_module_does_not_import_export_or_maltego_code():
    import ast

    source = (ROOT / "entity-graph" / "src" / "entity_graph" / "importers" / "org_intel.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported += [f"{'.' * node.level}{node.module or ''}:{a.name}" for a in node.names]
        elif isinstance(node, ast.Import):
            imported += [a.name for a in node.names]
    assert not [i for i in imported if "export" in i or "maltego" in i.lower() or "sprawa" in i], imported
    assert "to_maltego_csv" not in source


# ------------------------------------------------------------------ 8. brak proxy blokuje wymagane wyszukiwanie

# Nieprawdziwy klucz o poprawnym formacie; nigdy nie opuszcza testu.
BRAVE_KEY = "synthetic-test-key-0123456789"  # gitleaks:allow


def test_required_proxy_missing_blocks_search_with_zero_connections(runner, tmp_path):
    """BRAVE_REQUIRE_PROXY=1 bez BRAVE_PROXY: odmowa (kod 3), zero polaczen (dziennik podprocesu), sprawa bez zmian."""
    case = make_case(tmp_path / "sprawa")
    empty_cfg = tmp_path / "brave.env"
    empty_cfg.write_text("", encoding="utf-8")  # izolacja od prawdziwego pliku konfiguracji operatora
    before = snapshot(case)
    proc = runner.eg(
        "szukaj-profili",
        case,
        "--person",
        "Jan Testowy",
        "--dodaj",
        "--operator",
        "ala",
        env={"BRAVE_SEARCH_API_KEY": BRAVE_KEY, "BRAVE_REQUIRE_PROXY": "1", "BRAVE_SEARCH_ENV_FILE": str(empty_cfg)},
    )
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "BRAVE_REQUIRE_PROXY" in proc.stderr and "bez połączenia bezpośredniego" in proc.stderr
    assert BRAVE_KEY not in proc.stdout + proc.stderr
    assert runner.attempts() == []
    assert snapshot(case) == before


def test_required_proxy_missing_never_calls_the_http_client(monkeypatch, tmp_path, capsys):
    """To samo w procesie, z atrapa klienta HTTP: zero wywolan, sprawa bez zmian."""
    calls: list[tuple] = []

    class FakeHttp:
        def __getattr__(self, name):
            def record(*args, **kwargs):
                calls.append((name, args, kwargs))
                raise AssertionError("klient HTTP nie moze byc wolany bez wymaganego proxy")

            return record

    empty_cfg = tmp_path / "brave.env"
    empty_cfg.write_text("", encoding="utf-8")
    for key in ("BRAVE_PROXY", "OSINT_PROXY"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("BRAVE_SEARCH_API_KEY", BRAVE_KEY)
    monkeypatch.setenv("BRAVE_REQUIRE_PROXY", "1")
    monkeypatch.setenv("BRAVE_SEARCH_ENV_FILE", str(empty_cfg))
    monkeypatch.setattr(eg_cli, "PROFILE_HTTP", FakeHttp())
    case = make_case(tmp_path / "sprawa")
    before = snapshot(case)
    argv = ["szukaj-profili", str(case), "--person", "Jan Testowy", "--dodaj", "--operator", "ala"]
    assert eg_cli.main(argv) == eg_cli.EXIT_CONFIG
    assert calls == [] and snapshot(case) == before
    assert BRAVE_KEY not in capsys.readouterr().err


# ------------------------------------------------------------------ 9. zrodla bez proweniencji sa odrzucane


def test_org_intel_rejects_record_without_source_and_keeps_the_rest(runner, tmp_path):
    doc = copy.deepcopy(OWN_INPUT)
    doc["organizations"] = [
        {"legal_name": "Dobra Firma Testowa Sp. z o.o.", "krs": "0000999041", "sources": ["www"]},
        {"legal_name": "Firma Bez Zrodla Sp. z o.o.", "krs": "0000999042", "sources": []},
        {"legal_name": "Firma Z Obcym Zrodlem Sp. z o.o.", "krs": "0000999043", "sources": ["nie-ma-takiego"]},
    ]
    doc.pop("persons")
    path = write_json(tmp_path / "wejscie.json", doc)
    store = tmp_path / "store.json"
    proc = runner.org_intel("ingest", path, "--store", store)
    assert proc.returncode == 4, proc.stdout + proc.stderr  # EXIT_PARTIAL: czesc rekordow odrzucona
    assert "ODRZUCONO" in proc.stdout and "Firma Bez Zrodla" in proc.stdout
    saved = json.loads(store.read_text(encoding="utf-8"))
    names = (
        " ".join(o["legal_name"] for o in saved["organizations"].values())
        if isinstance(saved["organizations"], dict)
        else " ".join(o["legal_name"] for o in saved["organizations"])
    )
    assert "Dobra Firma" in names and "Bez Zrodla" not in names and "Obcym Zrodlem" not in names


def _export_without_incident_sources(pipe: Pipe, tmp_path: Path) -> Path:
    data = json.loads(pipe.export.read_text(encoding="utf-8"))
    data["incidents"][0]["source_ids"] = []
    return write_json(tmp_path / "export_bez_zrodla.json", data)


def test_importer_rejects_record_without_sources_with_exit_4_and_imports_the_rest(pipe, runner, tmp_path):
    case = make_case(tmp_path / "sprawa")
    bad = _export_without_incident_sources(pipe, tmp_path)
    proc = runner.eg(*import_args(case, bad, "--json"))
    assert proc.returncode == 4, proc.stdout + proc.stderr
    rep = json.loads(proc.stdout)
    assert rep["rejected_records"] == 1 and "brak źródła" in rep["rejections"][0]["reason"]
    assert rep["nodes_created"] > 0
    assert verify_audit(case / "audit.jsonl")[0]


def test_importer_strict_refuses_record_without_sources_with_exit_5_and_changes_nothing(pipe, runner, tmp_path):
    case = make_case(tmp_path / "sprawa")
    before = snapshot(case)
    bad = _export_without_incident_sources(pipe, tmp_path)
    proc = runner.eg(*import_args(case, bad, "--strict", "--json"))
    assert proc.returncode == 5, proc.stdout + proc.stderr
    rep = json.loads(proc.stdout)
    assert rep["refused"] is True and rep["rejected_records"] == 1
    assert snapshot(case) == before  # --strict: odmowa przed jakimkolwiek zapisem, takze dziennika


def test_importer_rejects_org_intel_input_format_without_running_ingest(pipe, runner, tmp_path):
    """Plik wejsciowy adaptera (bez `ingest` i `export`) nie jest eksportem org-intel: kod 2, sprawa bez zmian."""
    case = make_case(tmp_path / "sprawa")
    before = snapshot(case)
    proc = runner.eg(*import_args(case, pipe.feed, "--strict"))
    assert proc.returncode == 2 and "org-intel ingest" in proc.stderr
    assert snapshot(case) == before


# ------------------------------------------------------------------ 10. wlasnosci samego srodowiska testowego


def test_subprocess_network_guard_logs_and_blocks_connection_attempts(runner):
    code = (
        "import socket\n"
        "try:\n"
        "    socket.create_connection(('203.0.113.7', 80), timeout=1)\n"
        "except OSError as exc:\n"
        "    print('BLOCKED', exc)\n"
    )
    proc = runner.run_code(code)
    assert "BLOCKED" in proc.stdout and runner.attempts()
    runner.netlog.unlink()  # proba byla zamierzona: czyscimy dziennik, zeby nie zawiodla kontrola konca testu


def test_in_process_network_is_blocked():
    import socket

    with pytest.raises(AssertionError, match="sieci"):
        socket.create_connection(("203.0.113.7", 80), timeout=1)
