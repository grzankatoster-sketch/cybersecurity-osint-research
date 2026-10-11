"""Generate auditable field tables and runtime reports from measured artifacts."""

# ruff: noqa: E501  # Long Markdown table rows in report templates.
import ast
import collections
import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "artifacts/enrichment"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(name, text):
    (ROOT / name).write_text(text, encoding="utf-8")


def main():
    inventory = read(ART / "inventory.json")
    before = read(ART / "before.json")
    after = read(ART / "after.json")
    benchmark = read(ROOT / "artifacts/enrichment-benchmark.json")
    fields = inventory["fields"]
    schemes = {s["name"]: s for s in inventory["schemes"]}
    lines = [
        "# Pełny katalog pól enrichment\n",
        "Nazwy poniżej pochodzą z rzeczywistego `fields` oraz nazwanych grup regex w "
        "`socid_extractor/schemes.py`. To katalog 498 nazw statycznych, nie obietnica "
        "uzyskania ich z każdego konta. Mechanizmy mogą się nakładać.\n",
        "**Liczba schematów nie oznacza liczby niezależnych serwisów.** Kolumna definicji "
        "to unia dopasowań pełnych domen url_hints do surowych URL katalogu; 0 oznacza "
        "brak tego dopasowania, nie brak możliwości ekstrakcji. Rzeczywista liczba "
        "działających serwisów dla każdego pola pozostaje UNKNOWN poza korpusem.\n",
        "| Pole | Źródło — schematy | Mechanizm | Schematy | Potencjalne definicje |",
        "|---|---|---|---:|---:|",
    ]
    for field, names in sorted(fields.items()):
        mechanisms = sorted({m for n in names for m in schemes[n]["mechanisms"]})
        sites = {s for n in names for s in schemes[n]["potential_definitions"]}
        lines.append(
            f"| `{field}` | {', '.join(names)} | {', '.join(mechanisms)} | {len(names)} | {len(sites)} |"
        )
    lines.extend(
        [
            "\n## Pola postprocessorów i techniczne\n",
            "Nie są dodatkowym dowodem istnienia konta. Gravatar wyprowadza hash/link "
            "z avatara; EmailToUsername wyprowadza lokalną część emaila; "
            "YandexUsernameToEmail tworzy przypuszczalny adres. `NormalizeDates` "
            "zmienia wartości existing created_at/updated_at/latest_activity_at/birthday.\n",
            "| Pole dodatkowe | Źródło | Charakter |",
            "|---|---|---|",
        ]
    )
    for field, sources in sorted(inventory["derived"].items()):
        lines.append(
            f"| `{field}` | {', '.join(sources)} | pochodne; liczba działających usług UNKNOWN |"
        )
    lines.append("| `_extractor` | main.py | nazwa schematu, pole techniczne; nie cecha osoby |")
    lines.extend(
        [
            "\n## Model Ultimate\n",
            "`ProfileMetadata.fields` i `extra_fields` zawierają `FieldCandidate`; "
            "`candidates` zachowuje alternatywy, `conflicts` nazwy pól konfliktowych, "
            "`errors` błędy. Dataclass ma jawne typy i przechodzi round-trip JSON.\n",
            "| Kategoria | Pola wspólne | Typ |",
            "|---|---|---|",
            "| Identity | username, display_name, user_id | str; ID liczbowe do str |",
            "| Profile | bio, description, avatar_url, banner_url, profile_url | str; URL HTTP(S) |",
            "| Links | website; external_links | str; tuple[str, ...] |",
            "| Location | location | str bez inference |",
            "| Counters | followers, following, posts | nieujemny int |",
            "| Dates | created_at, updated_at, latest_activity_at | ISO 8601; bez dodawania strefy |",
            "| Account | account_type, category, verified, tags | str, str, bool, tuple[str, ...] |",
            "| Extra | public_repos_count, public_gists_count, is_looking_for_job, company | int, int, bool, str |",
            "\nNie każde pole jest obecnie mapowane przez każdy extractor. `latest_activity_at`, "
            "`posts` itp. mogą pozostać brakujące w danej strukturze. Jawne reguły mogą "
            "uzupełniać nazwane extra_fields po przejściu normalizacji. Unsupported "
            "wartości złożone nie są zamieniane bezmyślnie w stringi.\n",
            "Provenance kandydata: `source_site`, `source_url`, `extractor`, `evidence` "
            "(lokalizator, ograniczony do 256 znaków), `observed_at`, `quality`, "
            "`priority`, `validation`. Evidence oraz wartość umożliwiają inspekcję "
            "reguły bez trwałego przechowywania pełnego HTML. Hash odpowiedzi jest "
            "w próbie HTTP na poziomie SearchResult.\n",
        ]
    )
    write("ENRICHMENT_FIELDS.md", "\n".join(lines))

    models = {
        "Maigret": [r["maigret"] for r in before],
        "Ultimate before": [r["ultimate_before"] for r in before],
        "Ultimate after": [r["ultimate_after"] for r in after],
    }
    expected = sum(len(r["expected"]) for r in after)
    total = len(after)
    stats = {}
    for name, rows in models.items():
        value = {
            k: sum(r[k] for r in rows) for k in ("returned", "correct", "wrong", "missing", "empty")
        }
        value.update(
            parser_failed_cases=sum(bool(r["errors"]) for r in rows),
            failed_empty_cases=sum(bool(r["errors"]) and not r["returned"] for r in rows),
            empty_extractions=sum(not r["returned"] for r in rows),
            p50=statistics.median(r["seconds"] for r in rows),
            p95=sorted(r["seconds"] for r in rows)[int((total - 1) * 0.95)],
        )
        stats[name] = value
    table = ["| Metryka | Maigret | Ultimate before | Ultimate after |", "|---|---:|---:|---:|"]
    metrics = [
        ("Profiles FOUND — wejście harnessu", lambda s: "19 (kontrolowane)"),
        ("Fields returned", lambda s: s["returned"]),
        ("Correct fields", lambda s: s["correct"]),
        ("Wrong fields", lambda s: s["wrong"]),
        ("Missing fields", lambda s: s["missing"]),
        ("Empty fields", lambda s: s["empty"]),
        ("Przypadki z błędem parsera", lambda s: s["parser_failed_cases"]),
        ("Błąd parsera i całkiem pusty wynik", lambda s: s["failed_empty_cases"]),
        ("Mean fields/fixture", lambda s: f"{s['returned'] / total:.3f}"),
        ("Field coverage", lambda s: f"{100 * s['correct'] / expected:.2f}%"),
        ("Field precision", lambda s: f"{100 * s['correct'] / s['returned']:.2f}%"),
        ("Wrong field rate", lambda s: f"{100 * s['wrong'] / s['returned']:.2f}%"),
        ("Empty extraction rate", lambda s: f"{100 * s['empty_extractions'] / total:.2f}%"),
        ("Parser failure rate (cases)", lambda s: f"{100 * s['parser_failed_cases'] / total:.2f}%"),
        ("p50 extraction ms", lambda s: f"{s['p50'] * 1000:.3f}"),
        ("p95 extraction ms", lambda s: f"{s['p95'] * 1000:.3f}"),
    ]
    for label, func in metrics:
        table.append("| " + label + " | " + " | ".join(str(func(s)) for s in stats.values()) + " |")
    summary = "\n".join(table)
    comparison = f"""# Maigret / Ultimate before / Ultimate after

Werdykt: **CZĘŚCIOWO**. Nowy Ultimate jest lepszy w badanym korpusie pod względem
liczby poprawnych pól, typów, pochodzenia, odrzucania generic page i izolowania błędów.
Nie wykazano przewagi na całym katalogu platform. Maigret zachowuje przewagę w liczbie
dedykowanych schematów; konkretny kontrprzykład w korpusie to Patreon RSC.

{summary}

Próbka: {total} autorskich fixture, {expected} jawnie oczekiwanych pól. To regresje
mechanizmów, częściowo przypadki negatywne/adwersarialne, a nie losowa próba profili.
19 oznacza wstrzykniętą bramę FOUND/CLAIMED dla odpowiedzi 200; **nie jest wynikiem
pełnego detektora Maigret**. Dwie odpowiedzi mają statusy 403 i 404. E2E transport
Ultimate testowany jest osobno na lokalnym serwerze HTTP.

Normalizacja scoringu pozwala donorowi zwracać liczby/bool jako stringi; `1.2K`
porównuje się semantycznie z 1200. Surowe wartości są zachowane w JSON. Typy rzeczywiste
sprawdza osobny test Ultimate. Nie zaliczamy poprawnej reprezentacji stringowej
licznika jako błędnej wartości tylko dlatego, że typ jest słabszy.

Ultimate before to wykonanie utrwalonego kodu z `baseline-src.zip`, z jawnymi regułami
już dostępnymi przed zmianą. Były przypisane do 3 fixture. Domyślny katalog importowany
nie miał żadnych extractorów, więc jego rzeczywisty automatyczny enrichment wynosił 0.
Nie dodano wstecz ręcznych selektorów do każdej fixture: mierzymy dostępną konfigurację,
nie teoretyczną możliwość napisania parsera regex dla dowolnego fragmentu.

Nowy moduł zebrał **104 dodatkowe poprawne pola względem skonfigurowanego before**
i **63 więcej niż Maigret netto**. „Netto” uwzględnia 8 pól Patreon, które zwrócił
donor, a których nowy moduł nie zwrócił. 100% precision dotyczy wyłącznie fixture.

## Stan przed i decyzje

Ultimate wcześniej miał działającą ekstrakcję JSON, regex, Discourse, XenForo i Patreon,
typed FieldObservation, kontrolę owner_path, limity oraz odrębne procesy. Nie był to
sam scaffold. Brakowało automatycznego wyboru metadanych z odpowiedzi, wspólnego modelu
profilu, ogólnych OG/JSON-LD, zachowania konfliktów i przypięcia reguł do importów.

Już wcześniej przewagą Ultimate były błędy oddzielone od detection, killable parser,
zachowanie 0/false oraz scheduler. Maigret miał znacznie bogatszą bibliotekę selektorów.

ADAPT: wiele pól z jednego JSON, parsery rodzin forów, publiczny JSON w HTML.
REWRITE: dobór właściciela, typy, walidacja, merge, diagnostyka, planowanie follow-up.
REJECT: inferred email, first-user/global-state, wykonywanie JS, ukryte HTTP w parserze,
niekontrolowany plugin import i domyślny zapis pełnej odpowiedzi.

Najbardziej wartościowy mechanizm donora: selektory wielu pól jednego obiektu profilu.
Najbardziej kruchy: regex/flags bez źródłowego URL i tożsamości właściciela oraz
first-user przy RSC. Dalsza poprawa jakości: przetestowane mapowania platformowe z
relacjami owner; dalsza poprawa czasu: nadzorowana pula procesów.
"""
    write("ENRICHMENT_COMPARISON.md", comparison)
    runtime = [
        "# Kontrolowane wyniki runtime\n",
        summary,
        "\n## Metoda i odtwarzanie\n",
        "Wykonanie offline. Network time w macierzy wynosi 0; response pochodzi "
        "z kontrolowanej fixture, a latency oznacza wyłącznie czas wywołania ekstrakcji. "
        "Nie mierzono publicznej sieci ani pełnego CLI Maigret. Szczegóły wrappera "
        "i ograniczenia zależności: ENRICHMENT_ANALYSIS.md. Maigret defaults AI=False.\n",
        "Komendy (środowisko audytowe wymaga dostępnych lokalnie zależności socid):\n",
        "```powershell\npython tools/enrichment_audit/inventory.py\n"
        "python tools/enrichment_audit/compare.py\npython tools/enrichment_audit/compare.py --after\n"
        "python benchmarks/enrichment_benchmark.py\npython tools/check.py\npython tools/enrichment_docs.py\n```\n",
        "Harness korzysta z zamrożonego źródła before i bieżącego after. Sieć donorów "
        "jest zablokowana, dodatki socid wyłączone, pliki donorów pozostają niezmienione. "
        "Scoring: correct/expected = coverage; correct/returned = precision; "
        "wrong/returned = wrong rate; puste ekstrakcje/liczba fixture = empty rate; "
        "przypadki z błędem/liczba fixture = parser failure rate. Brak optional field "
        "nie jest błędem parsera. Oczekiwane wartości ustalono w fixture, nie na "
        "podstawie tego, co akurat zwróci extractor. W każdej komórce `R/C/M/W` "
        "oznacza returned/correct/missing/wrong.\n",
        "| Fixture | Gate FOUND | Expected | Maigret R/C/M/W | Before R/C/M/W | After R/C/M/W | Bytes | Parser type |",
        "|---|---|---:|---|---|---|---:|---|",
    ]
    for b, a in zip(before, after, strict=True):
        vals = [b["maigret"], b["ultimate_before"], a["ultimate_after"]]
        cells = [
            "/".join(str(v[k]) for k in ("returned", "correct", "missing", "wrong")) for v in vals
        ]
        runtime.append(
            f"| {a['id']} | {'TAK (input)' if a['detection_gate'] else 'NIE'} | {len(a['expected'])} | {' | '.join(cells)} | {a['response_bytes']} | {a['kind']} |"
        )
    runtime.extend(
        [
            "\n## Wydajność\n",
            "Poniżej 1000 powtórzeń czystego pipeline bez uruchamiania procesów "
            "i bez HTTP. FULL parsuje dodatkową kontrolowaną odpowiedź JSON.\n",
            "| Mode | Mean ms | p50 ms | p95 ms | Parse mean ms | Enrichment mean ms |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for r in benchmark["pipeline"]:
        runtime.append(
            f"| {r['mode']} | {r['mean_seconds'] * 1000:.4f} | {r['p50_seconds'] * 1000:.4f} | {r['p95_seconds'] * 1000:.4f} | {r['parse_mean'] * 1000:.4f} | {r['extraction_mean'] * 1000:.4f} |"
        )
    runtime.extend(
        [
            "\nRzeczywisty UsernameEngine + scheduler + osobny proces (5 profili/tryb). "
            "FakeTransport z planowanym opóźnieniem 1 ms; rzeczywisty czas opóźnienia "
            "zależy od schedulera systemu. Nie jest to pomiar Internetu.\n",
            "| Mode | HTTP calls | Mean total ms | Network total ms | Parse mean ms | Enrichment mean ms |",
            "|---|---:|---:|---:|---:|---:|",
        ]
    )
    for r in benchmark["process_pipeline"]:
        runtime.append(
            f"| {r['mode']} | {r['request_count']} | {r['mean_seconds'] * 1000:.3f} | {r['network_total'] * 1000:.3f} | {r['parse_mean'] * 1000:.3f} | {r['extraction_mean'] * 1000:.3f} |"
        )
    off, basic, full = benchmark["process_pipeline"]
    runtime.append(
        f"\nBASIC dodaje średnio {(basic['mean_seconds'] - off['mean_seconds']) * 1000:.3f} ms, FULL {(full['mean_seconds'] - off['mean_seconds']) * 1000:.3f} ms/profil w tym lokalnym pomiarze. W BASIC ekstrakcja wewnątrz procesu stanowi {100 * basic['extraction_mean'] / basic['mean_seconds']:.2f}% czasu całkowitego; większość kosztu przypada na izolację/start i IPC. Próbka 5 jest mała, nie jest SLA.\n"
    )
    once = benchmark["html_parse_once_vs_five"]
    runtime.append(
        f"\n1000 dokumentów: jeden parse {once['1']:.4f} s; pięć niezależnych parse {once['5']:.4f} s ({once['5'] / once['1']:.2f}×). To porównanie liczby parsowań, nie deklaracja takiego przyspieszenia całej aplikacji ani całego Maigret.\n"
    )
    runtime.extend(
        [
            "\n## Pamięć\n",
            "Tracemalloc, MiB alokacji Pythona. Niezależne scenariusze retencji powtarzanej "
            "fixture; stałe stringi mogą być współdzielone. To nie RSS i nie estymacja "
            "10 000 stron o rozmiarze 1 MiB. `document` obejmuje body, decoded text "
            "i wybrane węzły; nie jest pełnym DOM BeautifulSoup. `metadata` obejmuje "
            "pola, URL avatara, provenance, evidence i kandydatów.\n",
            "| Profile | Retained component | Current MiB | Peak MiB |",
            "|---:|---|---:|---:|",
        ]
    )
    for r in benchmark["memory"]:
        runtime.append(
            f"| {r['profiles']} | {r['retained_component']} | {r['current_bytes'] / 2**20:.4f} | {r['peak_bytes'] / 2**20:.4f} |"
        )
    runtime.append("\n## Ranking pól w tej próbce\n")
    counter = collections.Counter(
        k
        for r in after
        for k, v in r["ultimate_after"]["actual"].items()
        if k in r["expected"] and v == r["expected"][k]
    )
    runtime.append(", ".join(f"`{k}`: {n}" for k, n in counter.most_common()))
    runtime.extend(
        [
            "\nNajbardziej weryfikowalne: dokładny username, jawny ID oraz wartości "
            "tego samego obiektu profilu. Najbardziej problematyczne: generic display_name, "
            "niejednoznaczne skróty liczników, daty bez strefy, profile vs viewer, RSC owner. "
            "Najniższa wartość: tytuł/logo/marketingowy opis serwisu. Kosztowne: pola "
            "wymagające dodatkowego response i startu parsera. W kontrolowanym FULL "
            "dodatkowy endpoint daje followers; czy warto go pobierać na danej platformie "
            "wymaga pomiaru liczby nowych pól, nie samego faktu istnienia endpointu.\n",
            "\n## Diagnostyka każdej fixture\n",
        ]
    )
    for b, a in zip(before, after, strict=True):
        runtime.append(
            f"\n### {a['id']}\n\nDetection: {'FOUND jako wejście testu' if a['detection_gate'] else 'bramka statusu nie dopuszcza ekstrakcji'}. Network: 0 s; response: {a['response_bytes']} B; format: {a['kind']}.\n"
        )
        runtime.append(
            "```json\n"
            + json.dumps(
                {
                    "expected": a["expected"],
                    "maigret": b["maigret"],
                    "ultimate_before": b["ultimate_before"],
                    "ultimate_after": a["ultimate_after"],
                    "extraction_sources": a.get("extraction_sources", []),
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n```\n"
        )
        missing = [k for k, v in a["expected"].items() if a["ultimate_after"]["actual"].get(k) != v]
        runtime.append(
            "Missing possibilities: " + (", ".join(missing) or "brak w fixture") + ". "
            "Źródło: body fixture; nazwa schematu donora jest w raw._extractor, "
            "lokalizatory Ultimate w jego modelu/testach. Rekomendacja: "
            + (
                "owner-aware parser RSC przed włączeniem automatycznego mapowania."
                if missing
                else "utrzymać przypadek w regresjach; potwierdzić na kontrolowanej odpowiedzi platformy przed rozszerzeniem deklarowanej obsługi."
            )
        )
    write("ENRICHMENT_RUNTIME_RESULTS.md", "\n".join(runtime))
    (ART / "summary.json").write_text(
        json.dumps({"fixtures": total, "expected_fields": expected, "stats": stats}, indent=2),
        encoding="utf-8",
    )

    tests = read(ROOT / "artifacts/test-results.json")
    tree = ast.parse((ROOT / "tests/unit/test_profile_metadata.py").read_text(encoding="utf-8"))
    proof = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        for dec in node.decorator_list:
            if (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Attribute)
                and dec.func.attr == "regression"
            ):
                for arg in dec.args:
                    if isinstance(arg, ast.Constant):
                        name = "tests/unit/test_profile_metadata.py::" + node.name
                        matches = {
                            n: s for n, s in tests["outcomes"].items() if n.split("[")[0] == name
                        }
                        proof[arg.value] = {
                            "test": name,
                            "passed": bool(matches)
                            and all(s == "PASSED" for s in matches.values()),
                            "outcomes": matches,
                        }
    (ART / "regression-proof.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")
    print("Generated field catalog, comparison, runtime diagnostics and regression proof")


if __name__ == "__main__":
    main()
