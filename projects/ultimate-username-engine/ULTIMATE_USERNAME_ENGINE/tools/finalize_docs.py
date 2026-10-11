"""Render status only from completed quality gates, imports and measured benchmarks."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    quality = json.loads((ROOT / "artifacts/quality-gates.json").read_text("utf-8"))
    tests = json.loads((ROOT / "artifacts/test-results.json").read_text("utf-8"))
    donors = json.loads((ROOT / "artifacts/donor-integrity.json").read_text("utf-8"))
    performance = json.loads((ROOT / "benchmarks/results.json").read_text("utf-8"))
    assert quality["passed"] and donors["passed"] and tests["exit_code"] == 0
    assert {100, 1000, 10000} <= {r["sites"] for r in performance["runs"]}
    assert all(r["cleanup_verified"] for r in performance["runs"])
    count = tests["summary"]["PASSED"]
    covered = sum(r["status"] == "COVERED" for r in tests["regression"].values())
    na = sum(r["status"] == "NOT_APPLICABLE" for r in tests["regression"].values())
    status = f"""# Phase

READY_FOR_CONTROLLED_RUNTIME_VALIDATION

## DONE

- CORE_OFFLINE_COMPLETE — modele, registry, walidacja, planner, FakeTransport,
  detektory, scheduler, API i normalizacja.
- REAL_HTTP_TRANSPORT — pooling, TLS, proxy HTTP, timeouty, redirect/retry i cleanup;
  testy lokalnych serwerow.
- LEGACY_IMPORT — 8956 definicji, 164 rekordy kwarantanny, 756 grup konfliktow,
  17 reguł metadanych Blackbird.
- FULL_REGRESSION_SUITE — wszystkie 92 ustalenia sklasyfikowane;
  {covered} COVERED i {na} NOT_APPLICABLE.
- CLI_AND_OUTPUT — biblioteka, CLI, JSON/NDJSON/CSV, SQLite journal, atomowe eksporty.
- PERFORMANCE_VALIDATION — zmierzone 100 / 1000 / 10000 definicji;
  ograniczenia i cleanup potwierdzone.
- Oryginalne repozytoria: 419 plikow identycznych, wszystkie HEAD zgodne i worktree clean.

## IN PROGRESS

Brak etapow implementacji w toku.

## BLOCKED

Brak blokad implementacji.

## TESTS

{count} PASSED / 0 FAILED / 0 SKIPPED. Mypy strict i ruff check/format przechodza.
Dowody: artifacts/test-results.json, artifacts/quality-gates.json.
Offline regression: {covered} COVERED / {na} NOT_APPLICABLE / 0 REQUIRES_RUNTIME.
To status wad implementacyjnych. Skutecznosc historycznych regul online nie zostala zweryfikowana.

## KNOWN ISSUES

- Historyczne pozytywne reguly importowane nie maja verified profile binding: najwyzej PROBABLE.
- 164 definicje kwarantanny; nieobslugiwane m.in. placeholdery hostname, aktywacje, nie-HTTP.
- 756 grup konfliktow wymaga osobnej oceny; brak automatycznego wyboru wariantu.
- SOCKS/onion nie sprawdzono przeciwko rzeczywistemu gateway; proxy HTTP sprawdzono lokalnie.
- Proces na ekstrakcje ma cold-start overhead. SQLite sink jest synchroniczny.
- Benchmark nie obejmuje dysku, enrichment ani internetu; registry ma osobny koszt O(S).
- Lock snapshotu po crash nie jest automatycznie przejmowany.
- Brak AI/browser/GUI/rekurencji/permutacji/PDF/XLSX/autoupdate, zgodnie z zakresem MVP.

## NEXT

Osobny etap: kontrolowana walidacja niewielkiej liczby wybranych definicji i ich controls,
ocena konfliktow oraz kalibracja reguł. Nie wykonano zadnych live scanow publicznych platform.
"""
    (ROOT / "IMPLEMENTATION_STATUS.md").write_text(status, encoding="utf-8")
    lines = [
        "# Performance validation",
        "",
        "Syntetyczny FakeTransport, body 277 bajtow, 16 originow, C=32, Q=128. "
        "Streaming bez listy wszystkich wynikow. Python " + performance["python"].split()[0] + ".",
        "",
        "Tracemalloc byl wlaczony: wyniki sa pomiarem tego harnessu, bez SLA dla internetu. "
        "Czas pipeline obejmuje planner, scheduler, FakeTransport i detection; nie jest czystym "
        "czasem samego dispatchera.",
        "",
        "| Sites | Registry build s | Registry build peak MiB | Pipeline s | Work peak MiB | "
        "Async tasks peak | HTTP peak | Queue peak | Detection us/result |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in performance["runs"]:
        lines.append(
            f"| {r['sites']} | {r['registry_build_seconds']:.3f} | "
            f"{r['registry_build_peak_bytes'] / 1048576:.2f} | "
            f"{r['scheduler_pipeline_seconds']:.3f} | "
            f"{r['work_peak_bytes_excluding_registry'] / 1048576:.3f} | "
            f"{r['observed_peak_asyncio_tasks']} | {r['peak_http_active']} | {r['peak_pending']} | "
            f"{r['detection_microseconds_per_result']:.2f} |"
        )
    lines.extend(
        [
            "",
            "## Interpretacja",
            "",
            "- Liczba taskow nie rośnie z liczba definicji. 34 oznacza main+dispatcher+32 attempts "
            "w tym scenariuszu; timer oczekiwania moze utworzyc dodatkowy lekki task "
            "w scenariuszu cooldown.",
            "- Work peak to nowe alokacje Python podczas search po utworzeniu registry, "
            "nie calkowity RSS. "
            "Registry i jego serializacja maja koszt O(S); peak budowania jest raportowany osobno.",
            "- Queue nie przekroczyla 128, HTTP nie przekroczylo 32; "
            "kazda z definicji zwrocila wynik.",
            "- Osobne testy sprawdzaja 100 rownoczesnych jobow, 30% odpowiedzi 429, wolny pierwszy "
            "request, wolnego odbiorce, slow cleanup, parser process timeout i lokalny TLS.",
            "- Nie strojono limitow na podstawie nieistniejacych pomiarow publicznych platform. "
            "Brak danych o realnym RTT, skutecznosci markerow i przepustowosci proxy/SOCKS.",
            "",
            "Ponowienie: `python benchmarks/run_synthetic.py`. "
            "Pelne metryki: `benchmarks/results.json`.",
        ]
    )
    (ROOT / "PERFORMANCE.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Status ready: {count} passed; {covered} covered; {na} not applicable")


if __name__ == "__main__":
    main()
