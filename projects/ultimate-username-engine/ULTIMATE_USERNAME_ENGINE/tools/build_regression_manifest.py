"""Explicit audit-to-behavior-test mapping; never infer coverage from architecture."""

import ast
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Names are resolved to collected pytest base node IDs, including all parameterizations.
COVERED = {
    "SH01": "failure_gate_for_every_detector",
    "SH02": "status_only_and_absence_of_negative_cannot_prove_found",
    "SH03": "sherlock_string_and_list_redirect_identical",
    "SH04": "bounded_parallel_jobs_and_complete_results",
    "SH05": (
        "non_destructive_normalization_and_path_encoding json_body_recurses_and_escapes_username"
    ),
    "SH06": (
        "hundred_lifecycles_leave_no_tasks_and_counters_are_per_job read_timeout_and_cancel_cleanup"
    ),
    "SH07": (
        "strict_codec_and_invalid_record_isolation invalid_and_disabled_do_not_abort_valid_work"
    ),
    "SH09": "empty_registry_and_selection invalid_timeouts",
    "SH11": "hundred_lifecycles_leave_no_tasks_and_counters_are_per_job",
    "SH12": (
        "sherlock_string_and_list_redirect_identical registry_filters_disabled_categories_and_id"
    ),
    "SH13": (
        "dns_root_causes_distinct_and_serializable "
        "exception_timeout_and_success_produce_three_terminal_records"
    ),
    "SH14": (
        "slow_first_completion_stream_and_ten_thousand_bounded "
        "slow_consumer_backpressure_and_lazy_source"
    ),
    "SH15": (
        "import_has_no_network_file_writes_or_plugin_loading "
        "bounded_parallel_jobs_and_complete_results"
    ),
    "SH16": "health_shared_detector_empty_partial_and_random_collision",
    "MG01": (
        "exception_timeout_and_success_produce_three_terminal_records "
        "scheduler_source_exception_surfaces_without_orphans"
    ),
    "MG02": "parser_process_deadline_preserves_found_and_base_committed_first",
    "MG03": "unknown_status_body_cannot_prove_account",
    "MG04": (
        "status_only_and_absence_of_negative_cannot_prove_found "
        "generic_cloudflare_captcha_mentions_and_escaped_unicode"
    ),
    "MG05": "pool_reused_redirect_not_automatic_and_cookies_disabled",
    "MG07": "request_identity_preserves_path_case_query_and_context",
    "MG08": "hundred_lifecycles_leave_no_tasks_and_counters_are_per_job",
    "MG10": (
        "health_shared_detector_empty_partial_and_random_collision "
        "strict_codec_and_invalid_record_isolation"
    ),
    "MG11": (
        "maigret_engine_merge_does_not_mutate_and_quarantines_conflict codec_roundtrip_nested_rules"
    ),
    "MG12": "unknown_fields_and_bad_record_do_not_silently_default",
    "MG13": "json_body_recurses_and_escapes_username form_and_query_encoding_preserves_method",
    "MG15": "slow_cancellation_cleanup_holds_slot process_success_and_cancellation_cleanup",
    "MG16": "queue_job_deadlines_and_admission_limit read_timeout_and_cancel_cleanup",
    "MG17": (
        "retry_transient_errors_and_preserve_attempts "
        "retry_after_delta_and_http_date "
        "retry_cooldown_does_not_occupy_worker_or_starve_healthy_origin"
    ),
    "MG18": "dns_root_causes_distinct_and_serializable fake_network_errors_not_missing",
    "MG19": (
        "json_export_all_errors_unicode_and_no_detection_recomputation "
        "exception_timeout_and_success_produce_three_terminal_records"
    ),
    "MG20": (
        "parser_process_deadline_preserves_found_and_base_committed_first "
        "malformed_empty_then_matching_extractor_continues"
    ),
    "MG21": (
        "snapshot_hash_schema_cas_and_concurrent_writer_failure "
        "atomic_export_failure_preserves_previous_and_cleans_temp"
    ),
    "MG23": (
        "queue_job_deadlines_and_admission_limit "
        "hundred_jobs_with_thirty_percent_rate_limits_share_all_limits "
        "cancel_awaits_active_requests_and_other_job_survives"
    ),
    "MG24": (
        "non_destructive_normalization_and_path_encoding "
        "hundred_lifecycles_leave_no_tasks_and_counters_are_per_job"
    ),
    "MG25": "slow_first_completion_stream_and_ten_thousand_bounded decoded_body_limit",
    "MG26": (
        "atomic_export_failure_preserves_previous_and_cleans_temp "
        "json_export_all_errors_unicode_and_no_detection_recomputation"
    ),
    "MG27": "health_shared_detector_empty_partial_and_random_collision",
    "MG28": "all_scheduler_limits_reject_zero_negative_and_bool invalid_retry_and_contradiction",
    "WM01": (
        "failure_gate_and_account_evidence "
        "health_shared_detector_empty_partial_and_random_collision"
    ),
    "WM03": "dns_root_causes_distinct_and_serializable fake_network_errors_not_missing",
    "WM05": "late_marker_export_and_error_json_roundtrip",
    "WM06": (
        "wmn_every_request_field_and_disabled_preserved json_body_recurses_and_escapes_username"
    ),
    "WM07": "health_shared_detector_empty_partial_and_random_collision",
    "WM08": (
        "invalid_url_templates duplicate_id_quarantines_both_entries "
        "missing_wmn_controls_and_bad_payload_rejected"
    ),
    "WM09": (
        "cancel_awaits_active_requests_and_other_job_survives "
        "slow_first_completion_stream_and_ten_thousand_bounded"
    ),
    "WM11": "generic_cloudflare_captcha_mentions_and_escaped_unicode invalid_detection_rules",
    "WM12": (
        "hundred_lifecycles_leave_no_tasks_and_counters_are_per_job "
        "all_scheduler_limits_reject_zero_negative_and_bool "
        "import_has_no_network_file_writes_or_plugin_loading"
    ),
    "BB01": (
        "failure_gate_and_account_evidence wmn_empty_markers_are_diagnostics_not_empty_predicates"
    ),
    "BB02": "wmn_every_request_field_and_disabled_preserved",
    "BB03": "hundred_jobs_with_thirty_percent_rate_limits_share_all_limits",
    "BB04": (
        "process_success_and_cancellation_cleanup "
        "parser_process_deadline_preserves_found_and_base_committed_first"
    ),
    "BB05": "snapshot_hash_schema_cas_and_concurrent_writer_failure",
    "BB08": "typed_values_and_conflicting_observations_do_not_alias definition_frozen",
    "BB09": (
        "untrusted_tls_certificate_is_error_without_verdict "
        "real_engine_redirect_retry_and_decoding "
        "invalid_json_or_encoding_is_parse_error"
    ),
    "BB10": (
        "invalid_and_disabled_do_not_abort_valid_work "
        "malformed_empty_then_matching_extractor_continues "
        "parser_process_deadline_preserves_found_and_base_committed_first"
    ),
    "BB11": (
        "all_scheduler_limits_reject_zero_negative_and_bool "
        "empty_registry_and_selection bounded_parallel_jobs_and_complete_results"
    ),
    "BB14": (
        "plugin_failure_is_contained_and_override_rejected "
        "blackbird_metadata_supported_shapes_and_unsupported_diagnostic"
    ),
    "BB12": "typed_values_and_conflicting_observations_do_not_alias",
    "BB15": "snapshot_hash_schema_cas_and_concurrent_writer_failure",
    "BB16": (
        "import_has_no_network_file_writes_or_plugin_loading "
        "malformed_empty_then_matching_extractor_continues"
    ),
    "SO01": "malformed_empty_then_matching_extractor_continues",
    "SO02": (
        "malformed_empty_then_matching_extractor_continues "
        "exact_host_and_owner_guard_exclude_viewer"
    ),
    "SO03": "malformed_empty_then_matching_extractor_continues",
    "SO04": "extractor_capture_contract",
    "SO05": "typed_values_and_conflicting_observations_do_not_alias typed_field_value",
    "SO06": (
        "import_has_no_network_file_writes_or_plugin_loading "
        "plugin_failure_is_contained_and_override_rejected"
    ),
    "SO09": (
        "exact_host_and_owner_guard_exclude_viewer "
        "discourse_and_xenforo_profile_guards_and_attribute_order"
    ),
    "SO10": "missing_profile_with_nonempty_extraction_remains_missing",
    "SO11": (
        "discourse_and_xenforo_profile_guards_and_attribute_order "
        "typed_values_and_conflicting_observations_do_not_alias"
    ),
    "SO12": "decoded_body_limit parser_process_deadline_preserves_found_and_base_committed_first",
    "SO14": "exact_host_and_owner_guard_exclude_viewer",
    "SO17": "regression_manifest_complete_and_tests_exist",
    "CO01": (
        "hundred_jobs_with_thirty_percent_rate_limits_share_all_limits "
        "retry_cooldown_does_not_occupy_worker_or_starve_healthy_origin"
    ),
    "CO02": (
        "confidence_is_null_without_calibration "
        "status_only_and_absence_of_negative_cannot_prove_found"
    ),
    "CO03": "untrusted_tls_certificate_is_error_without_verdict",
}
NOT_APPLICABLE = {
    "SH08": (
        "Brak wrappera wywolujacego legacy CLI i kontraktu TXT. Nowe CLI konsumuje Python API/JSON."
    ),
    "SH10": "XLSX nie jest czescia MVP; sciezka JSON/CSV jest jawna i nie powstaje z username.",
    "MG06": (
        "Brak rekurencji crosslinks i generowania permutacji w MVP. Budzet "
        "zwyklych requestow jest implementowany."
    ),
    "MG09": "PDF i opcjonalny backend PDF nie sa implementowane.",
    "MG14": (
        "Jeden backend HTTP; brak legacy backendow requests/curl/browser i "
        "aktywatorow. FakeTransport nie udaje klienta cookies."
    ),
    "MG22": (
        "Aktywacja i cache tokenow sa odrzucone; importer kwarantannuje "
        "activation, naglowki definicji sa immutable."
    ),
    "WM02": "Renderer/browser poza MVP; HTTP nie uruchamia przegladarki.",
    "WM04": "Brak automatycznego fallbacku backendow; retry zachowuje probe i wszystkie proby.",
    "WM10": (
        "Brak browser/requests fallback. Jeden jawny kontrakt aiohttp, "
        "przekierowania koordynuje scheduler."
    ),
    "BB06": "AI analysis i globalny config AI nie istnieja w nowym core.",
    "BB07": (
        "Legacy DSL filtrow nie jest obslugiwany. API przyjmuje jawne ID i "
        "kategorie, CLI nie interpretuje operatorow."
    ),
    "BB13": "PDF/layout i debug dump poza MVP; eksport JSON/CSV operuje na DTO.",
    "SO07": (
        "Automatyczne cookies celowo wylaczone (DummyCookieJar); brak "
        "flatten/import/export cookie jar."
    ),
    "SO08": (
        "Brak generowania mutation endpoints. Nie implementowano wspoldzielenia "
        "odpowiedzi pomiedzy roznymi definicjami."
    ),
    "SO13": (
        "Brak inferencji/postprocessora nadpisujacego dane. Obserwacje "
        "extractorow sa oddzielnymi immutable rekordami."
    ),
    "SO15": (
        "Legacy parser dat i aktywatory nie sa przeniesione. Daty pozostaja "
        "danymi zrodlowymi; pliki UTF-8."
    ),
    "SO16": "AI fallback i SDK modeli poza MVP.",
}

SCOPE = {
    "SH12": (
        "Negatywne controls zachowane; lookup i disabled po dokladnym ID. Nie "
        "pobiera legacy exclusions."
    ),
    "MG21": "Lokalna promocja snapshotow z CAS/lock/hash/schema. Brak automatycznego downloadera.",
    "MG28": (
        "Walidacja limitow; sieciowy URL aktualizacji nie jest wspierany, wiec "
        "brak ukrytego HTTP updatera."
    ),
    "BB04": "Pure extraction poza event loop; obraz jest URL-em, bez pobierania pliku w parserze.",
    "BB14": (
        "Jawna rejestracja strategii; brak pluginu AI, nieobslugiwany extractor ma diagnostyke."
    ),
    "BB15": (
        "SnapshotStore uzywa absolutnej sciezki oraz integralnosci; downloader "
        "nie istnieje, liczba pobran wynosi zero."
    ),
    "SO02": (
        "Brak aktywatorow i dodatkowego I/O w parserach; extraction otrzymuje "
        "tylko body i jawny URL."
    ),
    "SO11": (
        "Jawna lista per-site zamiast skanu calego katalogu; wszystkie parsery "
        "maja szanse zwrocic wynik."
    ),
    "SO12": "Body/field/process deadlines; globalne debug dump sa pominiete.",
    "CO02": (
        "Confidence pozostaje null; kalibracja skutecznosci rzeczywistych "
        "platform wymaga odrebnego runtime."
    ),
}


def main():
    ledger = json.loads((ROOT / "docs/audit-ledger.json").read_text("utf-8"))
    known = {}
    for path in (ROOT / "tests").rglob("test_*.py"):
        for node in ast.walk(ast.parse(path.read_text("utf-8"))):
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
                known[node.name.removeprefix("test_")] = (
                    path.relative_to(ROOT).as_posix() + "::" + node.name
                )
    assert set(COVERED) | set(NOT_APPLICABLE) == {row["id"] for row in ledger}
    assert not set(COVERED) & set(NOT_APPLICABLE)
    records = []
    for item in ledger:
        key = item["id"]
        tests = [known[name] for name in COVERED.get(key, "").split()]
        records.append(
            {
                **item,
                "status": "COVERED" if key in COVERED else "NOT_APPLICABLE",
                "tests": tests,
                "scope": SCOPE.get(key, NOT_APPLICABLE.get(key, item["fix"])),
            }
        )
    path = ROOT / "docs/regression-manifest.json"
    path.write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    counts = Counter(r["status"] for r in records)
    lines = [
        "# Regression status — 92 ustalenia",
        "",
        f"COVERED: {counts['COVERED']}; NOT_APPLICABLE: {counts['NOT_APPLICABLE']}; "
        "REQUIRES_RUNTIME: 0.",
        "",
        "COVERED oznacza zachowanie nowego core sprawdzone konkretnymi testami, "
        "nie skutecznosc katalogu w internecie. N/A nie oznacza naprawy legacy; "
        "wskazany mechanizm nie zostal przeniesiony. Mapa nie usuwa zadnego ustalenia.",
        "",
        "Wyniki wykonania i parametryzowane node IDs: `artifacts/test-results.json`. "
        "Brak testu lub niepelny run nie jest dowodem zaliczenia.",
        "",
        "| ID | Status | Testy | Naprawa / zakres |",
        "|---|---|---|---|",
    ]
    for row in records:
        tests = "<br>".join("`" + t + "`" for t in row["tests"]) or "—"
        lines.append(f"| {row['id']} | {row['status']} | {tests} | {row['scope']} |")
    (ROOT / "REGRESSION_STATUS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(dict(counts))


if __name__ == "__main__":
    main()
