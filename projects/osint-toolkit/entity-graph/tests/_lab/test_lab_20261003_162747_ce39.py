from entity_graph.guardrails import AuditLog, verify_audit


ODD = ["\u2028", "\u2029", "\u0085"]


def test_untouched_log_with_unicode_line_separators_verifies(tmp_path):
    for i, ch in enumerate(ODD):
        path = tmp_path / f"a{i}.jsonl"
        log = AuditLog(path, operator="ala")
        log.start("audyt własnej firmy X", [{"type": "username", "value": f"jan{ch}kowalski"}], {"depth": 1})
        log.write("transform", transform="username_scan", status="FOUND", evidence=f"profil{ch}publiczny")
        log.write("end", nodes=2)
        ok, msg = verify_audit(path)
        assert ok, f"nienaruszony dziennik (znak {ch!r}) uznany za uszkodzony: {msg}"


def test_append_after_unicode_separator_keeps_chain(tmp_path):
    path = tmp_path / "a.jsonl"
    log = AuditLog(path, operator="ala")
    log.start("audyt własnej firmy X", [], {})
    log.write("transform", transform="t1", status="FOUND", evidence="a\u2028b")
    AuditLog(path, operator="ala").write("end")   # nowy obiekt kontynuuje łańcuch
    ok, msg = verify_audit(path)
    assert ok, msg


def test_tampering_still_detected_with_unicode_separator(tmp_path):
    path = tmp_path / "a.jsonl"
    log = AuditLog(path, operator="ala")
    log.start("audyt własnej firmy X", [], {})
    log.write("transform", transform="t1", status="ERROR", evidence="x\u2028y")
    log.write("end")
    raw = path.read_text(encoding="utf-8")
    path.write_text(raw.replace("ERROR", "FOUND"), encoding="utf-8")
    assert not verify_audit(path)[0]
