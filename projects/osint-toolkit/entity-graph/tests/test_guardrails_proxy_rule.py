"""Zasada fail-closed dla proxy/Tora w EXCLUDED_CAPABILITIES (osobno od importera org-intel)."""


def test_excluded_capabilities_state_the_fail_closed_proxy_rule():
    from entity_graph.guardrails import EXCLUDED_CAPABILITIES

    text = " ".join(EXCLUDED_CAPABILITIES)
    assert "Tor" in text and "fail-closed" in text and "zatrzymuje" in text
    assert "rotacja IP" in text and "podrabianie odcisku przeglądarki" in text and "CallApp" in text
