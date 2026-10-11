"""Reguła wspólna z entity-graph: pola kopiowalne to jedna zależna grupa, "mocne" tylko z linków wzajemnych,
raport pokazuje poziom dowodów, nie procent."""
from username_engine.correlate import COPYABLE_CAP, Account, link_accounts

A_URL, B_URL = "https://alpha.example/u/ziarno7", "https://beta.example/u/ziarno_7"
COPY = {"name": "Ala Testowa", "location": "Gdansk", "website": "https://pracodawca.example",
        "bio": "Tworze otwarte narzedzia mapowe oraz projekty edukacyjne",
        "avatar": "https://cdn.example/images/photo123.jpg"}


def test_copied_fields_are_one_group_and_never_strong():
    link = link_accounts(Account("ziarno7", "Alpha", A_URL, COPY), Account("ziarno_7", "Beta", B_URL, COPY))
    assert len(link.reasons) >= 4                     # wszystkie powody są widoczne...
    assert link.score <= COPYABLE_CAP                 # ...ale liczą się raz (dawniej 0.93)
    assert link.level == "umiarkowane" and link.copy_only


def test_reciprocal_links_are_strong_one_way_is_a_claim():
    a = Account("ziarno7", "Alpha", A_URL, {"links": [B_URL]})
    b = Account("ziarno_7", "Beta", B_URL, {"links": [A_URL]})
    both = link_accounts(a, b)
    assert both.level == "mocne" and not both.copy_only
    one = link_accounts(a, Account("ziarno_7", "Beta", B_URL, {"name": "X"}))
    assert one.level == "umiarkowane" and one.copy_only


def test_report_shows_level_not_percent():
    from username_engine.report import _analysis_block
    html = _analysis_block({"country": [], "profiles_with_data": 0,
                           "variant_links": {"x_": {"score": 0.7, "level": "umiarkowane", "copy_only": True,
                                                    "reasons": ["r"], "pair": "A ↔ B", "accounts": 1}},
                           "pairs": [{"a": "A", "b": "B", "score": 0.7, "level": "umiarkowane", "copy_only": True,
                                      "reasons": ["r"]}]})
    assert "70%" not in html and "umiarkowane, tylko pola kopiowalne" in html
