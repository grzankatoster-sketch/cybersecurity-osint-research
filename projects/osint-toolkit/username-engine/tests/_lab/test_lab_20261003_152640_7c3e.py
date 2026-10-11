from username_engine.correlate import Account, link_accounts


def _pair(variant, display):
    a = Account(variant, "SerwisA", f"https://a.example/{variant}", {"name": display})
    b = Account(variant, "SerwisB", f"https://b.example/{variant}", {"name": display})
    return a, b


def test_display_name_equal_to_dotted_username_is_weak_signal():
    # nazwa wyswietlana to po prostu login -> sygnal slaby, tak jak dla loginu bez separatora
    plain = link_accounts(*_pair("sampler51", "sampler51"))
    dotted = link_accounts(*_pair("sampler.51", "sampler.51"))
    assert plain.score <= 0.1
    assert dotted.score <= 0.1, dotted


def test_display_name_equal_to_underscored_username_is_weak_signal():
    link = link_accounts(*_pair("sampler_51", "Sampler_51"))
    assert link.score <= 0.1, link


def test_real_display_name_still_counts():
    link = link_accounts(*_pair("sampler.51", "Jan Kowalski"))
    assert link.score >= 0.3
