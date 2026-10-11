"""Szum korelacji z pomiaru 03.10.2026 (nazwa `mozilla`): ten sam serwis pod dwoma szablonami adresu
(Venmo / Venmo [maigret], Flipboard / amp.flipboard.com) oraz sklepy jednej rodziny (Envato) ze wspólnym
domyślnym avatarem i tytułem strony zamiast nazwy wyświetlanej dawały fałszywe „prawdopodobnie ta sama osoba”."""
from username_engine.correlate import (Account, boilerplate_avatars, link_accounts, same_name_clusters,
                                       service_domain, variant_links)
from username_engine.models import Result, Status

ENVATO_AVATAR = "https://s3.envato.com/files/default_avatar.png"
ENVATO_TITLE = "mozilla's profile on AudioJungle"
ENVATO_BIO = "Envato market author portfolio items followers sales"


def _envato(site: str, host: str) -> Account:
    return Account("mozilla", site, f"https://{host}/user/mozilla",
                   {"avatar": ENVATO_AVATAR, "name": ENVATO_TITLE, "bio": ENVATO_BIO})


def test_service_domain():
    assert service_domain("https://account.venmo.com/u/x") == "venmo.com"
    assert service_domain("https://venmo.com/x") == "venmo.com"
    assert service_domain("https://amp.flipboard.com/@x") == "flipboard.com"
    assert service_domain("https://x.example.co.uk/u") == "example.co.uk"
    assert service_domain("https://allegro.pl/uzytkownik/x") == "allegro.pl"
    assert service_domain("http://[bad") == ""


def test_same_service_same_username_is_not_evidence():
    prof = {"avatar": "https://cdn.venmo.com/a/123.jpg", "name": "Marta Exemplar | @Mozilla",
            "bio": "coffee hiking travel photography dogs"}
    pairs = same_name_clusters([Account("mozilla", "Venmo", "https://account.venmo.com/u/mozilla", prof),
                                Account("mozilla", "Venmo [maigret]", "https://venmo.com/mozilla", prof)])
    assert pairs == []


def test_same_service_different_variants_still_correlate():
    """Dwa różne konta na jednej platformie (różne nazwy) wolno łączyć — to nie jest to samo konto."""
    prof = {"avatar": "https://cdn.example.com/a/1.jpg", "name": "Jan Kowalski"}
    pairs = same_name_clusters([Account("sampler51", "Blog", "https://sampler51.blogspot.com", prof),
                                Account("sampler.51", "Blog", "https://sampler-51.blogspot.com", prof)])
    assert len(pairs) == 1


def test_avatar_shared_by_three_services_is_boilerplate():
    accs = [_envato("Audiojungle", "audiojungle.net"), _envato("VideoHive", "videohive.net"),
            _envato("Codecanyon", "codecanyon.net")]
    assert boilerplate_avatars(accs) == {ENVATO_AVATAR}
    assert same_name_clusters(accs) == []


def test_avatar_shared_by_two_services_still_counts():
    a = Account("x", "A", "https://a.com/x", {"avatar": "https://gravatar.com/avatar/abc"})
    b = Account("x", "B", "https://b.com/x", {"avatar": "https://gravatar.com/avatar/abc"})
    assert boilerplate_avatars([a, b]) == set()
    assert "ten sam adres avatara" in link_accounts(a, b).reasons


def test_page_title_is_not_display_name():
    a = Account("mozilla", "Codecanyon", "https://codecanyon.net/user/mozilla", {"name": ENVATO_TITLE})
    b = Account("mozilla", "VideoHive", "https://videohive.net/user/mozilla", {"name": ENVATO_TITLE})
    assert link_accounts(a, b).score == 0


def test_variant_links_ignore_boilerplate_avatar():
    def found(site, host, variant):
        return Result(site=site, url=f"https://{host}/user/{variant}", status=Status.FOUND, confidence=0.9,
                      profile={"avatar": ENVATO_AVATAR})
    scans = {"mozilla": [found("Audiojungle", "audiojungle.net", "mozilla"),
                         found("VideoHive", "videohive.net", "mozilla")],
             "mozilla_": [found("Codecanyon", "codecanyon.net", "mozilla_")]}
    assert variant_links(scans, "mozilla")["mozilla_"]["score"] == 0.0


def test_cli_output_survives_cp1250_redirect(monkeypatch):
    """Wyjście przekierowane do pliku na Windows (cp1250) nie może wywracać skanu na znakach typu ↔."""
    import io
    import sys

    from username_engine import cli
    buf = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(buf, encoding="cp1250"))
    assert cli.main(["sampler51", "--show-variants"]) == 0
    print("Audiojungle ↔ VideoHive ≥0.6")
    sys.stdout.flush()
    assert "↔".encode() in buf.getvalue()


def test_default_and_name_generated_avatars_are_not_evidence():
    tw = "https://static-cdn.jtvnw.net/user-default-pictures-uv/ead5c8b2-300x300.png"
    a = Account("mozilla", "Twitch", "https://www.twitch.tv/mozilla", {"avatar": tw})
    b = Account("mozilla", "Twitch [maigret]", "https://twitchtracker.com/mozilla", {"avatar": tw})
    assert link_accounts(a, b).score == 0
    gen = "https://cash.app/share-image?ct=mozilla"
    c = Account("mozilla", "CashMe", "https://cash.me/$mozilla", {"avatar": gen})
    d = Account("mozilla", "Cash.app", "https://cash.app/$mozilla", {"avatar": gen})
    assert link_accounts(c, d).score == 0


def test_display_name_naming_the_service_is_a_template():
    a = Account("mozilla", "CashMe", "https://cash.me/$mozilla", {"name": "Pay me on Cash App"})
    b = Account("mozilla", "Cash.app", "https://cash.app/$mozilla", {"name": "Pay me on Cash App"})
    assert link_accounts(a, b).score == 0
    # prawdziwa nazwa nadal się liczy
    c = Account("jan", "GitHub", "https://github.com/jan", {"name": "Jan Kowalski"})
    d = Account("jan", "GitLab", "https://gitlab.com/jan", {"name": "Jan Kowalski"})
    assert link_accounts(c, d).score > 0
