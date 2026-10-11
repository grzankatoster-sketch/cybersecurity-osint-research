from pathlib import Path

from username_engine import cli
from username_engine.correlate import Account, link_accounts, same_name_clusters
from username_engine.geo import Gazetteer
from username_engine.models import Result, Status

GH_URL = "https://github.com/sampler51"
WY_URL = "https://wykop.pl/ludzie/sampler51"


def _gh(profile=None):
    return Account("sampler51", "GitHub", GH_URL, profile or {"name": "Kod"})


def _wykop(bio):
    return Account("sampler51", "Wykop", WY_URL, {"bio": bio})


# --- nowe zachowanie: wzmianka bez schematu w bio = link krzyżowy ---

def test_schemeless_profile_mention_in_bio_links_accounts():
    link = link_accounts(_wykop("Mój kod: github.com/sampler51 | zapraszam"), _gh())
    assert link.score == 0.7
    assert "Wykop linkuje do GitHub" in link.reasons


def test_mention_with_www_uppercase_and_sentence_dot():
    link = link_accounts(_wykop("Zobacz WWW.GitHub.com/Sampler51."), _gh())
    assert link.score == 0.7
    assert "Wykop linkuje do GitHub" in link.reasons


def test_mention_with_trailing_slash_and_comma():
    link = link_accounts(_wykop("repo: github.com/sampler51/, reszta prywatna"), _gh())
    assert link.score == 0.7


def test_reverse_direction_mention_in_second_account_bio():
    gh = _gh({"bio": "Wykop: wykop.pl/ludzie/sampler51"})
    wy = Account("sampler51", "Wykop", WY_URL, {"name": "Sampler"})
    link = link_accounts(wy, gh)
    assert link.score == 0.7
    assert "GitHub linkuje do Wykop" in link.reasons


def test_subdomain_profile_mentioned_without_scheme():
    blog = Account("sampler51", "Blogspot", "https://sampler51.blogspot.com/", {"name": "Blog"})
    link = link_accounts(_wykop("bloguję na sampler51.blogspot.com od lat"), blog)
    assert link.score == 0.7
    assert "Wykop linkuje do Blogspot" in link.reasons


def test_mutual_schemeless_mentions_combine_both_directions():
    gh = _gh({"bio": "też wykop.pl/ludzie/sampler51"})
    link = link_accounts(_wykop("github.com/sampler51"), gh)
    assert link.score == 0.85 and link.level == "mocne"   # wzajemne linki: jeden sygnał kontroli (reguła wspólna z entity-graph)
    assert "Wykop linkuje do GitHub" in link.reasons
    assert "GitHub linkuje do Wykop" in link.reasons


def test_same_name_clusters_reports_pair_from_bio_mention():
    pairs = same_name_clusters([_wykop("kod: github.com/sampler51"), _gh()])
    assert len(pairs) == 1
    assert pairs[0]["score"] == 0.7
    assert "Wykop linkuje do GitHub" in pairs[0]["reasons"]


def test_cli_analyze_shows_pair_from_schemeless_bio_mention(capsys):
    scans = {"sampler51": [
        Result("Wykop", WY_URL, Status.FOUND, 0.9, "ok", 200, {"bio": "kod: github.com/sampler51"}),
        Result("GitHub", GH_URL, Status.FOUND, 0.9, "ok", 200, {"name": "Kod"}),
        Result("Inny", "https://inny.example/sampler51", Status.ERROR, 0.0, "timeout"),
    ]}
    analysis = cli.analyze(scans, "sampler51", {}, Gazetteer(None), 0.6)
    assert analysis["pairs"] and analysis["pairs"][0]["score"] == 0.7
    cli.print_analysis(analysis)
    out = capsys.readouterr().out
    assert "Możliwe powiązanie kont (dowody umiarkowane, tylko pola kopiowalne)" in out and "%)" not in out
    assert "Wykop linkuje do GitHub" in out


# --- brzegowe: brak fałszywych powiązań i podwójnego liczenia ---

def test_longer_username_is_not_a_mention():
    link = link_accounts(_wykop("github.com/sampler51x"), _gh())
    assert link.score == 0.0
    assert link.reasons == []


def test_domain_suffix_is_not_a_mention():
    link = link_accounts(_wykop("notgithub.com/sampler51"), _gh())
    assert link.score == 0.0


def test_deeper_path_is_not_profile_mention():
    link = link_accounts(_wykop("github.com/sampler51/dotfiles"), _gh())
    assert link.score == 0.0


def test_full_url_in_links_and_bio_counted_once():
    wy = Account("sampler51", "Wykop", WY_URL,
                 {"bio": "kod https://github.com/sampler51", "links": ["https://github.com/sampler51"]})
    link = link_accounts(wy, _gh())
    assert link.score == 0.7
    assert link.reasons.count("Wykop linkuje do GitHub") == 1


def test_missing_bio_gives_no_signal():
    link = link_accounts(Account("sampler51", "Wykop", WY_URL, {"name": "Zupełnie inna"}), _gh())
    assert link.score == 0.0
