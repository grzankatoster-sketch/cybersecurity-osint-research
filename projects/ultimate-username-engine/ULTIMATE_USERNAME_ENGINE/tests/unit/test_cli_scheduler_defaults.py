"""Domyslna wspolbieznosc CLI: --per-job nie obcina --concurrency, bufor zadania rosnie razem z nia."""

from ultimate_username.cli import parser, scheduler_config


def _args(*extra):
    return parser().parse_args(["search", "nick", *extra])


def test_per_job_defaults_to_concurrency():
    arguments = _args()
    config = scheduler_config(arguments)
    assert config.concurrency == 20
    assert config.per_job == 20
    assert config.per_origin == 2


def test_explicit_per_job_is_kept():
    config = scheduler_config(_args("--concurrency", "20", "--per-job", "10"))
    assert (config.concurrency, config.per_job) == (20, 10)


def test_job_buffer_covers_two_waves_of_work():
    assert scheduler_config(_args("--concurrency", "8")).job_buffer == 32
    assert scheduler_config(_args("--concurrency", "40")).job_buffer == 80


def test_rescan_half_follows_effective_concurrency():
    config = scheduler_config(_args())
    assert max(1, min(config.per_job, config.concurrency) // 2) == 10
