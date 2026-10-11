"""Argument parsing, library invocation and output. No detection logic."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from ultimate_username.demo import make_demo
from ultimate_username.domain.codec import from_json, from_value, to_json
from ultimate_username.domain.metadata import EnrichmentMode, MetadataState
from ultimate_username.domain.models import (
    ExecutionState,
    ExtractionState,
    JSONValue,
    SearchResult,
)
from ultimate_username.dorks import build_queries, check_wayback, wayback_targets
from ultimate_username.engine import SearchOptions, UsernameEngine
from ultimate_username.geo import Gazetteer, geo_section, sources_from_results
from ultimate_username.html_report import render_report
from ultimate_username.health_probe import (
    BROKEN_SHARE_LIMIT,
    HealthEntry,
    broken_share,
    fill_missing,
    load_health,
    passive_health,
    probe_health,
    save_health,
)
from ultimate_username.http_transport import AiohttpTransport, HttpConfig
from ultimate_username.identity import (
    AvatarHash,
    IdentityConfig,
    IdentitySeed,
    fetch_avatar_records,
    identity_document,
    pillow_available,
    score_identities,
)
from ultimate_username.opsec.transport_factory import public_egress_transport
from ultimate_username.presentation import analyst_document, render_analyst, render_console
from ultimate_username.registry import SiteRegistry
from ultimate_username.request_economy import DefinitionHealth, economy
from ultimate_username.runtime_policy import MODES, RuntimePolicy, runtime_selection
from ultimate_username.scheduler import SchedulerConfig
from ultimate_username.selection import prepared_registry, select_services
from ultimate_username.storage import (
    ResultJournal,
    atomic_write,
    csv_chunks,
    export_results,
    json_chunks,
)
from ultimate_username.transport import Transport
from ultimate_username.variants import generate

IDENTITY_IMAGE_BUDGET = 50  # avatar requests when no explicit enrichment budget is set


@dataclass(frozen=True, slots=True)
class IdentityOptions:
    config: IdentityConfig
    seed: IdentitySeed | None = None
    images: bool = False


@dataclass(frozen=True, slots=True)
class Command:
    usernames: tuple[str, ...]
    registry: Path | None
    demo: bool
    output: str
    format: str
    journal: Path
    sites: tuple[str, ...] | None
    categories: tuple[str, ...] | None
    scheduler: SchedulerConfig
    search: SearchOptions
    proxy: str | None
    selection: str = "quality"
    runtime: RuntimePolicy | None = None
    wayback: bool = False
    wayback_budget: int = 20
    wayback_unknown: bool = False
    identity: IdentityOptions | None = None
    health: dict[str, HealthEntry] | None = None
    include_broken: bool = False


def expand_variants(
    inputs: Sequence[str], max_names: int
) -> tuple[tuple[str, ...], dict[str, str]]:
    """Inputs plus generated variants (at most ``max_names`` names per input, the typed one first).

    Returns the names to scan and ``{variant: input it came from}``. A person-style input
    ("Jan Kowalski") is not itself a username, so only its variants are scanned. An input that has
    no valid variant is kept as typed, so the engine reports it as before."""
    explicit = set(inputs)
    names: list[str] = []
    source: dict[str, str] = {}
    for typed in inputs:
        candidates = generate(typed, limit=max_names + 1)
        own = [] if " " in typed.strip() else [typed]
        group = own + [c for c in candidates if c not in (typed, typed.lower())]
        for name in group[:max_names] or [typed]:
            if name in names:
                continue
            names.append(name)
            if name not in explicit:
                source[name] = typed
    return tuple(names), source


async def execute(
    command: Command,
    registry: SiteRegistry,
    transport: Transport,
    journal: ResultJournal,
    wayback_out: dict[str, dict[str, JSONValue]] | None = None,
    avatars: dict[str, AvatarHash] | None = None,
) -> tuple[bool, tuple[str, ...]]:
    failures = False
    jobs: list[str] = []
    async with UsernameEngine(
        registry, transport, config=command.scheduler, sink=journal.append
    ) as engine:
        for username in command.usernames:
            selection = select_services(
                registry,
                username,
                ids=command.sites,
                categories=command.categories,
                mode=command.selection,
            )
            if command.runtime:
                selection = runtime_selection(
                    registry, selection, command.runtime, command.health, command.include_broken
                )
            async for result in engine.search_stream(
                username,
                site_ids=selection.selected,
                options=command.search,
                runtime=command.runtime,
                selection=selection,
            ):
                if result.detection.state not in (ExecutionState.OK, ExecutionState.SKIPPED):
                    failures = True
                if result.profile_metadata.state in (
                    MetadataState.ERROR,
                    MetadataState.TIMEOUT,
                    MetadataState.PARTIAL,
                ):
                    failures = True
                if result.enrichment.state in (ExtractionState.ERROR, ExtractionState.TIMEOUT):
                    failures = True
            job_id = engine.summaries[-1].job_id
            jobs.append(job_id)
            if command.identity is not None and command.identity.images and avatars is not None:
                avatars.update(
                    await fetch_avatar_records(
                        list(journal.read(job_id=job_id)),
                        engine.transport,
                        budget=command.search.enrichment_request_budget or IDENTITY_IMAGE_BUDGET,
                        min_hits=command.identity.config.boilerplate_min_hits,
                    )
                )
        if command.wayback and wayback_out is not None:
            # Archive lookups use the engine's transport and their own budget (a total for the run),
            # so they never consume the search request budget.
            remaining = command.wayback_budget
            for job_id in jobs:
                urls = wayback_targets(journal.read(job_id=job_id), command.wayback_unknown)
                report = await check_wayback(transport, urls, remaining)
                requests = report["requests"]
                remaining -= requests if isinstance(requests, int) else 0
                wayback_out[job_id] = report
        failures = failures or bool(engine.sink_errors)
    return failures, tuple(jobs)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="username-engine", description="Evidence-based username research"
    )
    commands = root.add_subparsers(dest="command", required=True)
    validate = commands.add_parser(
        "validate", help="Validate a local canonical registry without HTTP"
    )
    validate.add_argument("registry", type=Path)
    for name in ("search", "demo"):
        command = commands.add_parser(
            name, help="Offline fixtures" if name == "demo" else "HTTP search"
        )
        command.add_argument("usernames", nargs="+")
        command.add_argument(
            "--registry",
            type=Path,
            default=Path(__file__).resolve().parents[2] / "data" / "catalog.json",
        )
        command.add_argument("--site", action="append")
        command.add_argument("--category", action="append")
        command.add_argument("--output", default=None, help="File path; - writes to stdout")
        command.add_argument("--format", choices=("json", "ndjson", "csv"), default="json")
        command.add_argument("--journal", type=Path)
        command.add_argument("--concurrency", type=int, default=20)
        command.add_argument("--per-origin", type=int, default=2)
        command.add_argument(
            "--per-job",
            type=int,
            default=None,
            help="Concurrent requests of one name (default: --concurrency)",
        )
        command.add_argument("--queue", type=int, default=128)
        command.add_argument("--job-timeout", type=float)
        command.add_argument("--request-budget", type=int)
        command.add_argument("--mode", choices=tuple(MODES), default="normal")
        command.add_argument(
            "--runtime-config",
            type=Path,
            help="JSON RuntimePolicy; explicit CLI ceilings override it",
        )
        command.add_argument("--service-budget", type=int)
        command.add_argument("--retry-budget", type=int)
        command.add_argument("--control-budget", type=int)
        command.add_argument(
            "--no-rescan",
            action="store_true",
            help="Skip the closing pass that retries services which ended in a network error",
        )
        command.add_argument("--proxy")
        command.add_argument("--enrich", choices=("off", "basic", "full"), default="basic")
        command.add_argument("--enrichment-request-budget", type=int)
        command.add_argument("--view", choices=("analyst", "debug"), default="analyst")
        command.add_argument(
            "--only-matches",
            action="store_true",
            help="Filter analyst presentation; full export is preserved",
        )
        command.add_argument("--selection", choices=("quality", "all"), default="quality")
        command.add_argument(
            "--variants",
            action="store_true",
            help="Also scan generated variants of each name (off by default; each is a full scan)",
        )
        command.add_argument(
            "--dorks",
            action="store_true",
            help="List search-engine dork queries in the output document (nothing is sent)",
        )
        command.add_argument(
            "--wayback",
            action="store_true",
            help="Look up matched profile URLs in the Wayback CDX (separate budget)",
        )
        command.add_argument(
            "--wayback-budget",
            type=int,
            default=20,
            help="Wayback CDX requests for the whole run (default 20)",
        )
        command.add_argument(
            "--wayback-unknown",
            action="store_true",
            help="With --wayback, also look up UNKNOWN profiles",
        )
        command.add_argument(
            "--geo",
            action="store_true",
            help="Add a geo section: country clues from matched profiles' metadata (offline)",
        )
        command.add_argument(
            "--geo-gazetteer",
            type=Path,
            help="Optional larger gazetteer JSON ({countries:{}, cities:{}}) for --geo",
        )
        command.add_argument(
            "--html",
            type=Path,
            help="Also write a self-contained HTML report (all names of this run) to this file",
        )
        command.add_argument(
            "--max-variants",
            type=int,
            default=6,
            help="Names scanned per input when --variants is on, the typed one included",
        )
        command.add_argument(
            "--identity",
            action="store_true",
            help="Add an identity section (same person or namesake) to the analyst output",
        )
        command.add_argument("--seed-name", help="Target's real name for --identity")
        command.add_argument(
            "--seed-url", action="append", help="Known account URL of the target (repeatable)"
        )
        command.add_argument(
            "--identity-images",
            action="store_true",
            help="Fetch avatars (5 MB limit, needs Pillow) and compare perceptual hashes",
        )
        command.add_argument(
            "--identity-threshold", type=float, help="TARGET_LIKELY threshold (default 0.5)"
        )
        command.add_argument(
            "--identity-weights", type=Path, help="JSON with IdentityConfig overrides"
        )
        command.add_argument(
            "--health",
            type=Path,
            help="health.json from health-probe; default: next to the registry, if present",
        )
        command.add_argument(
            "--include-broken",
            action="store_true",
            help="Do not skip definitions rated dead, blocked or false_positive",
        )
    default_registry = Path(__file__).resolve().parents[2] / "data" / "catalog.json"
    default_health = default_registry.with_name("health.json")
    probe = commands.add_parser(
        "health-probe", help="Rate definitions: known and random name through the engine"
    )
    probe.add_argument("--registry", type=Path, default=default_registry)
    probe.add_argument("--sites", nargs="+", metavar="ID")
    probe.add_argument("--limit", type=int)
    probe.add_argument("--out", type=Path, default=default_health)
    probe.add_argument("--concurrency", type=int, default=20)
    probe.add_argument("--timeout", type=float, default=45.0)
    probe.add_argument("--proxy")
    probe.add_argument("--merge", action="store_true", help="Keep current ratings not re-probed")
    probe.add_argument(
        "--force",
        action="store_true",
        help="Write even when more than 40%% of the results are dead or blocked",
    )
    passive = commands.add_parser(
        "health-passive", help="Rate definitions from collected results.json files, no requests"
    )
    passive.add_argument("--results", type=Path, nargs="+", required=True)
    passive.add_argument("--out", type=Path, default=default_health)
    passive.add_argument(
        "--merge", action="store_true", help="Probe ratings in --out win; fill the rest"
    )
    passive.add_argument(
        "--force",
        action="store_true",
        help="Write even when more than 40%% of the results are dead or blocked",
    )
    report = commands.add_parser(
        "report", help="Render an HTML report from an existing *.analyst.json (no HTTP)"
    )
    report.add_argument("analyst", type=Path, help="Analyst document written by search/demo")
    report.add_argument(
        "--html", type=Path, help="Output file (default: the analyst file with .html)"
    )
    return root


def write_html_report(path: Path, documents: Sequence[dict[str, JSONValue]]) -> None:
    atomic_write(path, [render_report(documents)])
    print(f"HTML report: {path.resolve()}", file=sys.stderr)


def scheduler_config(arguments: argparse.Namespace) -> SchedulerConfig:
    """One name may use the whole --concurrency (the old fixed per-job cap of 10 idled half of it).

    The per-origin limit is unchanged, so no host gets more requests; job_buffer keeps two
    waves of work admitted so retries waiting for their turn do not starve the free slots.
    """
    per_job = arguments.per_job if arguments.per_job is not None else arguments.concurrency
    return SchedulerConfig(
        arguments.concurrency,
        arguments.per_origin,
        per_job,
        arguments.queue,
        job_buffer=max(SchedulerConfig().job_buffer, 2 * per_job),
    )


def _real_transport(proxy: str | None) -> Transport:
    """The production transport behind the public-egress guard (requests, redirects, avatars,
    Wayback): internal and loopback destinations are refused before a socket is opened."""
    return public_egress_transport(
        AiohttpTransport(HttpConfig(proxy=proxy)), resolve_dns=not proxy
    )


def _refuse_broken_share(rated: dict[str, HealthEntry], force: bool) -> bool:
    """A mass of dead/blocked ratings usually means a bad network or proxy, not a bad catalog."""
    share = broken_share(rated)
    if share <= BROKEN_SHARE_LIMIT or force:
        return False
    print(
        f"Refusing to write health data: {share:.0%} of {len(rated)} results are dead or "
        f"blocked (limit {BROKEN_SHARE_LIMIT:.0%}); check the network/proxy or use --force.",
        file=sys.stderr,
    )
    return True


def _health_probe(arguments: argparse.Namespace) -> int:
    if arguments.limit is not None and arguments.limit < 1:
        raise ValueError("--limit must be positive")
    if arguments.concurrency < 1 or not arguments.timeout > 0:
        raise ValueError("--concurrency and --timeout must be positive")
    registry = prepared_registry(SiteRegistry.from_path(arguments.registry))
    known = {e.id for e in registry.entries}
    ids = sorted(arguments.sites) if arguments.sites else sorted(known)
    unknown = set(ids) - known
    if unknown:
        raise ValueError("Unknown site IDs: " + ",".join(sorted(unknown)))
    if arguments.limit:
        ids = ids[: arguments.limit]
    rated = asyncio.run(
        probe_health(
            registry,
            _real_transport(arguments.proxy),
            ids,
            concurrency=arguments.concurrency,
            job_timeout=arguments.timeout,
        )
    )
    if _refuse_broken_share(rated, arguments.force):
        return 3
    if arguments.merge:
        rated = {**load_health(arguments.out), **rated}
    save_health(arguments.out, rated, source="probe")
    counts = Counter(e.state for e in rated.values())
    print(json.dumps({"sites": len(rated), "states": dict(sorted(counts.items()))}))
    print(f"Health: {arguments.out.resolve()}", file=sys.stderr)
    return 0


def _health_passive(arguments: argparse.Namespace) -> int:
    results: list[SearchResult] = []
    for path in arguments.results:
        values = json.loads(path.read_text(encoding="utf-8-sig"))
        if not isinstance(values, list):
            raise ValueError(f"{path}: expected a JSON array of results")
        results.extend(from_value(SearchResult, value) for value in values)
    rated = passive_health(results)
    if _refuse_broken_share(rated, arguments.force):
        return 3
    if arguments.merge:
        rated = fill_missing(load_health(arguments.out), rated)
    save_health(arguments.out, rated, source="passive")
    counts = Counter(e.state for e in rated.values())
    print(json.dumps({"sites": len(rated), "states": dict(sorted(counts.items()))}))
    print(f"Health: {arguments.out.resolve()}", file=sys.stderr)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "validate":
            registry = SiteRegistry.from_path(arguments.registry)  # with the overlay files
            invalid = [e for e in registry.entries if e.issues]
            print(
                json.dumps(
                    {
                        "records": len(registry.entries),
                        "invalid": len(invalid),
                        "revision": registry.revision,
                    }
                )
            )
            return 2 if invalid else 0
        if arguments.command == "report":
            loaded = json.loads(arguments.analyst.read_text(encoding="utf-8-sig"))
            if not isinstance(loaded, dict) or not isinstance(loaded.get("profiles"), list):
                raise ValueError("Not an analyst document: " + str(arguments.analyst))
            target = arguments.html or arguments.analyst.with_suffix(".html")
            write_html_report(target, [loaded])
            return 0
        if arguments.command == "health-probe":
            return _health_probe(arguments)
        if arguments.command == "health-passive":
            return _health_passive(arguments)
        if arguments.max_variants < 1:
            raise ValueError("--max-variants must be at least 1")
        if arguments.wayback_budget < 0:
            raise ValueError("--wayback-budget must not be negative")
        usernames, variant_source = (
            expand_variants(arguments.usernames, arguments.max_variants)
            if arguments.variants
            else (tuple(arguments.usernames), {})
        )
        gazetteer = Gazetteer(arguments.geo_gazetteer) if arguments.geo else None
        dork_groups: dict[str, list[str]] = {}
        for name in usernames:
            dork_groups.setdefault(variant_source.get(name, name), []).append(name)
        run_id = uuid4().hex
        policy = (
            from_json(RuntimePolicy, arguments.runtime_config.read_text(encoding="utf-8-sig"))
            if arguments.runtime_config
            else MODES[arguments.mode]
        )
        overrides = {
            name: getattr(arguments, flag)
            for name, flag in (
                ("request_budget", "request_budget"),
                ("service_budget", "service_budget"),
                ("retry_budget", "retry_budget"),
                ("control_budget", "control_budget"),
                ("job_timeout", "job_timeout"),
                ("enrichment_budget", "enrichment_request_budget"),
            )
            if getattr(arguments, flag) is not None
        }
        policy = replace(policy, **overrides)
        identity: IdentityOptions | None = None
        if arguments.identity:
            config = (
                IdentityConfig.load(arguments.identity_weights)
                if arguments.identity_weights
                else IdentityConfig()
            )
            if arguments.identity_threshold is not None:
                config = replace(config, threshold=arguments.identity_threshold)
            seed = IdentitySeed(arguments.seed_name or "", tuple(arguments.seed_url or ()))
            identity = IdentityOptions(
                config, None if seed.empty else seed, arguments.identity_images
            )
            if identity.images and not pillow_available():
                print(
                    "Warning: Pillow is not installed; avatar hashes are skipped.", file=sys.stderr
                )
        elif (
            arguments.seed_name
            or arguments.seed_url
            or arguments.identity_images
            or arguments.identity_threshold is not None
            or arguments.identity_weights
        ):
            print("Warning: identity options have no effect without --identity.", file=sys.stderr)
        if arguments.no_rescan:
            policy = replace(policy, rescan_errors=False)
        adaptive = arguments.command == "search" and arguments.selection == "quality"
        if arguments.control_budget is not None and not adaptive:
            print(
                "Warning: --control-budget has no effect without the runtime mode "
                "(search with --selection quality); no control requests will be sent.",
                file=sys.stderr,
            )
        rated: dict[str, HealthEntry] | None = None
        if adaptive and arguments.command == "search":
            health_path = arguments.health or arguments.registry.with_name("health.json")
            try:
                rated = load_health(health_path) or None
            except ValueError as exc:
                if arguments.health:
                    raise  # an explicit --health must be valid: configuration error (2)
                print(
                    f"Warning: ignoring {health_path}: {exc}; running without health ranking.",
                    file=sys.stderr,
                )
                rated = None
        output = arguments.output or str(Path("results") / (run_id + "." + arguments.format))
        journal_path = arguments.journal or Path("results") / (run_id + ".sqlite")
        command = Command(
            usernames,
            arguments.registry,
            arguments.command == "demo",
            output,
            arguments.format,
            journal_path,
            tuple(arguments.site) if arguments.site is not None else None,
            tuple(arguments.category) if arguments.category is not None else None,
            scheduler_config(arguments),
            SearchOptions(
                policy.job_timeout,
                policy.request_budget,
                EnrichmentMode(arguments.enrich),
                policy.enrichment_budget,
            ),
            arguments.proxy,
            arguments.selection,
            policy if adaptive else None,
            arguments.wayback,
            arguments.wayback_budget,
            arguments.wayback_unknown,
            identity,
            rated,
            arguments.include_broken,
        )
        transport: Transport
        if command.demo:
            registry, transport = make_demo()
        else:
            assert command.registry is not None
            registry = SiteRegistry.from_path(command.registry)
            registry = prepared_registry(registry)
            transport = _real_transport(command.proxy)
        if command.sites:
            unknown = set(command.sites) - {e.id for e in registry.entries}
            if unknown:
                raise ValueError("Unknown site IDs: " + ",".join(sorted(unknown)))
        if command.categories and not set(command.categories) <= set(registry.categories):
            raise ValueError("Unknown category")
        print(f"Journal: {journal_path.resolve()}", file=sys.stderr)
        with ResultJournal(journal_path) as journal:
            wayback_reports: dict[str, dict[str, JSONValue]] = {}
            avatar_records: dict[str, AvatarHash] = {}
            documents: list[dict[str, JSONValue]] = []
            failures, jobs = asyncio.run(
                execute(command, registry, transport, journal, wayback_reports, avatar_records)
            )

            def results() -> Iterator[SearchResult]:
                for job_id in jobs:
                    yield from journal.read(job_id=job_id)

            if output == "-":
                chunks = (
                    json_chunks(results())
                    if command.format == "json"
                    else csv_chunks(results())
                    if command.format == "csv"
                    else (to_json(r) + "\n" for r in results())
                )
                for chunk in chunks:
                    sys.stdout.write(chunk)
            else:
                export_results(Path(output), results(), command.format)
                print(f"Output: {Path(output).resolve()}", file=sys.stderr)
            for username, job_id in zip(command.usernames, jobs, strict=True):
                selection = select_services(
                    registry,
                    username,
                    ids=command.sites,
                    categories=command.categories,
                    mode=command.selection,
                )
                if command.runtime:
                    selection = runtime_selection(
                        registry,
                        selection,
                        command.runtime,
                        command.health,
                        command.include_broken,
                    )
                document = analyst_document(
                    journal.read(job_id=job_id),
                    registry,
                    username=username,
                    selection=selection,
                    only_matches=arguments.only_matches,
                )
                if command.runtime:
                    document["request_economy"] = economy(
                        journal.read(job_id=job_id),
                        request_budget=command.search.request_budget,
                        canonical_services=len(selection.services),
                        definitions_considered=selection.compatible,
                    )
                    summary = document.get("summary")
                    stats = document["request_economy"]
                    if isinstance(summary, dict) and isinstance(stats, dict):
                        counts = summary.get("counts")
                        reasons = summary.get("not_tested_reasons")
                        if isinstance(counts, dict):
                            counts["not_tested_selected"] = counts.get("not_tested", 0)
                            counts["not_tested"] = stats["services_not_tested"]
                        if isinstance(reasons, dict):
                            for reason in ("SERVICE_BUDGET", "MODE_QUALITY_THRESHOLD"):
                                reasons[reason] = sum(r == reason for _, r in selection.excluded)
                            skipped = sum(r.startswith("HEALTH_") for _, r in selection.excluded)
                            if skipped:
                                reasons["HEALTH_SKIPPED"] = skipped
                    health = DefinitionHealth(journal_path.parent / "definition-health.sqlite")
                    try:
                        health.record(journal.read(job_id=job_id))
                    finally:
                        health.close()
                group = dork_groups[variant_source.get(username, username)]
                if arguments.dorks and group[0] == username:
                    # one list per input, covering its variants; queries are never sent anywhere
                    document["dorks"] = {"queries": list(build_queries(group)), "sent": False}
                if job_id in wayback_reports:
                    document["wayback"] = wayback_reports[job_id]
                    stats = document.get("request_economy")
                    if isinstance(stats, dict):
                        stats["wayback_requests"] = wayback_reports[job_id]["requests"]
                if gazetteer is not None:
                    document["geo"] = geo_section(
                        sources_from_results(journal.read(job_id=job_id), registry), gazetteer
                    )
                if arguments.variants:
                    document["variants"] = {
                        "is_variant": username in variant_source,
                        "variant_of": variant_source.get(username),
                    }
                document["meta"] = {
                    "mode": arguments.mode if command.runtime else None,
                    "selection": arguments.selection,
                    "generated_at": datetime.now().isoformat(timespec="seconds"),
                }
                documents.append(document)
                if command.identity is not None:
                    hits = list(journal.read(job_id=job_id))
                    names = {
                        r.site_id: entry.definition.name
                        for r in hits
                        if (entry := registry.get(r.site_id)) is not None
                        and entry.definition is not None
                    }
                    document["identity"] = identity_document(
                        score_identities(
                            hits,
                            command.identity.seed,
                            {url: record.phash for url, record in avatar_records.items()},
                            command.identity.config,
                        ),
                        config=command.identity.config,
                        seed=command.identity.seed,
                        site_names=names,
                        avatar_records=avatar_records,
                        images=command.identity.images,
                        results=hits,
                    )
                if arguments.view == "analyst":
                    print(render_console(document), file=sys.stderr, end="")
                else:
                    print(to_json(selection, indent=2), file=sys.stderr)
                    for result in journal.read(job_id=job_id):
                        print(to_json(result), file=sys.stderr)
                    if command.runtime:
                        print(
                            "Request economy: " + to_json(document["request_economy"]),
                            file=sys.stderr,
                        )
                if output != "-":
                    suffix = "" if len(jobs) == 1 else "." + job_id
                    analyst_path = Path(output).with_suffix(suffix + ".analyst.json")
                    atomic_write(analyst_path, [render_analyst(document)])
                    print(f"Analyst output: {analyst_path.resolve()}", file=sys.stderr)
                    atomic_write(
                        Path(output).with_suffix(suffix + ".selection.json"),
                        [to_json(selection, indent=2)],
                    )
            if arguments.html:
                write_html_report(arguments.html, documents)
        return 1 if failures else 0
    except KeyboardInterrupt:
        print("Interrupted; committed observations remain in the journal.", file=sys.stderr)
        return 130
    except (OSError, ValueError) as exc:
        print(f"Configuration/output error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
