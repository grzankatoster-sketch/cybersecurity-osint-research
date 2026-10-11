"""Pure parsers with provenance, executed in killable bounded child processes."""

from __future__ import annotations

import asyncio
import json
import math
import multiprocessing
from collections.abc import Callable
from dataclasses import dataclass
from html.parser import HTMLParser
from multiprocessing.connection import Connection
from time import monotonic
from urllib.parse import unquote, urlsplit

import regex

from ultimate_username.detection import ResponseView
from ultimate_username.domain.json_types import json_value, parse_json
from ultimate_username.domain.models import (
    ErrorCode,
    ExtractionResult,
    ExtractionRule,
    ExtractionState,
    FieldObservation,
    JSONValue,
    SearchError,
    TransportResponse,
)


def at_path(value: JSONValue, path: tuple[str, ...]) -> JSONValue:
    for part in path:
        if isinstance(value, dict):
            value = value[part]
        elif isinstance(value, list) and part.isdigit():
            value = value[int(part)]
        else:
            raise KeyError(part)
    return value


class ProfileHTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.metadata: dict[str, str] = {}
        self.canonical = ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = dict(attrs)
        if tag == "meta" and data.get("property") and data.get("content") is not None:
            self.metadata[data["property"] or ""] = data["content"] or ""
        if tag == "link" and data.get("rel") == "canonical":
            self.canonical = data.get("href") or ""


def profile_html(text: str, url: str, username: str, strategy: str) -> JSONValue:
    parser = ProfileHTML()
    parser.feed(text)
    canonical = parser.canonical or parser.metadata.get("og:url", "")
    if not canonical or urlsplit(canonical).hostname != urlsplit(url).hostname:
        return None
    path = unquote(urlsplit(canonical).path)
    if strategy == "discourse":
        match = regex.fullmatch(r"/u/([^/]+)(?:/summary)?/?", path)
        if not match or match.group(1) != username:
            return None
        if not (parser.metadata.get("og:description") or parser.metadata.get("og:image")):
            return None
        return {
            "username": username,
            "bio": parser.metadata.get("og:description"),
            "image": parser.metadata.get("og:image"),
        }
    match = regex.fullmatch(r"/members/([^/]+)\.(\d+)/?", path)
    if not match or match.group(1) != username:
        return None
    return {
        "username": username,
        "uid": match.group(2),
        "bio": parser.metadata.get("og:description"),
        "image": parser.metadata.get("og:image"),
    }


def patreon_bootstrap(text: str) -> JSONValue:
    chunks = regex.findall(r'self\.__next_f\.push\(\[1,("(?:[^"\\]|\\.)*")\]\)', text, timeout=0.05)
    decoded = [parse_json(c) for c in chunks]
    stream = "".join(c for c in decoded if isinstance(c, str))
    marker = regex.search(r'"pageBootstrap"\s*:\s*', stream, timeout=0.05)
    if not marker:
        return None
    # raw_decode identifies a single balanced JSON value without executing JS.
    value, _ = json.JSONDecoder().raw_decode(stream[marker.end() :])
    data = json_value(value)
    raw = stream.encode("utf-8")

    def resolve(item: JSONValue, depth: int = 0) -> JSONValue:
        if depth > 32:
            raise ValueError("RSC nesting limit")
        if isinstance(item, str) and regex.fullmatch(r"\$[0-9a-f]+", item):
            row = regex.search(
                rb"(?:^|\n)" + item[1:].encode() + rb":T([0-9a-f]+),", raw, timeout=0.05
            )
            if row:
                length = int(row.group(1), 16)
                end = row.end() + length
                if end > len(raw):
                    raise ValueError("Truncated RSC reference")
                return raw[row.end() : end].decode("utf-8", errors="strict")
        if isinstance(item, list):
            return [resolve(v, depth + 1) for v in item]
        if isinstance(item, dict):
            return {k: resolve(v, depth + 1) for k, v in item.items()}
        return item

    return resolve(data)


def extract(
    response: TransportResponse,
    username: str,
    rules: tuple[ExtractionRule, ...],
    *,
    max_fields: int = 64,
    max_value_bytes: int = 16384,
) -> ExtractionResult:
    view = ResponseView(response)
    values: list[FieldObservation] = []
    errors: list[SearchError] = []
    parsed: dict[str, JSONValue] = {}
    source = response.final_url or response.requested_url
    for rule in rules[:max_fields]:
        if rule.expected_host and urlsplit(source).hostname != rule.expected_host:
            continue
        try:
            relation = "UNVERIFIED"
            if view.parse_error:
                raise ValueError("Invalid text encoding")
            if rule.strategy == "regex":
                match = regex.search(rule.pattern, view.text, timeout=0.05)
                value: JSONValue = match.group(rule.group) if match else None
            else:
                if rule.strategy not in parsed:
                    if rule.strategy == "json":
                        parsed[rule.strategy] = view.json()
                        if view.json_error:
                            raise ValueError("Malformed JSON")
                    elif rule.strategy in ("discourse", "xenforo"):
                        parsed[rule.strategy] = profile_html(
                            view.text, source, username, rule.strategy
                        )
                    elif rule.strategy == "patreon_rsc":
                        parsed[rule.strategy] = patreon_bootstrap(view.text)
                    else:
                        raise ValueError("Unsupported extractor")
                document = parsed[rule.strategy]
                if rule.owner_path and at_path(document, rule.owner_path) != username:
                    continue
                if rule.owner_path or rule.strategy in ("discourse", "xenforo"):
                    relation = "OWNER"
                value = at_path(document, rule.path)
                if rule.item_path and isinstance(value, list):
                    value = [at_path(item, rule.item_path) for item in value]
            if value is None:
                continue
            if rule.prefix:
                if not isinstance(value, str):
                    raise ValueError("Prefix requires string")
                value = rule.prefix + value
            encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
            if len(encoded.encode("utf-8")) > max_value_bytes:
                raise ValueError("Extracted field limit exceeded")
            values.append(
                FieldObservation(
                    rule.name,
                    encoded,
                    source,
                    rule.strategy,
                    "/".join(rule.path),
                    relation=relation,
                )
            )
        except KeyError:
            continue  # absent field, not malformed document
        except (
            ValueError,
            TypeError,
            IndexError,
            TimeoutError,
            RecursionError,
            regex.error,
        ) as exc:
            errors.append(
                SearchError(
                    ErrorCode.PARSE_ERROR, "extraction", f"{rule.name}: {type(exc).__name__}"
                )
            )
    if len(rules) > max_fields:
        errors.append(SearchError(ErrorCode.PARSE_ERROR, "extraction", "Extractor count limit"))
    state = (
        ExtractionState.PARTIAL
        if values and errors
        else ExtractionState.ERROR
        if errors
        else ExtractionState.SUCCESS
        if values
        else ExtractionState.EMPTY
    )
    return ExtractionResult(state, tuple(values), tuple(errors))


def _worker(
    connection: Connection,
    response: TransportResponse,
    username: str,
    rules: tuple[ExtractionRule, ...],
) -> None:
    try:
        connection.send(extract(response, username, rules))
    finally:
        connection.close()


@dataclass(frozen=True, slots=True)
class ExtractionConfig:
    workers: int = 2
    timeout: float = 3
    body_limit: int = 1048576

    def __post_init__(self) -> None:
        if (
            self.workers < 1
            or not math.isfinite(self.timeout)
            or self.timeout <= 0
            or self.body_limit < 1
        ):
            raise ValueError("Invalid extraction budgets")


Worker = Callable[[Connection, TransportResponse, str, tuple[ExtractionRule, ...]], None]


class ExtractionService:
    def __init__(self, config: ExtractionConfig | None = None, *, worker: Worker = _worker) -> None:
        self.config = config or ExtractionConfig()
        self._semaphore = asyncio.Semaphore(self.config.workers)
        self._worker = worker
        self.active = 0
        self.peak_active = 0

    async def run(
        self, response: TransportResponse, username: str, rules: tuple[ExtractionRule, ...]
    ) -> ExtractionResult:
        if len(response.body) > self.config.body_limit:
            return ExtractionResult(
                ExtractionState.ERROR,
                errors=(SearchError(ErrorCode.BODY_LIMIT, "extraction", "Extraction body limit"),),
            )
        async with self._semaphore:
            context = multiprocessing.get_context("spawn")
            receiving, sending = context.Pipe(duplex=False)
            process = context.Process(
                target=self._worker, args=(sending, response, username, rules), daemon=True
            )
            self.active += 1
            self.peak_active = max(self.peak_active, self.active)
            try:
                process.start()
                sending.close()
                deadline = monotonic() + self.config.timeout
                while monotonic() < deadline:
                    if receiving.poll():
                        result: object = receiving.recv()
                        if not isinstance(result, ExtractionResult):
                            raise ValueError("Invalid worker result")
                        return result
                    if not process.is_alive():
                        raise ValueError("Extractor exited without result")
                    await asyncio.sleep(0.005)
                return ExtractionResult(
                    ExtractionState.TIMEOUT,
                    errors=(
                        SearchError(
                            ErrorCode.ATTEMPT_TIMEOUT,
                            "extraction",
                            "Parser process deadline exceeded",
                        ),
                    ),
                )
            except (ValueError, OSError, EOFError) as exc:
                return ExtractionResult(
                    ExtractionState.ERROR,
                    errors=(SearchError(ErrorCode.PARSE_ERROR, "extraction", type(exc).__name__),),
                )
            finally:
                if process.pid is not None:
                    if process.is_alive():
                        process.terminate()
                    process.join(timeout=0.5)
                    if process.is_alive():
                        process.kill()
                        process.join()
                    process.close()
                receiving.close()
                sending.close()
                self.active -= 1
