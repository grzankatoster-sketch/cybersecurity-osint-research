# Detection evidence model (2026-10-09)

> English translation of [`EVIDENCE_MODEL.md`](../../EVIDENCE_MODEL.md) (Polish original, kept alongside). The text up to the "Translator's status notes" heading is a faithful translation of the original; the notes at the end were added during translation and compare the document with the code in this repository. Module, field and enum names are unchanged.

A result confirms a public profile under the given username. It does not confirm the identity of a person, or that accounts on several platforms belong to the same person.

## Order and conditions

`TransportResponse → response_quality / classify_response → detection rules → owner binding → enrichment → export`

The existing failure gate was extended. The new module `response_quality.py` also provides parsers of profiles that are limited to specific endpoints. It performs no HTTP requests and no JavaScript.

1. Transport errors, an incomplete response, 401/403/429/5xx, a challenge and a login page all rule out a positive result. `verdict=UNKNOWN` coexists with an execution state, for example `BLOCKED`.
2. A generic page, a search page, a redirect to a homepage or to a parking page, and a wrong owner are not profiles. The response class is a separate field, `response_class`; it must not be added to the verdicts as if they were disjoint categories.
3. The narrow parsers of verified endpoints require a matching request address and response, HTTP 200, a complete body and owner data. They are a deliberate correction of weak donor rules. They do not scan arbitrary JSON objects recursively looking for a matching username.
4. For the remaining definitions a positive/negative conflict gives `UNKNOWN`. A declared but unmet binding blocks a positive result. Positive content evidence together with a satisfied binding allows `FOUND`.
5. `PROBABLE` requires a positive rule and a profile signal: a matching root username/login together with a profile field in JSON, or a positive message/regex that points to a profile/member/player/nickname/account. This is still a heuristic that needs verification. An HTTP 200 alone, or the mere absence of an error message, is not enough.
6. Evidence of non-existence keeps `NOT_FOUND` only with negative content or a verified negative rule. Rejected candidates are not automatically turned into non-existent accounts.

## Explicit levels

| Level | Strength | Meaning and outcome |
| --- | --- | --- |
| 4 | STRONG | Profile object, username, account identifier and a matching endpoint; FOUND |
| 3 | STRONG | Profile content and an explicit binding; FOUND. Pinterest: author URL + a valid profile oEmbed, without an account ID |
| 2 | MODERATE | A profile signal without a strong binding; PROBABLE |
| 1 | WEAK | A weak positive rule without a profile signal; UNKNOWN |
| 0 | INSUFFICIENT | No evidence, a conflict, a block, or a response that is not a profile |

`confidence.value` remains `null`. Strength and evidence_level describe criteria, not probability. For legacy negatives `COMPOSITE` was kept; their level 0 does not measure certainty of non-existence. Errors may keep an older message about the missing model — no ML model has been added.

Existing content + binding rules also receive level 3 when they have an additional account identifier, as the GitHub adapter does. Level 4 is assigned by the new, explicitly supported profile-object parsers. This number should not be treated as a comparative rating of the reliability of platforms.

## Parser scope

| Service | Evidence that binds the profile | Additional restriction |
| --- | --- | --- |
| GitHub | login + positive ID + html_url | The previously verified GitHub adapter |
| Kick | slug + user.username + user.id = user_id | Positive int; a channel ID is not a user ID |
| Chess | username + player_id + @id + public URL | Casefold only for the supported endpoint |
| FACEIT | result=OK + payload.nickname + payload.id | ID in UUID format |
| GOG | explicit window.profilesData.profileUser + username + userId | JSONDecoder without executing JS; positive numeric ID, at most 32 characters |
| Pinterest | author_url + provider + type + author_name + iframe grid | Only the official oEmbed that points exactly at the profile; level 3 |

Anubis markers require the structure of the challenge script and a matching title. An article about Anubis alone is not a block. A WAF may signal a challenge with a header even when the body of an HTTP 202 is empty. A "login" link in a menu is not sufficient to classify a page as a login page.

## Metadata and images

Enrichment re-checks the response class and the binding. Fields are taken from the proper profile object, with provenance and a quality rating. Contradictory fields do not enter the set of usable data. Service metadata, Organization data, an OG preview and the content of another user are not data of the profile owner.

`VERIFIED_PROFILE_IMAGES.json` contains only URLs connected with confirmed profiles. GOG may use a predefined background; an avatar may be a default one. No images were downloaded, no face recognition was performed and no person's identity was established.

## Scoring and maintenance of definitions

The runtime `technical_quality`, which returns a SiteQualityScore, lowers the score of status-only definitions by 25, rewards a supported endpoint with a binding by 30, and subtracts 20 for an explicit NEEDS_RULE_FIX. These are structural criteria; they are neither a historical error rate nor a measure of popularity.

The versioned overlay `detection-quality-v1` marks 10 definitions from 7 services as NEEDS_RULE_FIX and disables 4 definitions of 2 parking services as QUARANTINE. The full list: `artifacts/detection-quality/definition-overlays.json`. The reason is recognised content and wrong profile routes, not a single timeout. Services that block bots are not quarantined for that reason. The donor, the original catalogue and the earlier Twitch quarantine are preserved. Leaving quarantine requires a correct route and profile tests, together with a negative check.

The classifier covers recognised patterns, not all pages on the internet. Calibration tests are not evidence of global precision or recall.

## Translator's status notes

These notes are not part of the original. They were checked against the code of this repository.

- **Files not published.** `VERIFIED_PROFILE_IMAGES.json`, `artifacts/detection-quality/definition-overlays.json` and the other `artifacts/` files cited here are not part of the published tree. The counts of definitions and services in the last two sections refer to the catalogue that is not shipped (see the main README, "Rebuilding the catalogue").
- **Level 4 in code.** The verdict resolver in `detection.py` itself assigns evidence level 3 (content + binding, `FOUND`), level 2 (`PROBABLE`) and level 1 (weak status-only definitions). Level 4 comes from the profile-object parsers in `response_quality.py` / `profile_adapters.py`, as the document states.
- **`technical_quality`** is implemented in `runtime_policy.py` (`WEAK_STATUS_ONLY_DEFINITION` −25, `REVIEWED_SCOPED_OWNER_ADAPTER` +30, `REVIEWED_RULE_FIX_REQUIRED` −20, plus further components such as `NO_POSITIVE_RULE` −20 and `INDEX_EVIDENCE_ONLY` −30 that are described in `BUDGET_ARCHITECTURE`).
- **Control requests** (a later addition, see `control.py`) are not described in this 2026-10-09 document. They can turn some `UNKNOWN` results into `PROBABLE`, `FOUND` or `NOT_FOUND` by comparing the real response with the response for a random control name. Discrepancy with the table above: in `control.py` (`_decide_a`) a control-derived `FOUND` is emitted with `strength=MODERATE` and `evidence_level=2`, whereas the table maps level 2 to `PROBABLE`. Consumers should therefore not infer the verdict from `evidence_level` alone; the reason code (for example `CONTROL_DIFFERS_STRONG`) identifies the path.
