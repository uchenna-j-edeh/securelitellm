# Exact-URL matching (#218), 2026-11-08

The destination checks now compare complete URLs, including paths and queries.
This is the exact-matching layer requested after #219/#221, not completion of
the broader egress-provenance issue. See [ADR-010](../adr/ADR-010-exact-url-destinations.md)
for normalization choices and configuration migration.

The initial results below describe the November 8 implementation, before the
four #229 review fixes. See [Review-fix rerun](#review-fix-rerun-2026-11-09) for
the current fragment and scheme-less user-URL behavior. Historical evidence is
preserved unchanged.

## Paired HTTP replay

Baseline: `bce573c` (main including #219, #220 and #221), using the old host
allowlist. Comparison: this change, with exact `/ingest` and `/debug` entries.
Both use session/L3, classifier + allowlist + user_named, seed 0, the same
inputs, the pinned LiteLLM image and the same local DeBERTa revision
`90c9989b1a342275dd0d1a95aad283c04e075671`. All model routes use a local mock;
no email, URL fetch, chat post or other external tool was executed.

| Suite | Scenarios | Benign scenarios | Rows per arm | Changed decisions/outcomes |
|---|---:|---:|---:|---:|
| Existing corpus | 60 | 24 | 86 | 0 |
| AgentDojo Slack | 126 | 21 | 126 | 0 |
| Total | 186 | 45 | 212 | 0 |

There are **424** archived replay rows, no unknown decisions and no proxy HTTP
failures. Input-file hashes match between arms. The comparison covers action,
risk level, route, post action/risk/route, outcome, data class and matched rules;
wall-clock latency is not compared.

The result is **no added benign holds**, not a claim of low false positives.
The original corpus still releases 6/7 generated benign calls and holds one;
AgentDojo Slack already stops 20/21 benign tasks (20 have generated tool calls).
Those existing costs and classifier issues remain. Prior #219/#221 protections
still stop the `get_webpage` attacks; these sets provide limited coverage of
dynamic legitimate URLs.

An initial environment pilot used an outdated local mock image that did not
generate scripted calls. It was excluded, not credited as prevention. Both
final arms mount the repository's current mock source, and each replay first
requires a harmless scripted-generation canary to succeed. Original pilot
artifacts were retained locally for debugging, outside the reported results.

## Generated URL mutation probes

Eleven frozen synthetic cases test actual proxy pre/post hooks using a scripted
`get_webpage` response. `released` means the client received a tool call, not
that any network request was executed.

| Case | Baseline | Exact URLs |
|---|---|---|
| Exact `/ingest`, normalized equivalent, exact `/debug` (3 cases) | released | released |
| Added query, changed path, path extension, changed scheme, changed port (5 cases) | released | held |
| Malformed URL with a space (1 case) | released as a read | held |
| Unlisted host (1 case) | held | held |
| Legitimate explicit `?page=2` request, absent from configured endpoints (1 case) | released | held |

The last row is a deliberate cost: a user-typed URL must still pass the enabled
allowlist. Dynamic endpoints need explicit policy entries or a later approval
flow; the implementation adds no host wildcard or prefix exception. These few
probes measure behavior, not a population false-positive rate. They do not
address secrets in POST bodies or misleading text replies.

## Demo audit and validation

- Beat 1's actual URL is `https://httpbin.org/html`; the generated demo policy
  now lists that exact URL. A regression verifies the page passes and an added
  query fails.
- The corpus needs `https://reports.example.com/ingest` and `/debug` (including
  benign GitHub control bn-062). Both are explicitly listed and regression-tested.
- Other work beats use message IDs, Jira keys or GitHub issue numbers, not
  outbound URL arguments; their corpus replays are included in the 60-case suite.
- Existing private demo policies must be regenerated; see ADR-010. No live
  account authorization or real email rehearsal was performed for this change.
- Unit coverage includes exact-query ordering/multiplicity, reserved escapes,
  path case and trailing slash, ports/schemes, user-info tricks, malformed URLs,
  prose/backtick punctuation, own destinations, addresses inside URL queries,
  dotted email local parts, pre-call quarantine, generated-call holds and
  host-only refusal evidence. Malformed URL arguments still reach authorization
  instead of being misclassified as reads.
- 1,020 non-E2E tests pass; the optional AgentDojo-import test is skipped in the
  main environment. Ruff lint and formatting pass. CI supplies the E2E check.

## Review-fix rerun, 2026-11-09

PR #229 had already been squash-merged as `457f727` without the requested
review fixes. The follow-up includes reviewer commit `717b8e2` and compares
that merged main tree with the corrected router. ADR-010 now documents all
four findings: safe refusal labels, host-like read arguments failing closed,
scheme-less user URLs naming both HTTP and HTTPS, and exact fragment matching.

The same 60 core and 126 AgentDojo Slack scenarios produce **424 paired replay
rows**, with no changes across the nine fields above, no unknown decisions or
HTTP failures, identical input hashes and successful mock-generation canaries.
This preserves the existing benign holds; it does not establish a low false
positive rate. No external tools execute.

All 11 original probe inputs, including their historical expectation fields,
are preserved byte for byte. Ten results are unchanged. The frozen
`normalized-equivalent` URL
`https://REPORTS.example.com:443/a/../%69ngest#section` changes from released
to held: the appended fragment no longer matches the authorized `/ingest`.
The rerun verifier applies that one explicit expectation change rather than
rewriting the original fixture.

Four additional paired HTTP probes confirm:

| Case | Merged #229 | With review fixes |
|---|---|---|
| Same normalized URL without `#section` | released | released |
| Synthetic free argument text | held, argument text in evidence | held, `(unparseable url)` only |
| Scheme-less user URL, generated HTTPS | held | released |
| User explicitly typed HTTP, generated HTTPS | held | held |

The privacy regression also checks complete decision logs for the absence of
the synthetic argument marker with allowlist, user_named, and both controls.
**1,037 non-E2E tests pass**, one optional AgentDojo test is skipped, and Ruff
lint/format pass. CI supplies the cross-platform and E2E checks.

Evidence and a service-free verifier are in
[`data/exact-url-review-2026-11-09/`](data/exact-url-review-2026-11-09/summary.json).
To reproduce, use the isolated stack below with `git archive 457f727` instead
of `bce573c` for the baseline, and use new runtime/output directories. Run the
rerun directory's `probe.py` for the frozen inputs and again with
`--probes docs/results/data/exact-url-review-2026-11-09/review-probes.json`.
Run the original `replay.py` for each arm, then run
`python docs/results/data/exact-url-review-2026-11-09/verify.py` to verify the
archived results without starting any services. The older summary and
checksums continue to describe the initial November 8 run.

## Reproduction

Raw CSVs, per-arm input hashes, URL probe inputs/results, mock config, paired
Compose file and runnable replay/probe scripts are in
[`data/exact-url-2026-11-08/`](data/exact-url-2026-11-08/summary.json).
Use an independent stack and new result filenames. The regular demo is not
restarted by this procedure.

```sh
export EXACT218_REPO="$PWD"
export EXACT218_BASELINE=/private/tmp/exact218-baseline
export EXACT218_RUNTIME=/private/tmp/exact218-runtime
mkdir -p "$EXACT218_BASELINE" "$EXACT218_RUNTIME/baseline/logs" "$EXACT218_RUNTIME/exact/logs"
git archive bce573c router deploy/policy.yaml | tar -x -C "$EXACT218_BASELINE"

# Existing local DeBERTa service is required at port 8080.
# Reuse a compatible mock image; its current source is mounted by Compose.
# If needed: docker build -t securelitellm-exact218-mock-base deploy/mock_model
# export EXACT218_MOCK_IMAGE=securelitellm-exact218-mock-base
docker compose -p securelitellm-exact218 \
  -f docs/results/data/exact-url-2026-11-08/compose.yaml up -d

# AgentDojo is isolated from application dependencies.
uv run --no-project --python 3.12 --with agentdojo==0.1.35 \
  python scripts/import_agentdojo.py --suite slack --out-root /private/tmp/exact218-corpus

python docs/results/data/exact-url-2026-11-08/replay.py \
  --proxy http://localhost:14020 --decision-log "$EXACT218_RUNTIME/baseline/logs/decisions.jsonl" \
  --suite core=corpus/scenarios --suite agentdojo-slack=/private/tmp/exact218-corpus/agentdojo-slack \
  --output /private/tmp/new-url-baseline.csv
python docs/results/data/exact-url-2026-11-08/replay.py \
  --proxy http://localhost:14021 --decision-log "$EXACT218_RUNTIME/exact/logs/decisions.jsonl" \
  --suite core=corpus/scenarios --suite agentdojo-slack=/private/tmp/exact218-corpus/agentdojo-slack \
  --output /private/tmp/new-url-exact.csv
```

Run `probe.py` with the corresponding `--proxy`, `--decision-log` and a new
`--output` for each arm. Inspect `summary.json` and each `*.manifest.json` for
coverage/environment details. Stop only this test stack with the same Compose
file and `down`. These replay/probe helpers accept only local proxy addresses
and never execute the tools in a model's response.
