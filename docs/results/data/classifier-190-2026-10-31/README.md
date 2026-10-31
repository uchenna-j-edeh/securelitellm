# #190 scoring evidence

See [findings and reproduction](../../classifier-reliability.md).

| File stem | Suite | Strategies | Observation rows | Role |
| --- | --- | --- | --- | --- |
| `deberta` | core 116 | raw/current/visible-html/base64-decoded/chunks | 580 | Final local core run, exact window-coverage assertions |
| `promptguard` | core 116 | raw/current/base64-decoded | 348 | Includes 42 strategy-level HTTP 400 observations (14 unique long inputs) |
| `qwen-judge` | core 116 | raw/current/base64-decoded | 348 | Original run, 18 strategy-level HTTP 429 observations (6 unique inputs) |
| `qwen-judge-retry` | core 116 | raw/current/base64-decoded | 348 | Reuses original successes; retries only transient failures with 35-second minimum request interval |
| `deberta-length` | follow-up 16 | current/chunks | 32 | Natural prose, token coverage and dilution |
| `promptguard-length` | follow-up 16 | current | 16 | Includes 7 long-input HTTP 400 observations |
| `qwen-judge-length` | follow-up 16 | current | 16 | 15-second minimum request interval |

Every `.jsonl` begins with a manifest, then one observation per (probe, strategy).
The sidecar's predicted-label confidence is not stored as attack probability:
local inference computes P(INJECTION) from the two logits; Prompt Guard's numeric
response already is P(INJECTION). The judge has only a label.

Sibling `.summary.json` files contain the exact result-file SHA-256, rates by
format/group/split/position, diagnostic threshold sweeps where probabilities
exist, and score ranges. Error counts are separate from scored denominators.
`audit.json` records structural verification; `SHA256SUMS` covers corpus, scripts,
tests, write-up and archived evidence (excluding itself). Recheck with
`shasum -a 256 -c docs/results/data/classifier-190-2026-10-31/SHA256SUMS` from the
repository root.

`service-parity.json` checks six representative raw inputs against the existing
HTTP classifier, including a benign field-list card, prose equivalent, metadata,
base64 and a truncated long input. All labels match and attack probabilities
agree within 0.00001. The running demo/classifier services were not reconfigured.

## Scoring source versions

Manifest hashes identify the precise scoring source used at launch. During the
study, only the local tokenizer API/coverage checks and retry/pacing validation
were refined; hosted request semantics and the judge prompt were unchanged.
The first local compatibility pilot produced errors and is not a scored model
experiment. No corpus wording or production threshold was tuned to those errors.

To recover an earlier runner in a **throwaway copy**, apply the matching
`source-<first 12 hash characters>.patch` to the checked-in
`eval/classifier_reliability.py`; its SHA-256 must equal the manifest's full
`source_sha256`. Each patch is relative to the checked-in runner, not to another
patch. This preserves the exact source behind older hosted/local observations
without overwriting any original result. Later source changes add only stricter
retry configuration checks and nonnegative pacing validation.

The pinned local model revision, Python/library versions, normalization-source
hash and exact input hashes are in the manifests. Local image used:
`sha256:3f309dc6b229d6ea5370c8367e37196d2aae5ea8c0dc24841424d018717af2fd`.
This is a local image ID, not a published registry digest. Rebuilding an unpinned
Dockerfile may change library versions; compare the recorded environment.

Hosted model weight revisions are provider-unexposed. Returned model IDs and
fingerprints are diagnostic provenance; they cannot guarantee future identical
results. The public primary model/API references are linked in the write-up.
The study sends only synthetic samples to the hosted endpoints, not private
account configuration or real customer reports.
