# ADR-007: Context-Richness Levels L0–L3 (Independent Variable)

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-30 |

## Context

The central independent variable of the experiment is how much context the routing policy is allowed to read when making a decision. More context should improve detection accuracy but increases latency and cost. Defining these levels precisely ensures the A/B evaluation is comparing well-specified conditions.

## Decision

Four levels are defined. At each level the policy may **only** read the features listed — no higher-level features may leak into a lower-level policy evaluation (enforced by the policy engine).

| Level | Features available to policy | Config key |
|---|---|---|
| **L0** | `untrusted_seen` (bool) — any untrusted source output has entered context this session; `sink_requested` (bool) — a sink-capable tool call is in the current request | `level: L0` |
| **L1** | L0 + `source_ids` (list of tool/MCP server names that contributed tainted content); `source_trust_tiers` (mapping source_id → tier: untrusted \| low \| medium) | `level: L1` |
| **L2** | L1 + `classifier_verdicts` (mapping source_id → {score: float, label: clean\|injection, latency_ms: int}) for each tainted source | `level: L2` |
| **L3** | L2 + `tainted_spans_in_sink_args` (bool) — normalized tainted content appears verbatim or near-verbatim in the current sink tool arguments; `correlation_method` (exact \| ngram) | `level: L3` |

### Feature toggling

Levels are set via `ROUTER_LEVEL` env var or `level:` key in `litellm_config.yaml`. The policy engine validates that rules only reference features permitted at the active level; referencing a higher-level feature raises a configuration error at startup.

### Stateless mode

In stateless mode (`mode: stateless`) session memory is disabled. L0 and L1 features are computed from the single request only (no cross-turn accumulation). L2 and L3 are computed from the current request's content only, with no session taint context.

## Consequences

- L0/L1 require only the session store — no classifier calls.
- L2 adds classifier latency per tainted source (cached by content hash within a session).
- L3 adds a string-matching pass over the current request's tool arguments.
- Each level is a strict superset of the previous, so a policy valid at L0 is valid at all levels.
- Paraphrase evasion defeats L3 correlation; this is a documented threat to validity.
