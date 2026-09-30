# ADR-003: Classifiers — Off-the-Shelf Only (No Training)

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-30 |

## Context

The research question is about **routing architecture** (session-aware vs. stateless), not about building a better classifier. Training custom classifiers would introduce a confound: improvements in detection rate might reflect better classification rather than better routing context.

Candidate classifiers: Meta PromptGuard 2 (transformer-based injection detector), LLM Guard (rule + model ensemble), custom fine-tune.

## Decision

Use off-the-shelf classifiers only — PromptGuard 2 and LLM Guard — with no fine-tuning or re-training. Both are integrated behind a common adapter interface so they can be swapped or ablated independently.

## Consequences

- Classifier performance is fixed; any detection delta between L0/L1 and L2/L3 is attributable to routing context richness, not classifier quality.
- PromptGuard 2 requires a CPU-feasible model variant to stay within latency budget; document the chosen variant.
- Off-the-shelf classifiers may drift between versions; eval must pin classifier versions.
