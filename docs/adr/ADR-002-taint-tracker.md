# ADR-002: Session State — Lightweight Source/Sink Taint Tracker

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-30 |

## Context

Two broad approaches to session-aware detection:

1. **Full history pooling** — store the entire message history; run classifiers or LLM judges over the full context each turn.
2. **Source/sink taint tracking** — store only which sources have been seen and whether a sink has been requested; optionally store hashes of tainted content spans.

Full history pooling is accurate but expensive: latency and token cost grow linearly with turn count, and running an LLM judge per turn is impractical at eval scale.

## Decision

Session state is a lightweight source/sink taint tracker:

- Mark the session **tainted** when a tool result from an untrusted source enters the context.
- Record the source identity and trust tier (L1).
- Optionally store content hashes + raw spans of tainted content (needed for L3 correlation).
- Do **not** store full message history.

## Consequences

- O(1) state size per session regardless of turn count (except for tainted span storage at L3).
- Cannot answer "what exactly did the tainted content say?" without the stored spans.
- Paraphrase evasion (attacker rephrases exfil content) is a known limitation, documented as a threat to validity in the paper.
