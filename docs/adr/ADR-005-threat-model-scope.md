# ADR-005: Threat Model Scope

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-30 |

## Context

LLM injection attacks span a wide surface. Attempting to detect all variants in one project risks shallow coverage of each. The project needs a clear scope so the corpus and metrics are coherent.

## Decision

**In scope:** Indirect / content-borne prompt injection delivered via tool outputs, MCP server responses, or retrieved documents, where the injected instruction subsequently drives an exfiltration action via a sink tool.

**Out of scope:**
- Direct user prompt injection (human user is trusted)
- Model weight poisoning / training-time attacks
- Side-channel / timing attacks
- Cross-run exfiltration (taint in agent run N triggers sink in agent run N+1)
- Denial-of-service against the router itself

## Consequences

- The corpus is restricted to multi-step injection → exfiltration chains where both source and sink occur within a single agent run.
- The "human user is trusted" assumption simplifies the feature extraction (user messages are not treated as taint sources) but would need revisiting for adversarial user scenarios.
- Cross-run attacks are a natural extension for future work and should be noted in the paper.
