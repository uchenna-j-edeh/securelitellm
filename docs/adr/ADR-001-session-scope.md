# ADR-001: Session Scope — One Agent Run

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-30 |

## Context

An "agent run" is a bounded sequence of LLM calls and tool invocations driven by one user-submitted goal (e.g., "book a flight"). Several scoping options exist:

- **Per-user across chats** — one long-lived session per user identity across all conversations
- **Per-conversation** — one session per chat thread, which may span many agent runs
- **Per-agent-run** — one session from the moment an agent starts working on a goal until it completes or is abandoned

The per-user and per-conversation scopes accumulate state across unrelated tasks, which makes taint attribution noisy: a taint mark from one task bleeds into detection decisions for a completely different task.

## Decision

Session = one agent run. A new session ID is derived from the `x-agent-run-id` request header (or a fallback) at the start of each run and is cleared when the run ends (TTL expiry).

## Consequences

- Taint state is scoped to a single goal → fewer false positives from cross-task bleed.
- The multi-run exfiltration scenario (taint in run 1, sink in run 2) is explicitly **out of scope** per the threat model (ADR-005).
- Session IDs must be injected by the agent framework or harness; the router cannot derive them from LLM content alone.
