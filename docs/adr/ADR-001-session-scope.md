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

Session = one agent run. The proxy issues the session ID at the start of each run and returns it in the `x-agent-run-id` response header; the agent sends it back on every later request of the run. The session ends when it has been idle longer than the TTL. (Originally the client chose the ID; superseded by [ADR-008](ADR-008-proxy-issued-session-ids.md).)

## Consequences

- Taint state is scoped to a single goal → fewer false positives from cross-task bleed.
- The multi-run exfiltration scenario (taint in run 1, sink in run 2) is explicitly **out of scope** per the threat model (ADR-005).
- The agent framework or harness must carry the issued ID between requests; the router cannot derive it from LLM content alone.
