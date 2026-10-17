# ADR-008: Proxy-Issued Session IDs

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-10-17 |
| **Issues** | #145 (A1), #146 (A2), #147 (A4) |

## Context

Session-mode taint tracking keys all state on the session ID. Originally the
client chose that ID (`x-agent-run-id`), with a per-request fallback when the
header was missing. That broke three ways:

- **A1 (#145):** the ID was an unauthenticated label. Any caller could pick a
  new ID to shed taint, or present another run's ID.
- **A2 (#146):** a missing header silently gave every request a fresh, clean
  session — session mode degraded to stateless with no record.
- Client-chosen IDs such as `demo-1a2b3c4d` (32 bits) or `sc-010-s0` (none)
  fail every standard for session identifiers.

NIST SP 800-63B (session management) requires session secrets to be generated
by the server with an approved random bit generator, carry at least 64 bits of
entropy, travel only over authenticated protected channels, and be invalidated
on timeout or logout. The OWASP Session Management Cheat Sheet likewise requires
at least 64 bits of entropy from a CSPRNG and unique IDs.

## Decision

The proxy issues session IDs; the session contract is enforced on every request
in both routing modes.

1. **Issue.** A request without `x-agent-run-id` starts a session. The proxy
   generates `secrets.token_urlsafe(32)` — 256 bits from the OS CSPRNG — and
   returns it once, in the `x-agent-run-id` response header
   (`async_post_call_response_headers_hook`).
2. **Session-start rule.** A session-start request may contain only `system`,
   `developer`, and `user` messages. Assistant turns, tool calls, or tool
   results mean a run already in progress; starting a fresh session there would
   shed its taint, so it is rejected.
3. **Validate.** Every later request must present an ID that is well formed
   (exactly 43 base64url characters), was issued by this proxy, has not expired
   (#147: 30 min idle), and belongs to the same API key. Anything
   else is rejected with HTTP 400. Nothing is ever silently recreated.
4. **Never store or log the raw ID.** The store is keyed by `SHA-256(id)`.
   Decision records carry `session_ref`, a 16-hex-character prefix of that hash.
   Violations log the reason (`session_malformed`, `session_unknown`,
   `session_expired`, `session_owner_mismatch`, `session_start_with_history`),
   never the presented value.
5. **Audit mode** (`ROUTER_ENFORCE=false`) logs a violation and continues the
   request in a newly issued session.

## Consequences

- Clients can no longer forge, guess, or reuse session IDs, and cannot shed
  taint by dropping or changing the header mid-run.
- Every client must read the issued ID from the first response and send it
  back: the demo agent, the eval harness (which first opens each scenario's
  session with its leading user message, as a real agent's first request
  would), and the e2e tests were updated.
- Owner binding uses LiteLLM's hashed API key. It only separates agents once
  each has its own virtual key (#148); today all callers share the master key.
- The store is still in memory: a proxy restart forgets every session, so
  in-flight runs are rejected as unknown and must start over — fail-closed.
  Persistence (Postgres, with a cache in front) is #169.
- Measured overhead: ~2 µs to issue an ID, ~1 µs per request to hash, look up,
  and check the owner — negligible next to the classifier call.
- The proxy must be served over TLS in deployment, as NIST requires for
  session secrets in transit.
