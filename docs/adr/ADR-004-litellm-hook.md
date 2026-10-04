# ADR-004: Integration Point — LiteLLM Pre- and Post-Call Hooks

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-30 |

## Context

The router must inspect both the request before it reaches the model and any
generated tool call before it reaches the agent. Options:

- **Proxy middleware** (e.g., NGINX, Envoy sidecar) — operates at HTTP layer, no LLM context.
- **Agent framework plugin** — framework-specific, not portable.
- **LiteLLM CustomLogger hooks** — run inside the LiteLLM process with access to
  parsed requests and non-streaming model responses.

## Decision

Integrate via `litellm.CustomLogger.async_pre_call_hook` and
`async_post_call_success_hook`. The pre-call hook decides whether a request may
reach the model. The post-call hook re-evaluates newly generated non-streaming
tool calls and maps them to execute, hold, or block. Because LiteLLM invokes the
custom logger callback after streaming content has already begun, requests that
combine streaming with tools are blocked before the model call.

## Consequences

- Full access to structured request data (message list, tool definitions, tool results) with no HTTP parsing.
- Tightly coupled to LiteLLM internals; API changes may require hook updates.
- Hook runs in the same process as the proxy; a crash can affect proxy stability.
  Missing policy files and configured classifier setup failures therefore stop
  startup instead of silently disabling checks.
- Latency overhead is added synchronously before every model call; must be measured (M1 benchmark).
