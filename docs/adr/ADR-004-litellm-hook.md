# ADR-004: Integration Point — LiteLLM async_pre_call_hook

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-09-30 |

## Context

The router must intercept every LLM request before it reaches the model. Options:

- **Proxy middleware** (e.g., NGINX, Envoy sidecar) — operates at HTTP layer, no LLM context.
- **Agent framework plugin** — framework-specific, not portable.
- **LiteLLM CustomLogger `async_pre_call_hook`** — runs inside the LiteLLM process with access to the full parsed request (messages, tools, metadata) before forwarding to the model.

## Decision

Integrate via `litellm.CustomLogger.async_pre_call_hook`. The hook is registered in `litellm_config.yaml` under `callbacks`.

## Consequences

- Full access to structured request data (message list, tool definitions, tool results) with no HTTP parsing.
- Tightly coupled to LiteLLM internals; API changes may require hook updates.
- Hook runs in the same process as the proxy; a crash in the hook can affect proxy stability (mitigated by fail-open configuration for classifiers).
- Latency overhead is added synchronously before every model call; must be measured (M1 benchmark).
