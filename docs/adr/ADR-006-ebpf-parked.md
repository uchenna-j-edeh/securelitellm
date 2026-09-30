# ADR-006: eBPF / Container-Escape Backstop — Parked

| | |
|---|---|
| **Status** | Parked (revisit at M4 review) |
| **Date** | 2026-09-30 |

## Context

An application-layer router can only block calls it intercepts. If an agent or a compromised tool bypasses LiteLLM (direct HTTP, subprocess, socket), the router is blind. An eBPF-based egress backstop running at the kernel layer would catch such bypasses regardless of application behavior.

## Decision

eBPF backstop is **parked** as a stretch track. A go/no-go decision will be made at the M4 milestone review based on schedule slack and incremental value.

If go: prototype in `router/ebpf/`. Document as ADR-008.
If no-go: document as future work in the paper's limitations section.

## Consequences

- For the primary eval, the router's detection capability is limited to requests that flow through LiteLLM. Exfil via non-LiteLLM paths is a known blind spot.
- The paper must clearly state this limitation under "threats to validity."
- Not pursuing eBPF keeps the scope manageable for the Dec 11 deadline.
