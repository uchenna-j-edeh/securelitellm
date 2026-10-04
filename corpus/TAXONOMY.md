# Corpus Taxonomy Map

Maps SecureLiteLLM scenario classes to OWASP Agentic Top 10 (2025) and the
NSA/CISA MCP Security Guide threat taxonomy.  Only in-scope categories are
listed (see ADR-005: direct user injection, supply-chain, DoS out of scope).

## In-scope threat categories

| Scenario class | OWASP Agentic | NSA MCP ref | Description | Scenario IDs |
|---|---|---|---|---|
| `direct_exfil` | A02, A03 | T1.3 | Injection in tool/MCP output drives immediate same-turn exfil | sc-001, sc-002, sc-003, sc-030 |
| `delayed_exfil` | A02, A03 | T1.3, T2.1 | Injection plants taint; exfil happens in a later turn after context scroll | sc-010, sc-011, sc-012, sc-013, sc-031 |
| `mcp_pivot` | A02, A05 | T2.2 | MCP server output redirects agent to call an unauthorized egress tool | sc-020, sc-021 |
| `rag_poison` | A02, A08 | T1.4 | Poisoned document in retrieval store drives exfil | sc-030, sc-031 |

## OWASP Agentic Top 10 coverage

| # | Category | In scope | Covered by |
|---|---|---|---|
| A01 | Unbounded agent actions | No | — |
| **A02** | **Indirect prompt injection** | **Yes** | All attack scenarios |
| **A03** | **Sensitive data exfiltration** | **Yes** | All attack scenarios |
| A04 | Excessive agency / over-permission | Partial | — |
| **A05** | **Agent tool misuse / confusion** | **Yes** | sc-020, sc-021 (mcp_pivot) |
| A06 | Supply chain / plugin poisoning | No | — |
| A07 | Insufficient logging | No | — |
| **A08** | **Memory / context poisoning** | **Yes** | sc-030, sc-031 (rag_poison) |
| A09 | Excessive trust in LLM output | Partial | — |
| A10 | Denial of service | No | — |

## NSA/CISA MCP Guide threat coverage

| Ref | Threat | Covered by |
|---|---|---|
| T1.3 | Tool output injection → exfiltration | sc-001–003, sc-010–013 |
| T1.4 | RAG / retrieval store poisoning | sc-030, sc-031 |
| T2.1 | Cross-turn taint / context carry-over | sc-010–013, sc-021, sc-031 |
| T2.2 | MCP server pivot (tool redirect) | sc-020, sc-021 |
| T3.1 | Credential / secret theft via tool | sc-010, sc-012 |

## Real-incident grounding (issue #38)

Each scenario class is grounded in at least one public incident or disclosure:

| Class | Incident | Citation |
|---|---|---|
| `direct_exfil` | Indirect prompt injection in Bing Chat / ChatGPT browsing — attacker-controlled web page injects instructions that cause the agent to exfiltrate conversation history. | Rehberger, J. (2023). *Indirect Prompt Injection Attacks against ChatGPT.* wandb.ai blog. |
| `delayed_exfil` | Slack AI indirect injection — poisoned Slack messages caused Slack AI to forward private-channel data to the attacker in a later response turn. | PromptArmor. (2024). *Slack AI Being Used to Steal Data from Private Channels.* promptarmor.com. |
| `mcp_pivot` | MCP tool poisoning — injected text in MCP tool descriptions / outputs caused Claude to redirect tool calls to attacker-controlled endpoints. | Invariant Labs. (2025). *MCP Security Notification: Tool Poisoning Attacks.* invariantlabs.ai. |
| `rag_poison` | Indirect prompt injection via retrieved documents — first systematic study of injection through LLM application context (RAG, APIs, emails). | Greshake et al. (2023). *Not What You've Signed Up For.* arXiv:2302.12173. |

## Key experimental contrast (sc-010 class)

The `delayed_exfil` scenarios (sc-010–013, sc-021, sc-031) are the primary
evidence for the research question.  In every multi-turn scenario the exfil
turn contains **no tool result** — simulating context truncation in long-running
agents.  Stateless routing scores 0.0 on that turn (no source visible); session
routing scores ≥0.50 because it remembers taint from the prior turn.
