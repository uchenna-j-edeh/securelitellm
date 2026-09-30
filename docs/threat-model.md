# Threat Model

## Assets

| Asset | Description |
|---|---|
| **User data in context** | PII, credentials, documents, emails retrieved by agent tools |
| **External services** | Email accounts, HTTP endpoints, file systems, code execution environments reachable via sink tools |
| **Agent integrity** | The agent's ability to complete the user's goal without adversary interference |

## Attacker

**Profile:** A malicious content author who controls data that can be retrieved or returned by tools the agent calls. The attacker has no direct access to the agent prompt, model weights, or infrastructure.

**Capabilities:**
- Plant adversarial instructions in documents, web pages, database rows, email bodies, or any content returned by a tool
- Craft instructions that are syntactically valid tool calls or natural-language directives
- Use encoding (base64, URL encoding) or paraphrase to evade classifiers
- Split the payload across multiple tool result turns

**Cannot:**
- Send messages directly as the user (human user is trusted — ADR-005)
- Modify model weights or the LiteLLM proxy configuration
- Observe the session state or decision records

## In Scope

**Indirect / content-borne prompt injection** where:
1. The agent calls a tool (web search, document fetch, MCP server query, email read, …)
2. The tool result contains adversarial instructions
3. Those instructions cause the agent to call a **sink tool** that exfiltrates data or takes an unauthorized action

Both the injection source and the sink action must occur within the same agent run (ADR-001).

## Out of Scope

- Direct user prompt injection (user is trusted)
- Model poisoning / training-time attacks
- Cross-run exfiltration (source in run N, sink in run N+1)
- Bypass of LiteLLM via non-proxied HTTP, subprocess, or socket (noted as limitation; eBPF stretch — ADR-006)
- Denial-of-service against the router
- Social engineering of the human user

## Sink Classes

| Sink class | Example tools | Exfil risk |
|---|---|---|
| **HTTP egress** | `http_post`, `webhook_send`, `web_request` | High — arbitrary data to attacker-controlled URL |
| **Email / message send** | `send_email`, `slack_post`, `sms_send` | High — data to attacker-controlled address |
| **File write** | `write_file`, `save_document` | Medium — data persisted, may be exfiltrated later |
| **Code execution** | `run_python`, `bash_exec` | High — arbitrary exfil possible via subprocess |
| **Calendar / task create** | `create_event`, `create_task` | Low — limited data exposure, included for completeness |

Unknown tools with URL, recipient, or path arguments default to **potential sink** (untrusted tier) per the sink registry (ADR-002).

## Source Trust Tiers

| Tier | Examples |
|---|---|
| **untrusted** | Public web search results, arbitrary document fetch, unverified email content |
| **low** | Internal wikis, shared drives not under access control |
| **medium** | Company-owned APIs, databases with access logging |

The trust tier of a source is configured in `router/classifiers/source_registry.yaml` (M2). Unknown tools default to **untrusted**.
