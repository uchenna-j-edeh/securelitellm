# ADR-011: A declared tool inventory, and who enforces each claim

| | |
|---|---|
| **Status** | Accepted (#176) |
| **Date** | 2026-11-11 |

## Problem

The router decided what a tool call could do from the tool's **name**
(`router/taint.py`: `send_` is egress, `get_`/`fetch_`/`list_` are reads).
#219 and #221 stopped trusting the name for calls that carry a destination,
but a tool with no destination in its arguments is still classed by its name,
a new tool with an unfamiliar name is "other", and nothing says what a tool
is *supposed* to do. The gateway guessed; it should be told.

The question that shaped the design: **can the gateway rely on a tool being
honest about its capabilities?** No. A declaration is a claim. The inventory
tells the gateway what it may *release*; it never tells it what a tool
*does*. Every claim needs an enforcer that is not the tool, and a claim with
no enforcer is not granted.

## Decision

The policy gains a `tools:` section. Each tool declares a capability and,
for `network-read` tools that always talk to one service, a fixed
destination:

```yaml
tools:
  read_file:          {capability: local-read}
  get_github_issue:   {capability: network-read, destination: https://api.github.com}
  fetch_url:          {capability: network-read}   # destination decided per call
  send_email:         {capability: egress}         # destinations: allowed_destinations
  run_command:        {capability: exec}           # never a plain grant (#222)
```

| Capability | Starts as | What the gateway checks |
|---|---|---|
| `local-read` | read | a call naming **any** destination (URL, host, address, channel) is a `capability_violation` |
| `network-read` with `destination` | read | a URL on any other origin, or any address or channel, is a `capability_violation`; a URL on the declared origin is still authorized exactly by the allowlist and user-named checks (#229) |
| `network-read` without | read | as today: a URL in the call makes it "network" and the destination checks decide (#218) |
| `egress` | exfil | as today: destinations against `allowed_destinations` and the user's message |
| `write` | write | as today |
| `exec` | other | fails closed under the allowlist; command policy is #222 |

A tool missing from a non-empty inventory is `tool_unlisted`. Both features
are policy rules in `deploy/policy.yaml`: `capability_violation` scores 0.9
(block), `tool_unlisted` 0.75 (hold). Without a `tools:` section nothing
changes, so existing deployments and the evaluation corpus are unaffected.

The declaration decides a tool's starting category even when its name says
otherwise: a `local-read` tool called `kb_lookup` is a read, an `egress` tool
called `publish` is a send.

**Fixed destinations are deploy-time config**, set by the operator (the Jira
site from `JIRA_BASE_URL`, GitHub's public API origin), never read from the
tool's own metadata. A tool vouching for its own destination would be the
tool being trusted again.

## Who enforces each claim

| Threat | Enforcer |
|---|---|
| The tool lies: declared `read`, secretly sends | Not the proxy, which can't see inside a tool. Credentials (read-only scopes) and network egress rules (#111); the broker holds credentials behind it (#223). The inventory is the spec the deployment is checked against. |
| A hijacked model misuses a read tool to send (data in a URL, query or `to`) | The gateway: the contradiction checks above, on top of #219/#221. |
| The agent bypasses the proxy and calls the tool directly | The broker (#223): a tool runs only with a gateway-signed release for that call and argument hash. The inventory lives there too. |

**Honest limit.** A compromised tool that legitimately needs the internet
(`web_search`) can exfiltrate whatever arguments it receives. The proxy can
only bound what the tool is given (#218, "what a send carries").

## Decision records

`features.capability_violation` and `features.tool_unlisted` are booleans;
`capability_violations` and `unlisted_tools` list the tool names involved.
Arguments are never recorded. The startup record's `tools` field counts the
declared tools per capability.

## Consequences

- The demo policy (`scripts/demo_policy.py`) declares the demo tool
  service's 13 tools, so a 14th tool is held until declared.
- Per-agent grants stay LiteLLM-native (#167): the inventory says what a
  tool *is*; the key or team permission says who may *use* it.
- Not in this change: schema pinning (a changed description or schema under
  the same name keeping its grant), a fixed target for `write` tools, and
  the broker. Those follow in #223.

Related: #218, #219, #221, #222, #223, #111, #167, #174.
