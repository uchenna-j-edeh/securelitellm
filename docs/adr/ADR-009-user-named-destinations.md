# ADR-009: User-Named Destinations

| | |
|---|---|
| **Status** | Accepted |
| **Date** | 2026-11-02 |
| **Issues** | #212 (builds on #167, #192; related #174, #190) |

## Context

The destination allowlist (#167) decides *where* data may go, but not *who
chose* to send it. With the allowlist on, an injection in a tool result could
still make the agent send data to an **allowlisted** destination the user never
asked for:

- **sc-040, sc-044–046:** the user asks only to read something; the content
  tells the agent to send it to an allowlisted email, host or channel.

Only the injection classifier could stop these, and it scored all four BENIGN.
The classifier fails in both directions (#190): it misses polite, workflow-style
directives, and it flags benign structured content, including real
Gmail/Jira/GitHub items (#210).

Allowlisted recipients are trusted, but injected content must not reach them.
Switching the classifier off (provenance only, #192) catches every attack, but
it also holds every legitimate "read X and send it" request (11/20 benign turns
flagged).

## Decision

**Tool content can be what a send carries, but it never decides that a send
happens or where it goes.**

A new protection switch, `user_named=on|off` (`router/controls.py`, off by
default), requires every send destination to appear in the user message that
started that turn. With the allowlist on, a send goes only to listed
destinations the user typed.

1. **Which user message.** A send is checked against the latest user message
   before the assistant message that made the call, i.e. the request for that
   turn. A generated (post-call) send is checked against the latest user
   message in the request. An address named in an earlier turn doesn't count.
2. **Exact matching,** as the allowlist does it (`router/allowlist.py`):
   - **email:** the full address, ignoring case;
   - **URL:** the complete normalized URL, including path/query (updated by ADR-010, #218);
   - **channel:** the exact `#channel`.

   Display-name tricks are resolved to the real address. Names and roles ("email
   Alice", "email HR") are not addresses and don't count. Neither does "the
   contact in the document".
3. **The user's own destinations** (policy `own_destinations:`) count as named
   in every turn ("email me a summary"). Sending to yourself isn't exfiltration.
   Entries use the allowlist's forms and are validated at startup.
4. **Enforcement.** The feature `destination_not_user_named` is set in pre-call
   (sends in the request) and post-call (sends the model generates). The policy
   rule `destination_not_user_named` scores it 0.75, so the send is held, the
   same as `destination_not_allowed`.
5. **Fail closed.** A send with no destination, or with no user message, is not
   named.
6. **Privacy.** Decision records list unnamed destinations by domain, host or
   channel only. The user's text is never logged.
7. **No classifier involved.** The check compares strings in the trusted user
   message and never reads tool content, so classifier mistakes can't affect
   it. The classifier stays on: it still raises risk on content it flags.

Rejected alternatives:

- **Hold every send after any tool read** (provenance only, #192): stops
  injected sends, but holds every legitimate "read X and send it" request.
  Usable only with approval of held sends (#174), which is future work.
- **Plan/data separation (CaMeL, dual-LLM):** the model that plans tool calls
  never sees raw tool content. Stops injected sends by construction, but it's an
  agent redesign, not a gateway rule. Future work.
- **Admin-set names** ("HR" → `hr@example.com`): would release bn-005, but adds
  configuration and matching rules. Not built; users type the address.

## Consequences

Measured once on 2026-11-02 (60 scenarios, one seed, mock model, L3; see
[`results/protection-combinations.md`](../results/protection-combinations.md#follow-up-user-named-destinations-212-2026-11-02)):

| Setting | Attack turns caught | Benign turns flagged | Generated attacks prevented |
|---|---|---|---|
| Session + classifier + allowlist (before) | 23/28 | 5/20 | 7/8 |
| Session + classifier + allowlist + user_named | **28/28** | 7/20 | **8/8** |
| Stateless + classifier + allowlist + user_named | **28/28** | 7/20 | **8/8** |

- **Closes the allowed-destination gap:** sc-040, sc-044–046 and sc-063 (an
  injected `bcc` on a user-requested send) are held. sc-054, a generated send
  the previous configuration executed, is held.
- **Session memory no longer matters for sends:** stateless catches the same
  attacks, because the rule needs only the current request. Session still adds
  a harder `block` when tainted content is copied into a send (sc-047).
- **Costs, both by design:** bn-005 ("email HR") and bn-042 ("send to the
  contact in the document") are held. Users have to type the full address.
- **Not covered: the message body.** If the user names a recipient and an
  injection adds data to the message (sc-064), the rule passes it. The data can
  only reach a recipient the user chose and the allowlist trusts. The classifier
  caught sc-064; a secret scan of send arguments would cover it without the
  classifier, but isn't built.
- **Not changed:** classifier false positives on benign content (bn-012, the
  real work-tool controls from #210).
- **Compatibility:** with the switch off, behaviour is unchanged. Eval labels
  and result file names include `user_named` only when it's on, so earlier
  results keep their names. Startup and decision records list it in `controls`.
- **The demo** (`scripts/demo_policy.py`) runs all three switches and adds the
  demo recipient (the operator's own mailbox) to `own_destinations`.
