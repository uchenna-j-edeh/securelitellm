# Gateway decisions in the UI

Decisions arrive with each model response. The UI does not read Docker logs or
CloudWatch, run the AWS CLI, or periodically poll a log/history service.
CloudWatch remains the audit sink for operations and retrospective review.

## Response contract

`x-securelitellm-decision` contains ASCII JSON with a version and ordered
decisions for that request. For an ordinary agent key the default is:

```json
{"version":1,"decisions":[{"decision_id":"0123456789abcdef0123456789abcdef","action":"allow"}]}
```

The id is gateway-generated and also appears in the corresponding audit record.
A request can have both pre-call and post-call decisions; the latter reports
the disposition of generated tool calls (`execute`, `hold`, or `block`). In
audit-only mode a minimal response uses `action: "observe"`, so a proposed
block is never shown as an enforced block.

When a request fails, the same object is carried in
`error.provider_specific_fields.securelitellm_decision`. The agent decodes it
before handling the failure or session reset and forwards structured events
to the browser before executing released calls. Model prose and tool content
are never parsed as gateway decisions.

Metadata is capped at 4 KiB. If detail exceeds the limit, the header keeps every
id/action and sets `details_truncated: true`; authorized users can retrieve
details from history. No raw session credential, prompt, tool arguments, API
key or classifier input is included.

## Disclosure controls

- Ordinary keys receive id/action only. Risk metrics remain unknown until
  authorized details are available.
- `proxy_admin` and `proxy_admin_viewer` can read full summaries and history.
- On an isolated demo gateway, `SECURELITELLM_EXPOSE_DECISIONS=true` explicitly
  exposes full summaries to ordinary keys. Those keys can read only their own
  history. Their LiteLLM `allowed_routes` must also permit the history endpoint
  if direct access is required.
- `ROUTER_LOCK=true` rejects that demo setting. Production should leave it off:
  scores, classifier verdicts and matched rules can aid adaptive probing.

Full summaries include id, timestamp, request id, non-secret session ref,
phase, action, route, risk score/level, enforcement mode, bounded rule names
and a compact classifier verdict. Existing audit fields retain their meaning;
`decision_id` is an additional correlation field.

## History and retention

`GET /securelitellm/decisions?session=<16-hex-session-ref>` uses LiteLLM key
authentication and checks the caller's role. It returns the newest 300 retained
decisions in chronological order. Ordinary keys are denied unless the demo
setting is on; when enabled, their authenticated key owner scopes every read.

With `SESSION_STORE=memory`, history is process-local, capped at 10,000 records
globally and 300 per session/key, and lost on gateway restart. With
`SESSION_STORE=postgres`, history is shared across workers and survives restarts.
Both retain records for one hour; Postgres expiry cleanup runs on writes.
Stored summaries and ownership/expiry metadata have an HMAC derived from the
existing session key. Database errors or invalid signatures are explicit
unavailable results, never a successful empty fallback.

History writes run in a worker thread rather than freezing the ASGI event loop.
If persistence fails, the response still reports the actual policy decision
and includes `history_available: false`. Policy enforcement does not depend
on history and never falls back to a fresh session store.

### Database upgrade

This change adds `securelitellm_decisions` and schema version 3. Before starting
the updated gateway, run the existing migration with the database admin
connection and grant the proxy role access:

```bash
SESSION_DB_ADMIN_URL=... python -m router.pg_session migrate --grant-to securelitellm_proxy
```

Use a coordinated gateway restart: old workers require schema version 2 and
reject a version 3 database. Session and approval MAC payload versions remain
at 2 because those payloads did not change, preserving existing signatures.
The proxy role needs no DDL permissions. The deployment database setup script
runs this migration through its existing setup path.

## UI setup and reloads

Use the existing local or remote launcher. No AWS credentials are needed on
the UI laptop. A remote gateway must also run this response update: updating
the page cannot add metadata to an older gateway. Missing metadata is shown
explicitly rather than inferred from an assistant's refusal.

The panel shows **Risk score**, **Risk level**, **Route**, and **Action**, with
expandable evidence. **Restore history** calls the gateway API through the UI
server using its existing admin/approver key when configured. Keys stay
server-side; the browser can request only its server-owned UI handle, not
arbitrary gateway session refs.

Per-tab session storage remembers only the opaque UI handle and selected mode.
Refresh restores received decisions, optionally enriched from gateway history.
A UI server restart loses its handle mapping and requires a new UI session;
gateway history remains available to authorized admins. Decisions received
before a rejected session remain visible after that session is cleared.

Saved audit exports may be loaded manually as **Recorded evidence**. They are
processed in the browser and clearly distinguished from current responses;
loading one neither runs an agent nor demonstrates a new live outcome.
