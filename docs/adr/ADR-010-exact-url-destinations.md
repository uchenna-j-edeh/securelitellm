# ADR-010: Exact URLs for destination authorization

| | |
|---|---|
| **Status** | Proposed (#218) |
| **Date** | 2026-11-08 |

## Problem

After #219/#221, calls with destinations reach the allowlist and user-named
checks regardless of their tool names. Matching only a URL's host still permits
an injection to append a secret to its path or query. A user asking to open
`https://reports.example.com/ingest` has not authorized
`https://reports.example.com/ingest?q=secret`.

## Decision

`Allowlist` stores complete normalized URLs. Both the configured allowlist
(`allowed_destinations`), the user's own destinations (`own_destinations`) and
URLs extracted from this turn's user request use the same comparison. Email and
channel matching retain their existing semantics. Every destination must pass
each enabled control; naming a URL does not bypass the allowlist.

| Property | Rule |
|---|---|
| Scheme and host | Lowercase; strip a final DNS dot; remove known default ports |
| Path and query | Preserve case, query order, duplicate parameters and reserved bytes |
| Path structure | Resolve `.`/`..`; preserve repeated slashes and `/a` versus `/a/` |
| Percent escapes | Uppercase hex; decode only RFC 3986 unreserved bytes, never `%2F`, `%26`, etc. |
| Fragment | **Keep and match exactly** (unreserved escapes normalized). HTTP clients don't send it, but a tool that logs or forwards the raw URL would carry data placed there |
| Empty query | `/a?` remains distinct from `/a` |
| Root page | A policy entry must explicitly include `/`; `https://x.example` fails startup with migration guidance |
| Scheme-less tool URL | Assume **http**, preserving `network_targets()`'s #219 convention; never ignore or silently switch a scheme |
| Scheme-less URL the user typed | Names **both** its `http` and `https` forms: the user chose no scheme, and models usually pick https. A scheme the user typed is exact, and policy entries always need an explicit scheme |
| Prose URL token | Trim sentence punctuation and unmatched closing brackets; backticks/quotes/angle brackets preserve intentional terminal punctuation |
| Invalid/ambiguous URL | Refuse credentials in authority, backslashes, invalid ports/percent escapes, controls and non-ASCII raw URLs; use explicit ASCII/punycode/percent-encoded forms |

The normalizer changes comparison keys only. It does not rewrite the request,
fetch a URL, resolve DNS, follow redirects, or interpret application-specific
query parameters. A canonical equivalent accepted here must also be interpreted
consistently by the executor. Redirect destinations need enforcement by that
executor; URL equality does not constrain later hops or data in a POST body.
Syntax normalization follows [RFC 3986 sections 5.2.4 and 6.2.2](https://www.rfc-editor.org/rfc/rfc3986).

Refusal evidence continues to contain **only the host**. Full paths, queries,
user text and credentials are never added to decision records by this change.
A refused URL is named by its host only when that host is a dotted DNS name or
an IP address; anything else, such as free text in a `url` or `link`
argument (`"password=hunter2"`), is recorded as `(unparseable url)`.

## Read tools with host-like arguments

`network_targets()` now treats **any** value in a `url`, `uri`, `link`, `href`,
`endpoint`, `webhook`, `webhook_url`, `host`, `domain` or `website` argument as
a URL, not only values that look like one. A malformed value therefore reaches
authorization and fails closed, instead of the call passing as a plain read.

As a result, read-named lookups such as `get_server_status(host="web-01")` or
`get_dns_record(domain="example.com")` are checked like sends and are held while
the allowlist is on, unless the exact target is listed. This is intentional: a
lookup of an injected host or domain can itself carry data out (DNS queries
reach the domain's name servers), and it confirms to the host's owner that the
agent obeyed. Deployments with legitimate host lookups, such as fleet operations
(#222), need those targets listed, or declared tool capabilities (#176).

## Migration and demo

- Replace the old corpus host entry with the exact `/ingest` and `/debug`
  endpoints. `/debug` is required by benign GitHub control bn-062.
- Demo Beat 1 explicitly allows `https://httpbin.org/html`, not the whole host.
- Regenerate existing private `deploy/policy.demo.yaml` with
  `python scripts/demo_policy.py` in the configured demo environment (also run
  by `make demo-dual-up`). It contains the operator's recipient and stays ignored.
- An intentionally allowed root page must be written `https://host.example/`.
  Old host-only entries are rejected even when the allowlist switch is off,
  consistent with existing startup validation.

## Consequences and scope

Dynamic search queries, per-record paths, pagination, reordered query parameters
and literal punctuation may need explicit endpoints or an explicit user request.
Benign holds must be reported beside blocked attacks; the existing small URL
sets cannot estimate the cost in all deployments. There is no new wildcard or
prefix mode.

This implements the exact-URL layer of #218. The broader issue remains open for
outbound-content provenance, reply-text checks (#129), declared tool capabilities
(#176) and classifier escalation-only decisions (#192). It does not claim to fix
the LLMail body-content gap. See the paired regression results for measured cost.
