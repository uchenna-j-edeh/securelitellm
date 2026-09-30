#!/usr/bin/env python3
"""
Bootstrap GitHub tracking for the LLM-router capstone.

Creates: labels, milestones (with due dates), ~45 issues, and a GitHub Projects board.
Idempotent: skips existing labels/milestones/issues and reuses the board by title, so re-running is safe.

Prereqs:
  gh auth login
  gh auth refresh -s project        # needed for the Projects board
Usage:
  python3 bootstrap_github.py [--repo <owner>/<repo>] [--dry-run] [--no-project] [--project-owner @me]
                              [--skip-protect] [--protect-only] [--ci-check <job>]
  --repo defaults to uchenna-j-edeh/securelitellm.
Stdlib only.
"""
import argparse, json, subprocess, sys

# ---------------------------------------------------------------- config
MILESTONES = [
    ("M0 Foundations",          "2026-10-09", "Repo, dev env, CI, ADRs"),
    ("M1 Hook Skeleton",        "2026-10-16", "Pass-through async_pre_call_hook + decision log"),
    ("M2 Session & Taint",      "2026-10-30", "Per-run sessions, source/sink taint; L0/L1"),
    ("M3 Classifiers",          "2026-11-06", "PromptGuard 2 + LLM Guard adapters; L2"),
    ("M4 Risk Policy & Routing","2026-11-13", "Policy engine, routing actions, L3 correlation"),
    ("M5 Attack Corpus",        "2026-11-13", "Taxonomy-mapped multi-step scenarios + benign controls"),
    ("M6 Evaluation Harness",   "2026-11-24", "Full A/B matrix runner -> results CSV"),
    ("M7 Analysis & Write-up",  "2026-12-11", "Figures, paper, demo, presentation"),
]

LABELS = {
    "type:feature":   ("1f6feb", "New capability"),
    "type:infra":     ("6e7781", "Build, CI, env"),
    "type:research":  ("8250df", "Reading / design decision"),
    "type:eval":      ("bf8700", "Evaluation work"),
    "type:docs":      ("0e8a16", "ADR, README, paper"),
    "area:hook":      ("c5def5", "LiteLLM hook"),
    "area:session":   ("c5def5", "Session store / taint"),
    "area:classifier":("c5def5", "PromptGuard 2 / LLM Guard"),
    "area:policy":    ("c5def5", "Risk scoring and routing actions"),
    "area:corpus":    ("c5def5", "Attack corpus"),
    "area:harness":   ("c5def5", "Agent driver, mock tools, runner"),
    "area:paper":     ("c5def5", "Write-up"),
    "P0":             ("d73a4a", "Critical path"),
    "P1":             ("fbca04", "Important, not blocking"),
    "stretch":        ("ededed", "Only if time allows"),
}

def I(ms, title, labels, body):
    return {"milestone": ms, "title": title, "labels": labels, "body": body.strip()}

M = [m[0] for m in MILESTONES]
ISSUES = [
# ---- M0
I(M[0], "Create repo skeleton and README", ["type:infra","P0"], """
Create directories per ROADMAP.md (router/, corpus/, harness/, eval/, docs/adr/, deploy/, tests/). Add README with one-paragraph research question and quickstart.
- [ ] Layout matches ROADMAP
- [ ] README quickstart placeholder"""),
I(M[0], "Python toolchain: uv/poetry, ruff, pytest, Makefile", ["type:infra","P0"], """
- [ ] Pinned deps incl. litellm version
- [ ] `make lint test` works locally"""),
I(M[0], "docker-compose: LiteLLM proxy + mock model backend", ["type:infra","P0"], """
Deterministic mock model (e.g. fake OpenAI-compatible server) so tests and eval don't depend on paid APIs; real model optional via env.
- [ ] `docker compose up` serves /chat/completions through LiteLLM
- [ ] Mock can return scripted tool calls"""),
I(M[0], "GitHub Actions CI: lint + unit tests", ["type:infra","P0"], """
- [ ] Runs on PR and main
- [ ] Branch protection: CI required before merge"""),
I(M[0], "ADR-001..006: record locked design decisions", ["type:docs","P0"], """
One short ADR each: per-run session, source/sink taint tracker, off-the-shelf classifiers, async_pre_call_hook, threat-model scope, eBPF parked.
- [ ] docs/adr/ committed"""),
I(M[0], "ADR-007: define context-richness levels L0-L3", ["type:research","P0"], """
Confirm L1 (provenance/trust tier) and L2 (classifier verdicts) definitions; L0 and L3 already fixed.
- [ ] Each level = exact list of features the policy may read
- [ ] Features are toggleable by config"""),
I(M[0], "Threat model doc (in/out of scope, assets, sinks)", ["type:docs","P1"], """
- [ ] Attacker capabilities, trusted user assumption
- [ ] Enumerated sink classes (HTTP egress, email/message send, file write, code exec)"""),
# ---- M1
I(M[1], "Implement CustomLogger with async_pre_call_hook (pass-through)", ["type:feature","area:hook","P0"], """
- [ ] Registered via litellm config
- [ ] No behavior change to requests
- [ ] Unit test with mock backend"""),
I(M[1], "Decision record schema + JSONL logger", ["type:feature","area:hook","P0"], """
Fields: ts, session_id, request_id, mode, level, features, risk_score, action, latency_ms.
- [ ] JSON schema in repo
- [ ] One record per request"""),
I(M[1], "Config: mode=stateless|session and level=L0..L3 toggles", ["type:feature","area:hook","P0"], """
- [ ] Switchable via env/config without code change
- [ ] Logged in every decision record"""),
I(M[1], "Extract tool calls and tool results from request messages", ["type:feature","area:hook","P0"], """
Parse OpenAI-style messages: role=tool results (sources) and assistant tool_calls (candidate sinks).
- [ ] Fixtures for multi-turn tool conversations"""),
I(M[1], "Hook overhead benchmark (baseline latency)", ["type:eval","area:hook","P1"], """
- [ ] p50/p95 added latency of pass-through hook recorded in eval/baseline.md"""),
I(M[1], "Tag v0.1", ["type:infra","P1"], "- [ ] Release notes list working features"),
# ---- M2
I(M[2], "Session ID derivation per agent run", ["type:feature","area:session","P0"], """
Source: request metadata/header (e.g. x-agent-run-id); fallback strategy documented.
- [ ] Two concurrent runs never share state (test)"""),
I(M[2], "Session store interface (in-memory impl, TTL)", ["type:feature","area:session","P0"], """
- [ ] get/put/expire
- [ ] Redis impl behind same interface = optional, P1"""),
I(M[2], "Source registry: classify tool/MCP/retrieval outputs by trust tier", ["type:feature","area:session","P0"], """
- [ ] Config maps tool names / MCP servers -> trust tier
- [ ] Unknown tools default to untrusted"""),
I(M[2], "Sink registry: classify tool calls by exfil capability", ["type:feature","area:session","P0"], """
- [ ] Sink classes from threat model
- [ ] Unknown tools with URL/recipient args flagged as potential sinks"""),
I(M[2], "Taint propagation across turns", ["type:feature","area:session","P0"], """
Mark session tainted when untrusted content enters context; retain tainted spans (hashed + raw for L3).
- [ ] Multi-turn tests: taint persists, clean session stays clean"""),
I(M[2], "L0 and L1 feature extraction", ["type:feature","area:session","P0"], """
- [ ] L0: bool(untrusted_seen), bool(sink_requested)
- [ ] L1: + source ids / trust tiers
- [ ] Present in decision record"""),
I(M[2], "Stateless-mode equivalent features (per-request only)", ["type:feature","area:session","P0"], """
Control arm: same features computed from the single request with no session memory.
- [ ] Same code path, state disabled"""),
I(M[2], "Tag v0.2", ["type:infra","P1"], ""),
# ---- M3
I(M[3], "Classifier adapter interface (score, label, latency)", ["type:feature","area:classifier","P0"], """
- [ ] Async, timeout, fail-open/fail-closed configurable"""),
I(M[3], "PromptGuard 2 adapter", ["type:feature","area:classifier","P0"], """
- [ ] Runs on tainted spans only (not every token)
- [ ] CPU-feasible model variant documented"""),
I(M[3], "LLM Guard adapter (prompt-injection scanner)", ["type:feature","area:classifier","P0"], ""),
I(M[3], "Classifier result caching by content hash", ["type:feature","area:classifier","P1"], "- [ ] Same tool output scanned once per session"),
I(M[3], "L2 feature extraction", ["type:feature","area:classifier","P0"], "- [ ] Classifier verdicts attached to tainted sources in decision record"),
I(M[3], "Classifier latency/cost benchmark", ["type:eval","area:classifier","P1"], "- [ ] p50/p95 per classifier recorded"),
I(M[3], "Tag v0.3", ["type:infra","P1"], ""),
# ---- M4
I(M[4], "Policy engine: YAML rules -> risk score", ["type:feature","area:policy","P0"], """
- [ ] Rules can only read features allowed at the configured level (enforced)
- [ ] Deterministic, unit-tested"""),
I(M[4], "Routing actions: allow / route-hardened / strip-tools / block", ["type:feature","area:policy","P0"], """
Implemented by mutating or rejecting the request inside async_pre_call_hook.
- [ ] Each action tested end-to-end through proxy"""),
I(M[4], "L3 content correlation: tainted spans in sink arguments", ["type:feature","area:policy","P0"], """
Exact + fuzzy match (normalized, n-gram); note paraphrase limitation as threat to validity.
- [ ] Tests for verbatim, encoded (base64/url), and partial exfil"""),
I(M[4], "Escalation/approval counter (approval-fatigue proxy)", ["type:feature","area:policy","P1"], "- [ ] Count escalations per session in decision record"),
I(M[4], "M4 review: go/no-go on eBPF backstop", ["type:research","P0"], """
Decide based on schedule slack. If no-go, document as future work in paper.
- [ ] Decision recorded as ADR-008"""),
I(M[4], "eBPF egress backstop prototype", ["type:feature","stretch"], "Only if ADR-008 = go."),
I(M[4], "Tag v0.4", ["type:infra","P1"], ""),
# ---- M5
I(M[5], "Corpus schema (scenario YAML) + validator", ["type:eval","area:corpus","P0"], """
Fields: id, taxonomy refs, steps (tool outputs / injected content), target sink, expected label (attack|benign), variant tags.
- [ ] JSON schema + CI validation"""),
I(M[5], "Taxonomy map: OWASP Agentic Top 10 + NSA MCP guide", ["type:research","area:corpus","P0"], "- [ ] Table of in-scope categories -> scenario classes"),
I(M[5], "Seed scenarios from real incidents", ["type:eval","area:corpus","P0"], "- [ ] >=1 scenario per in-scope category, with citation"),
I(M[5], "Multi-step composition scenarios (injection -> later exfil)", ["type:eval","area:corpus","P0"], """
Key case for session-aware vs stateless: taint and sink in different turns.
- [ ] Vary distance between source and sink (1, 3, 5+ turns)"""),
I(M[5], "Evasion variants: paraphrase, encoding, split payloads", ["type:eval","area:corpus","P1"], ""),
I(M[5], "Benign control set (untrusted content + legitimate sink use)", ["type:eval","area:corpus","P0"], "- [ ] Sized to estimate FPR with reasonable CI"),
I(M[5], "Freeze corpus v1.0 (tag + hash)", ["type:eval","area:corpus","P0"], "Freeze before running final eval; no tuning on the frozen set."),
# ---- M6
I(M[6], "Mock tool + MCP server that serves scenario content", ["type:feature","area:harness","P0"], "- [ ] Records sink invocations for ground truth"),
I(M[6], "Agent driver: replay scenario through LiteLLM proxy", ["type:feature","area:harness","P0"], """
Scripted (deterministic) driver first; optional real-LLM agent run as secondary experiment.
- [ ] Unique run id per scenario execution"""),
I(M[6], "Matrix runner: {stateless,session} x {L0..L3} x corpus x seeds", ["type:eval","area:harness","P0"], "- [ ] Single `make eval` -> results/*.csv"),
I(M[6], "Metrics: ASR, detection, FPR, latency, cost, per-level deltas + CIs", ["type:eval","area:harness","P0"], ""),
I(M[6], "Reproducibility: pinned versions, config snapshot, v1.0-eval tag", ["type:infra","area:harness","P0"], ""),
# ---- M7
I(M[7], "Figures and tables from results", ["type:eval","area:paper","P0"], ""),
I(M[7], "Threats to validity section", ["type:docs","area:paper","P0"], "Corpus bias, mock-vs-real agent, paraphrase evasion, classifier drift, same-process limitation of app-layer brokers."),
I(M[7], "Paper draft", ["type:docs","area:paper","P0"], ""),
I(M[7], "Recorded demo (attack blocked in session mode, missed in stateless)", ["type:docs","area:paper","P1"], ""),
I(M[7], "Final presentation deck", ["type:docs","area:paper","P0"], ""),
]

# ---------------------------------------------------------------- gh helpers
DRY = False
BOARD_TITLE = "Capstone: LLM Router"
DEFAULT_REPO = "uchenna-j-edeh/securelitellm"

class GhError(Exception):
    pass

def gh(*args, capture=True, stdin=None, soft=False):
    cmd = ["gh", *args]
    if DRY:
        print("DRY:", " ".join(a if " " not in a else repr(a) for a in cmd[:8]), "..." if len(cmd) > 8 else "")
        return ""
    r = subprocess.run(cmd, capture_output=capture, text=True, input=stdin)
    if r.returncode != 0:
        hint = ("\nHint: 404 on a write usually means you lack permission (admin for settings/protection, "
                "write for labels/issues). Check: gh api repos/<repo> --jq .permissions") if "404" in r.stderr else ""
        msg = f"gh failed: {' '.join(cmd[:6])}\n{r.stderr.strip()}{hint}"
        if soft:
            raise GhError(msg)
        sys.exit(msg)
    return r.stdout

def main_has_commits(repo):
    if DRY:
        return True
    try:
        gh("api", f"repos/{repo}/branches/main", soft=True)
        return True
    except GhError:
        return False

def protect_main(repo, ci_check=None):
    """Feature-branch workflow: no direct pushes to main, PR + 1 approval, squash-only merges.
    Returns True on success; warns and returns False otherwise so the rest of setup still runs."""
    if not main_has_commits(repo):
        print("WARN: 'main' has no commits yet, so it can't be protected. Push your first commit, then run:\n"
              f"      python3 bootstrap_github.py --repo {repo} --protect-only")
        return False
    try:
        gh("api", "-X", "PATCH", f"repos/{repo}",
           "-F", "allow_squash_merge=true", "-F", "allow_merge_commit=false",
           "-F", "allow_rebase_merge=false", "-F", "delete_branch_on_merge=true", soft=True)
        rules = {
            "required_status_checks": {"strict": True, "contexts": [ci_check]} if ci_check else None,
            "enforce_admins": True,
            "required_pull_request_reviews": {
                "required_approving_review_count": 1,
                "dismiss_stale_reviews": True,
            },
            "restrictions": None,
            "allow_force_pushes": False,
            "allow_deletions": False,
            "required_conversation_resolution": True,
        }
        gh("api", "-X", "PUT", f"repos/{repo}/branches/main/protection",
           "-H", "Accept: application/vnd.github+json", "--input", "-",
           stdin=json.dumps(rules), soft=True)
    except GhError as e:
        print(f"WARN: branch protection not applied; continuing.\n{e}")
        return False
    print(f"main protected: PR + 1 approval{', CI check ' + ci_check if ci_check else ''}")
    return True

def main():
    global DRY
    p = argparse.ArgumentParser()
    p.add_argument("--repo", default=DEFAULT_REPO, help=f"owner/repo (default: {DEFAULT_REPO})")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-project", action="store_true")
    p.add_argument("--project-owner", help="account that owns the board (default: repo owner; use @me if the repo is someone else's)")
    p.add_argument("--protect-only", action="store_true", help="only (re)apply main branch protection, then exit")
    p.add_argument("--ci-check", help="CI job name to require once CI exists, e.g. 'test'")
    p.add_argument("--skip-protect", action="store_true", help="skip admin-only repo settings/branch protection")
    a = p.parse_args(); DRY = a.dry_run
    repo = a.repo
    owner = a.project_owner or repo.split("/")[0]

    if not a.skip_protect:
        ok = protect_main(repo, a.ci_check)   # needs repo admin; main must already exist
        if a.protect_only:
            sys.exit(0 if ok else 1)
    if a.protect_only: return

    for name, (color, desc) in LABELS.items():
        gh("label", "create", name, "--repo", repo, "--color", color, "--description", desc, "--force")
    print(f"labels: {len(LABELS)}")

    existing_ms = set() if DRY else {m["title"] for m in json.loads(
        gh("api", f"repos/{repo}/milestones?state=all&per_page=100"))}
    for title, due, desc in MILESTONES:
        if title in existing_ms: continue
        gh("api", f"repos/{repo}/milestones", "-f", f"title={title}",
           "-f", f"due_on={due}T23:59:59Z", "-f", f"description={desc}")
    print(f"milestones: {len(MILESTONES)}")

    existing = {} if DRY else {i["title"]: i["url"] for i in json.loads(
        gh("issue", "list", "--repo", repo, "--state", "all", "--limit", "500", "--json", "title,url"))}
    urls, created = [], 0
    for it in ISSUES:
        if it["title"] in existing:
            urls.append(existing[it["title"]]); continue
        out = gh("issue", "create", "--repo", repo, "--title", it["title"],
                 "--body", it["body"] or "_See ROADMAP.md_", "--milestone", it["milestone"],
                 "--label", ",".join(it["labels"]))
        urls.append(out.strip()); created += 1
    print(f"issues created: {created} (of {len(ISSUES)}; {len(ISSUES) - created} already existed)")

    if a.no_project: return
    # Reuse an existing board with the same title instead of creating a duplicate.
    boards = [] if DRY else json.loads(gh("project", "list", "--owner", owner, "--format", "json")).get("projects", [])
    match = [b for b in boards if b.get("title") == BOARD_TITLE]
    if match:
        num = str(match[0]["number"])
    else:
        proj = gh("project", "create", "--owner", owner, "--title", BOARD_TITLE, "--format", "json")
        num = "0" if DRY else str(json.loads(proj)["number"])
    for u in urls:   # item-add is idempotent: re-adding an item is a no-op
        gh("project", "item-add", num, "--owner", owner, "--url", u)
    # A user-owned board can only be linked to repos with the same owner.
    if not DRY and owner in (repo.split("/")[0],):
        gh("project", "link", num, "--owner", owner, "--repo", repo)
    print(f"project #{num}: {len(urls)} items added")

if __name__ == "__main__":
    main()
