# Capstone Roadmap — Risk-Based LLM Router (LiteLLM + Session Taint Tracking)

**Research question:** Does session-aware (taint-tracking) routing detect content-borne injection → exfiltration chains better than stateless routing, and how does detection scale across four levels of context richness (L0–L3)?

**Contribution:** empirical A/B evaluation, not a new product. The router is the instrument; the results are the deliverable.

---

## Locked decisions (see `docs/adr/`)

| # | Decision |
|---|----------|
| ADR-001 | Session = one agent run (not per-user across chats) |
| ADR-002 | Session state = lightweight source/sink taint tracker, not full history pooling |
| ADR-003 | Classifiers are off-the-shelf: PromptGuard 2, LLM Guard — no training |
| ADR-004 | Integration point = LiteLLM `async_pre_call_hook` (custom callback) |
| ADR-005 | Threat model: in scope = indirect/content-borne injection via tool/MCP outputs & retrieved docs driving exfiltration. Out of scope = direct user prompt injection; human user trusted |
| ADR-006 | eBPF / container-escape backstop = **parked** (stretch track, decide at M4 review) |

## Context-richness levels (independent variable)

| Level | Router sees | Status |
|---|---|---|
| L0 | Bare flags: untrusted source seen in session? sink-capable tool requested? | defined |
| L1 | L0 + source provenance (which tool/MCP server, trust tier) | *proposed* |
| L2 | L1 + classifier verdicts on tainted content (PromptGuard 2 / LLM Guard) | *proposed* |
| L3 | L2 + content correlation (tainted spans appearing in sink arguments) | defined |

Confirm L1/L2 definitions in issue **ADR-007**.

---

## Milestones (incremental deliverables)

Each milestone ends in something **runnable or measurable**. Nothing waits for the end.

| Milestone | Target | Deliverable (demo-able) |
|---|---|---|
| **M0 Foundations** | Oct 9 | Repo, `docker compose up` brings LiteLLM proxy + mock model, CI green, ADRs committed |
| **M1 Hook Skeleton** | Oct 16 | Pass-through `async_pre_call_hook` logging a structured decision record per request; `mode=stateless\|session` flag |
| **M2 Session & Taint** | Oct 30 | Per-run session ID, source/sink registry, taint propagation; L0 + L1 decisions visible in logs |
| **M3 Classifiers** | Nov 6 | PromptGuard 2 + LLM Guard behind one adapter interface; latency measured; L2 live |
| **M4 Risk Policy & Routing** | Nov 13 | YAML policy → allow / route-hardened / strip-tools / block; L3 correlation live. **Go/no-go on eBPF stretch** |
| **M5 Attack Corpus** *(parallel from Oct 19)* | Nov 13 | Versioned corpus of multi-step scenarios + benign controls, mapped to OWASP Agentic Top 10 & NSA MCP guide |
| **M6 Evaluation Harness** | Nov 24 | One command runs the full matrix {stateless, session} × {L0..L3} × corpus → results CSV |
| **M7 Analysis & Write-up** | Dec 11 | Figures, threats-to-validity, paper, demo, final presentation |

```
Oct 5 ──M0──M1────M2────M3──M4──────M6────────M7── Dec 11
              └──────── M5 corpus (parallel) ─┘
```

Dates assume a Dec 11 finish; change `MILESTONES` in `bootstrap_github.py` before running if your term differs.

---

## Repo layout

```
router/            # hook, session store, taint, policy
  hook.py          # LiteLLM CustomLogger w/ async_pre_call_hook
  session.py       # per-run session store (in-mem, Redis optional)
  taint.py         # source/sink model, propagation
  classifiers/     # adapter interface + promptguard2.py, llmguard.py
  policy.py        # risk score → action
corpus/            # scenarios/*.yaml, schema.json, taxonomy map
harness/           # mock tools / MCP server, agent driver, runner
eval/              # metrics, notebooks, figures
docs/adr/          # architecture decision records
docs/paper/
deploy/            # docker-compose, litellm config
tests/
```

---

## Workflow (GitHub-only)

**Tracking:** GitHub Projects board → `Todo → In Progress → Done`. Milestones = phases above. One issue ≈ 0.5–2 days of work; bigger → split.

**Labels:** `type:*` (feature, infra, research, eval, docs), `area:*` (hook, session, classifier, policy, corpus, harness, paper), `P0`/`P1`, `stretch`.

**Branching (team agreement):** feature branches off `main`; `main` is protected — no direct pushes, merge only via PR with **1 teammate approval**.

**Flow per issue:**
1. Assign yourself, move to *In Progress*, branch `feature/12-taint-propagation` (`feature/<issue#>-<slug>`; `fix/…` for bugs)
2. Open a small PR with `Closes #12`; request a review from a teammate
3. 1 approval + CI green → squash merge → branch auto-deleted → issue closes → board moves to *Done*
4. Author merges after approval; new commits after approval dismiss it (re-review)

**Definition of Done:** code + tests pass in CI · decision record fields documented · README/ADR updated if behavior changed · demoable from `make` target.

**Weekly cadence (30 min, Friday):** close/roll milestone, update this file's table, note anything for the professor in a `status:weekly` issue comment.

**Tags:** `v0.1` at M1, `v0.2` at M2 … `v1.0-eval` = the exact commit results were produced from (reproducibility).

---

## Metrics (fixed now so the build serves them)

- **Attack success rate (ASR)** / detection rate per scenario class
- **False positive rate** on benign controls (and a proxy for approval fatigue: blocks/escalations per 100 benign runs)
- **Added latency** p50/p95 per level
- **Cost overhead** (classifier calls, tokens)
- Per-level delta: session-aware minus stateless, with CIs across repeated seeds
