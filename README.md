# SecureLiteLLM — Risk-Based LLM Router with Session Taint Tracking

**Research question:** Does session-aware (taint-tracking) routing detect content-borne injection → exfiltration chains better than stateless routing, and how does detection scale across four levels of context richness (L0–L3)?

This is an empirical A/B evaluation project, not a product. The router is the instrument; the results are the deliverable.

See [ROADMAP.md](ROADMAP.md) for the full research design and milestone plan.

---

## Quickstart

**Prerequisites:** Docker, Docker Compose, Python ≥ 3.11, [uv](https://docs.astral.sh/uv/)

```bash
# Install Python deps
uv sync --all-groups

# Start LiteLLM proxy + mock model
make up

# Verify the proxy is serving completions
curl http://localhost:4000/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-master-key-local-dev" \
  -d '{"model":"mock","messages":[{"role":"user","content":"hello"}]}'

# Lint and test
make lint test

# Stop services
make down
```

## Project layout

```
router/        hook, session store, taint engine, policy, classifiers
corpus/        attack scenarios (YAML), taxonomy map
harness/       mock MCP server, scripted agent driver, matrix runner
eval/          metrics, notebooks, figures
docs/adr/      architecture decision records
docs/paper/    write-up
deploy/        docker-compose, LiteLLM config, mock model server
tests/
```

## Architecture decisions

See `docs/adr/` for ADR-001 through ADR-007. Key decisions:

- Session = one agent run (ADR-001)
- Taint tracker, not full history pooling (ADR-002)
- Off-the-shelf classifiers only — PromptGuard 2 + LLM Guard (ADR-003)
- Integration via LiteLLM `async_pre_call_hook` (ADR-004)
- Threat model: indirect/content-borne injection only; direct user injection out of scope (ADR-005)
- eBPF backstop parked until M4 review (ADR-006)
- Four context-richness levels L0–L3 (ADR-007)
