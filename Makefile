.PHONY: lint test test-e2e e2e-up e2e-down up down dev eval eval-conditions eval-dry freeze classifier-up demo-setup demo-check demo-check-live demo demo-tools demo-mcp demo-dual-up demo-dual-down demo-replay gmail-auth

# Well-known key used exclusively for E2E tests — never the production key.
E2E_KEY := sk-test-e2e-key
# Prefer the pinned uv environment. A checked-in-place .venv remains usable when
# uv is not on PATH (for example, from a fresh terminal after `uv sync`).
PYTHON := $(shell if command -v uv >/dev/null 2>&1; then printf 'uv run python'; elif test -x .venv/bin/python; then printf '.venv/bin/python'; else printf 'python3'; fi)

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

test:
	$(PYTHON) -m pytest tests/ -v --ignore=tests/test_e2e.py

# Start the proxy in the configuration required for E2E tests:
#   - harness overlay mounts harness/logs → /logs so decisions.jsonl is accessible
#   - mock classifier (no DeBERTa sidecar needed)
#   - stateless mode (E2E tests exercise session isolation separately)
#   - well-known test master key
e2e-up:
	@mkdir -p harness/logs
	LITELLM_MASTER_KEY=$(E2E_KEY) \
	CLASSIFIER_BACKEND=mock \
	ROUTER_MODE=stateless \
	ROUTER_LEVEL=L3 \
	ROUTER_ENFORCE=true \
	docker compose -f deploy/docker-compose.yml -f harness/docker-compose.override.yml up -d --build

e2e-down:
	docker compose -f deploy/docker-compose.yml -f harness/docker-compose.override.yml down

test-e2e:
	E2E_MASTER_KEY=$(E2E_KEY) \
	E2E_DECISION_LOG="harness/logs/decisions.jsonl" \
	$(PYTHON) -m pytest tests/test_e2e.py -v -m e2e

up:
	docker compose -f deploy/docker-compose.yml up -d --build

down:
	docker compose -f deploy/docker-compose.yml down

dev:
	docker compose -f deploy/docker-compose.yml up --build

# M6 — run full evaluation matrix and compute metrics.
# HARNESS_MODEL=mock: the eval metric is the router's decision (hook-determined), which is
#   model-independent — validated as identical to Groq (0/300 mismatches). Mock removes
#   network latency and Groq rate limits.
# CLASSIFIER_BACKEND=local: mandatory — without it the fail-closed classifier 400s on every
#   tool-result turn, no decision is logged, and every row reads `unknown` (silent ~6h no-op).
# Override either on the command line, e.g. `HARNESS_MODEL=groq make eval`.
eval:
	CLASSIFIER_BACKEND=local HARNESS_MODEL=mock $(PYTHON) harness/matrix.py --seeds 1
	$(PYTHON) eval/metrics.py --table --figures

# Every combination of the protection switches (#196): one results CSV each,
# then one table across them. Each combination is a full eval run.
# One seed: the mock model answers every seed identically (#199).
eval-conditions:
	CLASSIFIER_BACKEND=local HARNESS_MODEL=mock $(PYTHON) harness/matrix.py --seeds 1 --conditions
	$(PYTHON) eval/metrics.py --summary eval/results/results_classifier-*.csv

# Quick dry-run (no Docker needed — just enumerates runs)
eval-dry:
	$(PYTHON) harness/matrix.py --dry-run

# Local classifier sidecar — DeBERTa prompt-injection model (downloads ~180 MB on first run)
# Swap model: CLASSIFIER_MODEL=<hf-model-id> make classifier-up
classifier-up:
	docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.classifier.yml up -d --build

# Demo — start the HTTP tool service and the web UI (proxy must already be up).
# demo-mcp remains as a backward-compatible alias; the service is MCP-shaped,
# not a wire-compatible MCP implementation.
demo-setup:
	@if command -v uv >/dev/null 2>&1; then \
		uv sync --locked --all-groups; \
	elif test ! -x .venv/bin/python; then \
		echo "uv is required for first-time setup: https://docs.astral.sh/uv/getting-started/installation/" >&2; \
		exit 2; \
	fi
	python3 scripts/setup_demo.py

demo-check:
	python3 scripts/setup_demo.py --check

demo-check-live:
	python3 scripts/setup_demo.py --check-online

demo-tools:
	@test -f deploy/.env || (echo "deploy/.env is missing; run 'make demo-setup' first" >&2; exit 2)
	@set -a; . ./deploy/.env; set +a; exec $(PYTHON) demo/mcp_server.py

demo-mcp: demo-tools

# Sign in to the demo Gmail account once per scope (read, send); see scripts/gmail_auth.py.
gmail-auth:
	@test -n "$(SCOPE)" || (echo "usage: make gmail-auth SCOPE=read|send" >&2; exit 2)
	$(PYTHON) scripts/gmail_auth.py $(SCOPE)

demo:
	@test -f deploy/.env || (echo "deploy/.env is missing; run 'make demo-setup' first" >&2; exit 2)
	@set -a; . ./deploy/.env; set +a; exec $(PYTHON) demo/server.py

# Dual-proxy demo stack — session proxy :4000 + stateless proxy :4001, one shared
# DeBERTa classifier. Powers the live A/B delayed-exfil demo (UI mode switch).
# Both proxies run the winning switches (classifier + allowlist) from the
# generated deploy/policy.demo.yaml; only their memory differs.
demo-dual-up:
	@test -f deploy/.env || (echo "deploy/.env is missing; run 'make demo-setup' first" >&2; exit 2)
	@set -a; . ./deploy/.env; set +a; $(PYTHON) scripts/demo_policy.py
	docker compose --env-file deploy/.env \
	               -f deploy/docker-compose.yml \
	               -f deploy/docker-compose.classifier.yml \
	               -f deploy/docker-compose.demo-dual.yml up -d --build

# Replay a corpus scenario against both demo proxies (scripted turns, mock model):
#   make demo-replay SCENARIO=sc-047
demo-replay:
	@test -n "$(SCENARIO)" || (echo "usage: make demo-replay SCENARIO=sc-047" >&2; exit 2)
	@set -a; . ./deploy/.env; set +a; $(PYTHON) scripts/demo_replay.py $(SCENARIO)

demo-dual-down:
	docker compose --env-file deploy/.env \
	               -f deploy/docker-compose.yml \
	               -f deploy/docker-compose.classifier.yml \
	               -f deploy/docker-compose.demo-dual.yml down

# Freeze corpus + env snapshot for reproducibility (#47)
freeze:
	$(PYTHON) harness/freeze.py --tag
