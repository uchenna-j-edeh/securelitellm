.PHONY: lint test test-e2e e2e-up e2e-down up down dev eval eval-dry freeze classifier-up demo demo-mcp demo-dual-up demo-dual-down

# Well-known key used exclusively for E2E tests — never the production key.
E2E_KEY := sk-test-e2e-key

lint:
	uv run ruff check .
	uv run ruff format --check .

test:
	uv run pytest tests/ -v --ignore=tests/test_e2e.py

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
	uv run pytest tests/test_e2e.py -v -m e2e

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
	CLASSIFIER_BACKEND=local HARNESS_MODEL=mock uv run python harness/matrix.py --seeds 3
	uv run python eval/metrics.py --table --figures

# Quick dry-run (no Docker needed — just enumerates runs)
eval-dry:
	uv run python harness/matrix.py --dry-run

# Local classifier sidecar — DeBERTa prompt-injection model (downloads ~180 MB on first run)
# Swap model: CLASSIFIER_MODEL=<hf-model-id> make classifier-up
classifier-up:
	docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.classifier.yml up -d --build

# Demo — start the MCP tool server and the web UI (proxy must already be up via make up)
demo-mcp:
	uv run python demo/mcp_server.py

demo:
	@set -a && [ -f deploy/.env ] && . deploy/.env; set +a; \
	LITELLM_MASTER_KEY="$${LITELLM_MASTER_KEY}" \
	uv run python demo/server.py

# Dual-proxy demo stack — session proxy :4000 + stateless proxy :4001, one shared
# DeBERTa classifier. Powers the live A/B delayed-exfil demo (UI mode switch).
demo-dual-up:
	docker compose -f deploy/docker-compose.yml \
	               -f deploy/docker-compose.classifier.yml \
	               -f deploy/docker-compose.demo-dual.yml up -d --build

demo-dual-down:
	docker compose -f deploy/docker-compose.yml \
	               -f deploy/docker-compose.classifier.yml \
	               -f deploy/docker-compose.demo-dual.yml down

# Freeze corpus + env snapshot for reproducibility (#47)
freeze:
	uv run python harness/freeze.py --tag
