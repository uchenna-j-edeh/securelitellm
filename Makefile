.PHONY: lint test test-e2e up down dev eval eval-dry freeze demo-up demo

lint:
	uv run ruff check .
	uv run ruff format --check .

test:
	uv run pytest tests/ -v --ignore=tests/test_e2e.py

test-e2e:
	uv run pytest tests/test_e2e.py -v -m e2e

up:
	docker compose -f deploy/docker-compose.yml up -d --build

down:
	docker compose -f deploy/docker-compose.yml down

dev:
	docker compose -f deploy/docker-compose.yml up --build

# M6 — run full evaluation matrix and compute metrics
eval:
	uv run python harness/matrix.py --seeds 3
	uv run python eval/metrics.py --table --figures

# Quick dry-run (no Docker needed — just enumerates runs)
eval-dry:
	uv run python harness/matrix.py --dry-run

# Demo — prompt injection → exfiltration attack + defense
demo-up:
	docker compose -f deploy/docker-compose.yml -f demo/docker-compose.yml up -d --build

demo: demo-up
	@until curl -sf http://localhost:4000/health/liveliness > /dev/null 2>&1; do sleep 2; done
	uv run python demo/run.py

# Freeze corpus + env snapshot for reproducibility (#47)
freeze:
	uv run python harness/freeze.py --tag
