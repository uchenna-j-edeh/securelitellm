.PHONY: lint test up down dev eval eval-dry freeze

lint:
	uv run ruff check .
	uv run ruff format --check .

test:
	uv run pytest tests/ -v

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

# Freeze corpus + env snapshot for reproducibility (#47)
freeze:
	uv run python harness/freeze.py --tag
