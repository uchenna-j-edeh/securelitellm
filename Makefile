.PHONY: lint test test-e2e up down dev eval eval-dry freeze classifier-up

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

# Local classifier sidecar — DeBERTa prompt-injection model (downloads ~180 MB on first run)
# Swap model: CLASSIFIER_MODEL=<hf-model-id> make classifier-up
classifier-up:
	docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.classifier.yml up -d --build

# Freeze corpus + env snapshot for reproducibility (#47)
freeze:
	uv run python harness/freeze.py --tag
