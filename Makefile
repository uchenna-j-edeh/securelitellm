.PHONY: lint test up down dev

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
