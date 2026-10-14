.PHONY: setup test lint fmt up down logs tunnel quicktunnel replay migrate psql eval playground

VENV := .venv
PY := $(VENV)/bin/python

setup:            ## local venv for tests/linting
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -e '.[dev]'

test:
	$(VENV)/bin/pytest -q

lint:
	$(VENV)/bin/ruff check src tests migrations
	$(VENV)/bin/ruff format --check src tests migrations
	$(VENV)/bin/mypy

fmt:
	$(VENV)/bin/ruff format src tests migrations
	$(VENV)/bin/ruff check --fix src tests migrations

up:               ## postgres, redis, migrations, api, worker
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f api worker

tunnel:           ## named Cloudflare tunnel (CLOUDFLARE_TUNNEL_TOKEN in .env)
	docker compose --profile tunnel up -d tunnel

quicktunnel:      ## throwaway trycloudflare.com URL; see `docker compose logs quicktunnel`
	docker compose --profile quicktunnel up -d quicktunnel
	@sleep 6; docker compose logs quicktunnel | grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' | tail -1

replay:           ## needs WHATSAPP_DRY_RUN=true in .env
	REDIS_URL=redis://localhost:6379/0 $(PY) -m kavach.tools.replay

migrate:
	docker compose run --rm migrate

psql:
	docker compose exec postgres psql -U kavach kavach

eval:             ## offline eval (no Docker): eval/messages.csv → console + eval-report.html
	$(PY) -m kavach.tools.evaluate --html eval-report.html; open eval-report.html

playground:       ## chat with the local bot in your browser (needs `make up` + dry run)
	open http://localhost:8000/playground
