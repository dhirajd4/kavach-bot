.PHONY: setup test lint fmt up down logs tunnel quicktunnel replay migrate psql eval playground image-eval apk-eval lock audit

VENV := .venv
PY := $(VENV)/bin/python

setup:            ## local venv for tests/linting, installed from the hash-locked dev set
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --require-hashes --no-deps -r requirements/dev.txt
	$(VENV)/bin/pip install --no-deps --no-build-isolation -e .

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

image-eval:       ## labelled images → running bot (real OCR in Docker); needs `make up` + dry run
	$(PY) -m kavach.tools.image_eval tests/fixtures/images

apk-eval:         ## harmless generated APKs → running bot (sandboxed static analysis)
	$(PY) scripts/make_apk_fixtures.py
	$(PY) -m kavach.tools.image_eval tests/fixtures/apks

# Supply chain: every package in the tree (sub-dependencies too) must be at least 14 days old
# at lock time, and is pinned by SHA-256. Bump LOCK_CUTOFF deliberately, then `make lock audit`.
LOCK_CUTOFF := 2026-10-01T23:59:59Z
UV_LOCK := $(VENV)/bin/uv pip compile --universal --python-version 3.12 --generate-hashes \
	--exclude-newer $(LOCK_CUTOFF) --quiet

lock:             ## regenerate requirements/*.txt (hash-locked) from pyproject.toml
	$(UV_LOCK) pyproject.toml requirements/build.in -o requirements/runtime.txt
	$(UV_LOCK) pyproject.toml requirements/build.in requirements/sandbox.in --extra apk \
		-o requirements/sandbox.txt
	$(UV_LOCK) pyproject.toml requirements/build.in --extra apk --extra dev -o requirements/dev.txt

audit:            ## known-vulnerability scan (OSV / PyPI advisories) of every locked package
	$(VENV)/bin/pip-audit --require-hashes --disable-pip -r requirements/runtime.txt
	$(VENV)/bin/pip-audit --require-hashes --disable-pip -r requirements/sandbox.txt
	$(VENV)/bin/pip-audit --require-hashes --disable-pip -r requirements/dev.txt
