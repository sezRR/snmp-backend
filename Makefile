# Shortcuts for the Compose development stack. Application settings and
# credentials come from `.env`; copy `.env.example` before the first run.

COMPOSE ?= docker compose

# src/app/__init__.py is the single source of truth for the version — it is what
# the running app reports from `GET /` — and the image tag follows it, so a bump
# is one edit. Read with sed rather than by importing the package: no dependency
# on a host python, no import side effects. Override for a throwaway build:
#
#   make up APP_VERSION=0.7.0-rc1
#
# Exported because Compose expands ${APP_VERSION} in compose.yaml from the
# environment, which also takes precedence over anything in `.env`.
APP_VERSION ?= $(shell sed -n 's/^__version__ = "\(.*\)"/\1/p' src/app/__init__.py)
export APP_VERSION

IMAGE := fastapi-demo:$(APP_VERSION)

.DEFAULT_GOAL := help
.PHONY: help version up down clean logs ps psql shell build watch restart migrate \
        check test reencrypt revision history

help: ## List targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | awk -F':.*?## ' '{printf "  \033[36m%-11s\033[0m %s\n", $$1, $$2}'

version: ## Print the version read from src/app/__init__.py and the tag it builds
	@echo "$(APP_VERSION)  ->  $(IMAGE)"

up: ## Build if needed and start the stack, waiting until it is serving
	$(COMPOSE) up -d --build --wait

down: ## Stop the stack, keeping the database volume
	$(COMPOSE) down

clean: ## Stop the stack and delete the database volume
	$(COMPOSE) down -v

logs: ## Follow the app's logs
	$(COMPOSE) logs -f api

ps: ## Show container and health status
	$(COMPOSE) ps

psql: ## Open a psql shell on the database
	$(COMPOSE) exec timescaledb sh -c 'psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"'

shell: ## Open a shell in the app container
	$(COMPOSE) exec api sh

build: ## Rebuild the app image
	$(COMPOSE) build api

watch: ## Run in the foreground, rebuilding when pyproject.toml or uv.lock change
	$(COMPOSE) watch

restart: ## Recreate the app container to apply .env changes
	$(COMPOSE) up -d --force-recreate --wait api

# Alembic authoring targets run on the host against the database port published
# by compose.yaml, so `.env` uses PGHOST=localhost and PGPORT=15432.

migrate: ## Apply migrations against the Compose database
	$(COMPOSE) exec api python -m app.db.migrate

check: ## Fail if db/tables.py has drifted from the migrations
	uv run alembic check

test: ## Run unit tests
	PYTHONPATH=src uv run python -m unittest discover -v

reencrypt: ## Move stored SNMP credentials onto SNMP_CREDENTIAL_ACTIVE_KEY
	$(COMPOSE) exec api python -m app.db.reencrypt

revision: ## Autogenerate a revision — make revision m="add widgets"
	@test -n "$(m)" || { echo 'usage: make revision m="what changed"'; exit 2; }
	@# The api container bind-mounts ./src and reloads on change, and boots with
	@# DB_AUTO_MIGRATE=true — so the moment this file lands it is applied to the
	@# dev database, reviewed or not. Read it before it runs, and `make clean` if
	@# you then change your mind.
	uv run alembic revision --autogenerate -m "$(m)"

history: ## Show the migration history and where this database sits
	uv run alembic history --verbose
	@uv run alembic current
