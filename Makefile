# Shortcuts for the Compose development stack (compose.yaml +
# compose.override.yaml). Nothing here mutates Kubernetes; see the README for
# the kubectl/helm flow, and `make deploy-tag` for the one line that joins them.

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
.PHONY: help version up down clean logs ps seed psql shell build watch restart smoke deploy-tag

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

seed: ## Register the simulated OpenStack fleet
	$(COMPOSE) --profile seed run --rm seed

psql: ## Open a psql shell on the database
	$(COMPOSE) exec timescaledb sh -c 'psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"'

shell: ## Open a shell in the app container
	$(COMPOSE) exec api sh

build: ## Rebuild the app image
	$(COMPOSE) build api

watch: ## Run in the foreground, rebuilding when pyproject.toml or uv.lock change
	$(COMPOSE) watch

restart: ## Restart the app container
	$(COMPOSE) restart api

deploy-tag: ## Print the kubectl command that points the Deployment at this build
	@echo "kubectl set image deploy/fastapi fastapi=$(IMAGE)"
	@echo "kubectl rollout status deploy/fastapi"

smoke: ## Hit the endpoints that prove the stack works end to end
	@curl -fsS localhost:$${API_PORT:-8000}/readyz && echo
	@curl -fsS localhost:$${API_PORT:-8000}/machines | head -c 400 && echo
	@curl -fsS localhost:$${API_PORT:-8000}/admin/collector && echo
