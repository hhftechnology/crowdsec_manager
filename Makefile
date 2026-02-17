.PHONY: setup dev dev-backend dev-frontend build build-backend build-frontend test test-backend test-frontend lint lint-backend lint-frontend docker-build docker-up docker-down clean

# ============================================================
# Setup
# ============================================================

setup: ## Install all dependencies
	go mod download
	cd ui && pnpm install

# ============================================================
# Development
# ============================================================

dev: ## Run backend and frontend concurrently
	@echo "Starting backend and frontend..."
	@make dev-backend &
	@make dev-frontend
	@wait

dev-backend: ## Run Go backend with hot reload
	go run ./cmd/server

dev-frontend: ## Run Vite dev server
	cd ui && pnpm dev

# ============================================================
# Build
# ============================================================

build: build-frontend build-backend ## Build everything

build-backend: ## Build Go binary
	CGO_ENABLED=1 go build -o bin/crowdsec-manager ./cmd/server

build-frontend: ## Build React frontend
	cd ui && pnpm build

# ============================================================
# Test
# ============================================================

test: test-backend test-frontend ## Run all tests

test-backend: ## Run Go tests
	go test ./internal/... -v -count=1

test-frontend: ## Run Vitest
	cd ui && pnpm test:unit

# ============================================================
# Lint
# ============================================================

lint: lint-backend lint-frontend ## Lint everything

lint-backend: ## Lint Go code
	go vet ./...
	go fmt ./...

lint-frontend: ## Lint frontend
	cd ui && pnpm lint

# ============================================================
# Docker
# ============================================================

docker-build: ## Build Docker image
	docker build -t crowdsec-manager:latest .

docker-up: ## Start with docker-compose
	docker compose up -d

docker-down: ## Stop docker-compose
	docker compose down

docker-dev: ## Start dev environment
	docker compose -f docker-compose.dev.yml up -d

# ============================================================
# Utility
# ============================================================

clean: ## Clean build artifacts
	rm -rf bin/
	rm -rf ui/dist/
	go clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
