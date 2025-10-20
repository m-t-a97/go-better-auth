.PHONY: help build run test clean install migrate-up migrate-down docker-build docker-run

# Variables
APP_NAME=go-better-auth
BINARY_PATH=./bin/$(APP_NAME)

# Help command
help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# Build commands
build: ## Build the package (library)
	@echo "Building $(APP_NAME) package..."
	@go build ./...
	@echo "Build complete!"

build-linux: ## Build example for Linux (if main.go exists)
	@echo "Building for Linux..."
	@[ -f cmd/main.go ] && GOOS=linux GOARCH=amd64 go build -o $(BINARY_PATH)-linux ./cmd || echo "No cmd/main.go found"

build-windows: ## Build example for Windows (if main.go exists)
	@echo "Building for Windows..."
	@[ -f cmd/main.go ] && GOOS=windows GOARCH=amd64 go build -o $(BINARY_PATH).exe ./cmd || echo "No cmd/main.go found"

build-mac: ## Build example for macOS (if main.go exists)
	@echo "Building for macOS..."
	@[ -f cmd/main.go ] && GOOS=darwin GOARCH=amd64 go build -o $(BINARY_PATH)-mac ./cmd || echo "No cmd/main.go found"

# Run commands
run: ## Run example (if cmd/main.go exists)
	@[ -f cmd/main.go ] && go run ./cmd || echo "No cmd/main.go found. This is a library package."

dev: ## Run with hot reload (requires air)
	@air

# Test commands
test: ## Run tests
	@echo "Running tests..."
	@go test -v ./...

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Dependency management
install: ## Install dependencies
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

deps-update: ## Update dependencies
	@echo "Updating dependencies..."
	@go get -u ./...
	@go mod tidy

# Database commands
migrate-up: ## Run database migrations (PostgreSQL)
	@echo "Running migrations..."
	@psql $(DATABASE_URL) -f migrations/postgres.sql

migrate-down: ## Rollback database migrations
	@echo "Rolling back migrations..."
	@psql $(DATABASE_URL) -c "DROP TABLE IF EXISTS verifications, accounts, sessions, users CASCADE;"

db-reset: migrate-down migrate-up ## Reset database
	@echo "Database reset complete"

# Docker commands
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t $(APP_NAME):latest .

docker-run: ## Run Docker container
	@echo "Running Docker container..."
	@docker run -p 3000:3000 --env-file .env $(APP_NAME):latest

docker-compose-up: ## Start services with docker-compose
	@docker-compose up -d

docker-compose-down: ## Stop services with docker-compose
	@docker-compose down

# Clean commands
clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html
	@go clean

# Code quality
lint: ## Run linter
	@echo "Running linter..."
	@golangci-lint run

fmt: ## Format code
	@echo "Formatting code..."
	@go fmt ./...

vet: ## Run go vet
	@echo "Running go vet..."
	@go vet ./...

# Generate commands
generate: ## Generate code (mocks, etc.)
	@echo "Generating code..."
	@go generate ./...

# All-in-one commands
all: clean install build check ## Clean, install deps, build, and run all checks

check: fmt vet lint test ## Run all checks (format, vet, lint, test)

# Default target
.DEFAULT_GOAL := help
