.PHONY: all build run clean test test-fast vet fmt fmt-check ci deps help

BINARY_NAME=prs

all: build

build: ## Build the binary
	@echo "Building..."
	go build -o $(BINARY_NAME) main.go

run: ## Run the application
	@echo "Running..."
	go run main.go

clean: ## Clean build artifacts and reports
	@echo "Cleaning..."
	go clean
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME).exe
	rm -f prs_report_*.html
	rm -f prs_report_*.json

test: ## Run tests
	@echo "Testing..."
	go test -vet=off ./...

test-fast: ## Run tests (same as test for now)
	@echo "Testing (fast)..."
	go test -vet=off ./...

vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

fmt: ## Format all Go files
	@echo "Formatting..."
	@files=$$(rg --files -g "*.go"); if [ -n "$$files" ]; then gofmt -w $$files; fi

fmt-check: ## Check formatting (fails if changes needed)
	@echo "Checking format..."
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "$$out"; exit 1; fi

ci: fmt-check test vet ## Local CI pipeline
	@echo "CI checks passed."

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
