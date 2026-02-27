.PHONY: proto proto-lint proto-breaking build test lint clean init ci ci-lint hooks release

# Auto-detect main branch name (master or main)
MAIN_BRANCH := $(shell git symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@')
ifeq ($(MAIN_BRANCH),)
  MAIN_BRANCH := main
endif

# Proto generation
proto:
	buf generate

proto-lint:
	buf lint

proto-breaking:
	buf breaking --against '.git#branch=$(MAIN_BRANCH)'

# Go build targets
build:
	go build ./...

test:
	go test ./...

test-v:
	go test -v ./...

lint:
	go vet ./...

clean:
	rm -f proto/iam/v1/*.pb.go

# Local CI guard — mirrors GitHub Actions checks
ci:
	@FAILED=0; \
	echo "========================================"; \
	echo "  Local CI Guard"; \
	echo "========================================"; \
	echo ""; \
	echo "[1/5] actionlint"; \
	if actionlint -shellcheck="" .github/workflows/*.yml; then \
		echo "  ✓ actionlint passed"; \
	else \
		echo "  ✗ actionlint FAILED"; FAILED=1; \
	fi; \
	echo ""; \
	echo "[2/5] buf lint"; \
	if buf lint; then \
		echo "  ✓ buf lint passed"; \
	else \
		echo "  ✗ buf lint FAILED"; FAILED=1; \
	fi; \
	echo ""; \
	echo "[3/5] golangci-lint"; \
	if golangci-lint run --timeout=5m; then \
		echo "  ✓ golangci-lint passed"; \
	else \
		echo "  ✗ golangci-lint FAILED"; FAILED=1; \
	fi; \
	echo ""; \
	echo "[4/5] go vet"; \
	if go vet ./...; then \
		echo "  ✓ go vet passed"; \
	else \
		echo "  ✗ go vet FAILED"; FAILED=1; \
	fi; \
	echo ""; \
	echo "[5/5] go test -race"; \
	if go test -race ./...; then \
		echo "  ✓ tests passed"; \
	else \
		echo "  ✗ tests FAILED"; FAILED=1; \
	fi; \
	echo ""; \
	echo "========================================"; \
	if [ $$FAILED -eq 0 ]; then \
		echo "  All checks passed"; \
	else \
		echo "  CI FAILED"; exit 1; \
	fi; \
	echo "========================================"

# Lightweight CI — lint checks only (fast)
ci-lint:
	@FAILED=0; \
	echo "========================================"; \
	echo "  CI Lint (quick)"; \
	echo "========================================"; \
	echo ""; \
	echo "[1/2] actionlint"; \
	if actionlint -shellcheck="" .github/workflows/*.yml; then \
		echo "  ✓ actionlint passed"; \
	else \
		echo "  ✗ actionlint FAILED"; FAILED=1; \
	fi; \
	echo ""; \
	echo "[2/2] buf lint"; \
	if buf lint; then \
		echo "  ✓ buf lint passed"; \
	else \
		echo "  ✗ buf lint FAILED"; FAILED=1; \
	fi; \
	echo ""; \
	echo "========================================"; \
	if [ $$FAILED -eq 0 ]; then \
		echo "  All lint checks passed"; \
	else \
		echo "  Lint FAILED"; exit 1; \
	fi; \
	echo "========================================"

# Install git hooks
hooks:
	@cp scripts/pre-push .git/hooks/pre-push
	@chmod +x .git/hooks/pre-push
	@echo "pre-push hook installed (git push will auto-run make ci)"

# Tag-based release
release:
	@if [ -z "$(VERSION)" ]; then \
		echo "Usage: make release VERSION=v0.1.0"; exit 1; \
	fi; \
	echo ""; \
	echo "========================================"; \
	echo "  Release $(VERSION)"; \
	echo "========================================"; \
	echo ""; \
	case "$(VERSION)" in v[0-9]*) ;; *) echo "ERROR: VERSION must start with 'v' (e.g. v0.1.0)"; exit 1;; esac; \
	BRANCH=$$(git rev-parse --abbrev-ref HEAD); \
	if [ "$$BRANCH" != "$(MAIN_BRANCH)" ]; then \
		echo "ERROR: Must be on $(MAIN_BRANCH) branch (currently on $$BRANCH)"; exit 1; \
	fi; \
	if [ -n "$$(git status --porcelain)" ]; then \
		echo "ERROR: Working directory not clean"; exit 1; \
	fi; \
	if git rev-parse "$(VERSION)" >/dev/null 2>&1; then \
		echo "ERROR: Tag $(VERSION) already exists"; exit 1; \
	fi; \
	git fetch origin $(MAIN_BRANCH) --quiet; \
	LOCAL=$$(git rev-parse HEAD); \
	REMOTE=$$(git rev-parse origin/$(MAIN_BRANCH)); \
	if [ "$$LOCAL" != "$$REMOTE" ]; then \
		echo "ERROR: $(MAIN_BRANCH) not synced with remote"; exit 1; \
	fi; \
	echo "Running CI checks..."; \
	$(MAKE) ci; \
	echo ""; \
	echo "Ready to release $(VERSION)"; \
	printf "Continue? [y/N] "; read CONFIRM; \
	if [ "$$CONFIRM" != "y" ] && [ "$$CONFIRM" != "Y" ]; then \
		echo "Aborted."; exit 1; \
	fi; \
	git tag -a "$(VERSION)" -m "Release $(VERSION)"; \
	git push origin "$(VERSION)"; \
	echo ""; \
	echo "Released $(VERSION)"

# Install dependencies (one-time setup)
init: hooks
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/bufbuild/buf/cmd/buf@latest
