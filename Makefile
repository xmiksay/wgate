# wgate — build/test/lint entry points. See README.md.

SHELL := /usr/bin/env bash
CARGO_BUILD_JOBS ?= 4
export CARGO_BUILD_JOBS

# Load nvm (if installed) and select web/.nvmrc.
NVM = export NVM_DIR="$$HOME/.nvm"; [ -s "$$NVM_DIR/nvm.sh" ] && . "$$NVM_DIR/nvm.sh"; nvm use >/dev/null 2>&1 || true;
MUSL = x86_64-unknown-linux-musl
# Local settings (WGATE_DATABASE_URL, …; see .env.example), sourced by the shell, not
# parsed by make (which would mangle `$` and `#`); quote values as in shell.
DOTENV = set -a; [ -f .env ] && . ./.env; set +a;

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: deps
deps: ## Install web dependencies
	cd web && $(NVM) npm ci

# Built only when its sources changed: a fresh web/dist would make build.rs re-stage it
# and the server recompile.
# Directories too: a deleted or renamed file changes only its directory's mtime.
WEB_SRC := $(shell find web/src web/public web/scripts 2>/dev/null) web/index.html \
	web/package.json web/package-lock.json web/.nvmrc web/vite.config.ts \
	$(wildcard web/tsconfig*.json)

.PHONY: web
web: web/dist/index.html ## Build the Vue UI into web/dist (when its sources changed)

web/dist/index.html: $(WEB_SRC)
	cd web && $(NVM) npm run build

.PHONY: build
build: web ## Debug build of the whole workspace
	cargo build

.PHONY: run-server
run-server: web ## Run the portal (WGATE_SERVER_CONFIG or /etc/wgate/server.toml)
	cargo run -p wgate -- server

.PHONY: migrate
migrate: ## Apply database migrations (WGATE_DATABASE_URL, see .env.example)
	$(DOTENV) cargo run -p wgate -- migrate

.PHONY: run-agent
run-agent: ## Run the agent as root (needs CAP_NET_ADMIN)
	cargo build -p wgate
	$(DOTENV) sudo -E target/debug/wgate agent

.PHONY: lint
# The UI is built first: the server embeds web/dist (build.rs), and the tests serve it.
lint: web ## clippy -D warnings, rustfmt check, eslint, vue-tsc, API types up to date
	cargo clippy --workspace --all-targets -- -D warnings
	cargo fmt --all --check
	cd web && $(NVM) npm run lint && npm run typecheck && npm run api:check

.PHONY: fmt
fmt: ## Format Rust sources
	cargo fmt --all

.PHONY: test
test: web test-unit test-int ## Unit + integration tests

.PHONY: test-unit
test-unit: ## Rust unit tests
	cargo test --workspace --lib --bins

.PHONY: test-int
# Each db test starts its own Postgres container; 4 threads cap them at 4 at once.
test-int: ## Rust integration tests (tests/; netns ones are #[ignore]d; db ones need Docker)
	cargo test --workspace --test '*' -- --test-threads=4

.PHONY: golden
golden: ## Rewrite golden files (core outputs, docs/openapi.json + its TS types) — review the diff!
	UPDATE_GOLDEN=1 cargo test -p wgate-core --lib
	UPDATE_GOLDEN=1 cargo test -p wgate-server --test openapi
	cd web && $(NVM) npm run api:gen

# Test binaries are built as the user and only executed under sudo, so target/
# stays user-owned.
.PHONY: test-netns
test-netns: ## Root-only tests in network namespaces (sudo, nft, wireguard, python3, Docker)
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E' \
		cargo test -p wgate-agent --test 'netns*' -- --ignored --test-threads=1
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E' \
		cargo test -p wgate --test 'netns*' -- --ignored --test-threads=1

.PHONY: release
release: web ## Static musl release binary + sha256 in dist/
	cargo build --release --locked --target $(MUSL) -p wgate
	mkdir -p dist
	cp target/$(MUSL)/release/wgate dist/wgate-$(MUSL)
	cd dist && sha256sum wgate-$(MUSL) > wgate-$(MUSL).sha256

.PHONY: clean
clean: ## Remove build outputs
	cargo clean
	rm -rf web/dist dist
