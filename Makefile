.PHONY: build test run clean vet lint help install install-callback-user install-callback-system uninstall-callback test-callback test-sandbox test-prereq test-no-llm test-cleanup

BIN := pilot
PKG := ./cmd/pilot
CALLBACK_SRC := ansible_callback/pilot_diagnose.py

USER_CALLBACK_DIR := $(HOME)/.ansible/plugins/callback
SYSTEM_CALLBACK_DIR := /etc/ansible/plugins/callback

help:          	## Show this help
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-25s %s\n", $$1, $$2}'

build:         	## Compile the binary (with debug info, for local dev)
	go build -o $(BIN) $(PKG)

release:       	## Compile stripped release binary
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN) $(PKG)
	@echo "Built $(BIN) (stripped, no debug info)"

test:          	## Run unit tests
	go test ./...

vet:           	## Run go vet
	go vet ./...

lint:          	## Run golangci-lint
	golangci-lint run ./...

test-race:     	## Run tests with the race detector
	go test -race -count=1 ./...

run-demo: build	## Run the demo script
	./scripts/demo.sh

chat: build    	## Start interactive chat
	./$(BIN) chat

clean:         	## Remove build artifacts
	rm -f $(BIN)
	rm -rf dist/

install: build 	## Install binary to /usr/local/bin
	install -m 0755 $(BIN) /usr/local/bin/$(BIN)

install-callback-user: ## Install callback to ~/.ansible/plugins/callback/
	install -d $(USER_CALLBACK_DIR)
	install -m 0644 $(CALLBACK_SRC) $(USER_CALLBACK_DIR)/
	@echo "✓ Installed to $(USER_CALLBACK_DIR)/pilot_diagnose.py"
	@echo ""
	@echo "Enable in ansible.cfg:"
	@echo "  [defaults]"
	@echo "  callbacks_enabled = pilot"
	@echo ""
	@echo "Or set env var: ANSIBLE_CALLBACKS_ENABLED=pilot"

install-callback-system: ## Install callback plugin to /etc/ansible/plugins/callback/
	install -d $(SYSTEM_CALLBACK_DIR)
	install -m 0644 $(CALLBACK_SRC) $(SYSTEM_CALLBACK_DIR)/
	@echo "✓ Installed to $(SYSTEM_CALLBACK_DIR)/pilot_diagnose.py"

uninstall-callback: ## Remove installed callback plugin
	rm -f $(USER_CALLBACK_DIR)/pilot_diagnose.py
	rm -f $(SYSTEM_CALLBACK_DIR)/pilot_diagnose.py
	@echo "✓ Removed"

test-callback: ## Run Python callback unit tests
	cd ansible_callback && python3 -m unittest test_pilot_diagnose.py -v

test-sandbox: ## Run L1+L2+L3 sandbox smoke test (see TESTING.md)
	./scripts/test-sandbox.sh

test-no-llm: ## Run L1+L2+L3 smoke test without ollama (raw ansible only)
	./scripts/test-sandbox.sh --no-llm

test-prereq: ## Check go / docker / ansible / ollama / image availability
	@command -v go >/dev/null              && echo "go OK"              || (echo "go MISSING"; exit 1)
	@command -v docker >/dev/null          && echo "docker OK"          || (echo "docker MISSING"; exit 1)
	@command -v ansible-playbook >/dev/null && echo "ansible OK"        || (echo "ansible MISSING"; exit 1)
	@docker ps >/dev/null 2>&1              && echo "docker daemon OK"   || (echo "docker daemon NOT REACHABLE"; exit 1)
	@docker images -q geerlingguy/docker-ubuntu2204-ansible:latest 2>/dev/null | grep -q . && echo "ansible image OK" || (echo "ansible image MISSING; docker pull geerlingguy/docker-ubuntu2204-ansible:latest"; exit 1)
	@curl -sf --max-time 3 http://localhost:11434/api/tags >/dev/null && echo "ollama OK" || echo "ollama not reachable (L3 will use --no-llm)"

test-cleanup: ## Remove all pilot-sandbox / pilot-dexec containers
	./scripts/test-sandbox.sh --cleanup-only

playbook-lint: ## L1 syntax (blocking) + L2 lint (advisory) over ALL playbooks — no VM needed
	@fail=0; \
	for pb in playbooks/apply/*.yml playbooks/verify/*.yml; do \
	  [ -e "$$pb" ] || continue; \
	  printf '── syntax-check %s\n' "$$pb"; \
	  ansible-playbook --syntax-check "$$pb" || fail=1; \
	done; \
	if [ $$fail -ne 0 ]; then echo "✗ syntax check failed (blocking)"; exit 1; fi; \
	echo "✓ syntax clean"; \
	echo "── duplicate YAML key check (repo-wide — .yml AND .yaml, so roster/vars files count too)"; \
	python3 scripts/check-yaml-duplicate-keys.py || exit 1; \
	if command -v ansible-lint >/dev/null 2>&1; then \
	  echo "── ansible-lint playbooks/ (advisory — does not block)"; \
	  ansible-lint playbooks/ || echo "⚠ ansible-lint reported findings (advisory; run 'ansible-lint playbooks/' to review)"; \
	else \
	  echo "ansible-lint not installed — skipping L2 (pip install ansible-lint)"; \
	fi

install-hooks: ## Enable the git pre-commit hook (runs playbook-lint before each commit)
	git config core.hooksPath .githooks
	@echo "✓ git hooksPath set to .githooks — playbook-lint now runs on commit"
	@echo "  bypass a single commit with: git commit --no-verify"

.PHONY: help build test vet run-demo chat clean install install-callback-user install-callback-system uninstall-callback test-callback test-sandbox test-prereq test-no-llm test-cleanup playbook-lint install-hooks pb-check-spec pb-init pb-iter pb-verify pb-idempotent pb-baseline pb-report pb-lint pb-clean

# ---------------------------------------------------------------------------
# Ansible playbook 開發迭代（見 docs/ansible-playbook-development.md）
#
# 用法：
#   make pb-init SPEC=docs/verification/bastion.md
#   make pb-iter  SPEC=docs/verification/bastion.md
#   make pb-verify SPEC=docs/verification/bastion.md
#   make pb-idempotent SPEC=docs/verification/bastion.md [RUNS=5]
#   make pb-baseline SPEC=docs/verification/bastion.md
#   make pb-report SPEC=docs/verification/bastion.md
#   make pb-lint SPEC=docs/verification/bastion.md
#   make pb-clean SPEC=docs/verification/bastion.md
#
# 變數：
#   SPEC     — spec 檔案路徑（必填）
#   PLAYBOOK — 覆寫預設 playbook 路徑（預設 playbooks/<host>.yml）
#   VERIFY   — 覆寫預設 verify 腳本（預設 scripts/verify-<host>.sh）
#   INVENTORY— inventory 路徑（預設 inventory/hosts）
#   RUNS     — idempotent 連跑次數（預設 3）
#   VERIF_ROOT — 報告目錄（預設 .verification）
# ---------------------------------------------------------------------------

PB_SPEC ?= $(SPEC)
PB_PLAYBOOK ?= $(PLAYBOOK)
PB_VERIFY ?= $(VERIFY)
PB_INVENTORY ?= $(INVENTORY)
PB_RUNS ?= $(RUNS)
PB_VERIF_ROOT ?= $(VERIF_ROOT)

PB_ENV = PB_SPEC='$(PB_SPEC)' PB_PLAYBOOK='$(PB_PLAYBOOK)' PB_VERIFY='$(PB_VERIFY)' \
         PB_INVENTORY='$(PB_INVENTORY)' PB_RUNS='$(PB_RUNS)' PB_VERIF_ROOT='$(PB_VERIF_ROOT)'

pb-check-spec: ## Verify SPEC variable is set and file exists (internal helper)
	@test -n "$(PB_SPEC)" || (echo "ERROR: SPEC=<path> is required. e.g. make pb-iter SPEC=docs/verification/bastion.md" && exit 2)
	@test -f "$(PB_SPEC)" || (echo "ERROR: spec file not found: $(PB_SPEC)" && echo "  Tip: cp docs/verification-spec-template.md $(PB_SPEC)" && exit 2)

pb-init: ## Copy verification spec template to SPEC path
	@test -n "$(PB_SPEC)" || (echo "ERROR: SPEC=<path> required" && exit 2)
	@mkdir -p $$(dirname $(PB_SPEC))
	@cp docs/verification-spec-template.md $(PB_SPEC)
	@echo "✓ Copied template -> $(PB_SPEC)"
	@echo "  1. Edit $(PB_SPEC) — fill in the checklist"
	@echo "  2. make pb-lint   SPEC=$(PB_SPEC)"
	@echo "  3. make pb-iter   SPEC=$(PB_SPEC)"

pb-iter: pb-check-spec ## Run full L1..L7 iteration cycle (syntax, lint, dry-run, apply, verify, idempotent, diff)
	$(PB_ENV) ./scripts/pb-iter.sh iter

pb-verify: pb-check-spec ## Run only L5 verify against current state
	$(PB_ENV) ./scripts/pb-iter.sh verify

pb-idempotent: pb-check-spec ## Run playbook N times (RUNS, default 3); expect changed=0 after first
	$(PB_ENV) ./scripts/pb-iter.sh idempotent

pb-baseline: pb-check-spec ## Diff latest report vs previous report
	$(PB_ENV) ./scripts/pb-iter.sh baseline

pb-report: pb-check-spec ## List recent baseline reports for this spec
	$(PB_ENV) ./scripts/pb-iter.sh report

pb-lint: pb-check-spec ## L1 syntax + L2 lint only
	$(PB_ENV) ./scripts/pb-iter.sh lint

pb-clean: pb-check-spec ## Remove baseline reports for this spec (interactive confirm)
	$(PB_ENV) ./scripts/pb-iter.sh clean

.PHONY: pb-check-spec pb-init pb-iter pb-verify pb-idempotent pb-baseline pb-report pb-lint pb-clean release

