SHELL := /bin/bash

PYTHON ?= python3
HOST ?= 127.0.0.1
PORT ?= 8765
TARGET ?=
PROFILE ?= discovery
INTERFACE ?= eth0
SNMP_CONFIG ?= switches.json

STATE_DIR ?= $(HOME)/.local/state/network-atlas
DB ?= $(STATE_DIR)/atlas.db
PID_FILE ?= $(STATE_DIR)/viewer.pid
LOG_FILE ?= $(STATE_DIR)/viewer.log

ATLAS = PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m network_atlas --db "$(DB)"

.DEFAULT_GOAL := help
.PHONY: help init run start stop restart status logs url doctor install-hooks \
	scan scan-dry scan-discovery scan-inventory arp mdns snmp classify summary \
	test privacy clean

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*## "; printf "Network Atlas\n\nUsage: make <target> [VARIABLE=value]\n\n"} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf '\nExamples:\n  make start\n  make scan-inventory TARGET=10.23.45.0/24\n  make arp INTERFACE=eth0\n  make stop\n'

init: ## Initialize the local database outside the repository
	@mkdir -p "$(STATE_DIR)"
	@$(ATLAS) init

run: init ## Run the viewer in the foreground
	@$(ATLAS) serve --host "$(HOST)" --port "$(PORT)"

start: init ## Start the viewer in the background
	@set -euo pipefail; \
	if [[ -f "$(PID_FILE)" ]]; then \
		pid="$$(cat "$(PID_FILE)" 2>/dev/null || true)"; \
		if [[ "$$pid" =~ ^[0-9]+$$ ]] && kill -0 "$$pid" 2>/dev/null && ps -p "$$pid" -o args= | grep -qE 'network_atlas.*serve'; then \
			echo "Network Atlas is already running (PID $$pid) at http://$(HOST):$(PORT)"; \
			exit 0; \
		fi; \
		rm -f "$(PID_FILE)"; \
	fi; \
	nohup env PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m network_atlas --db "$(DB)" serve --host "$(HOST)" --port "$(PORT)" >>"$(LOG_FILE)" 2>&1 & \
	echo $$! >"$(PID_FILE)"; \
	sleep 0.4; \
	pid="$$(cat "$(PID_FILE)")"; \
	if kill -0 "$$pid" 2>/dev/null; then \
		echo "Network Atlas started (PID $$pid): http://$(HOST):$(PORT)"; \
	else \
		echo "Viewer failed to start. Recent log output:" >&2; \
		tail -20 "$(LOG_FILE)" >&2 || true; \
		rm -f "$(PID_FILE)"; \
		exit 1; \
	fi

stop: ## Stop the background viewer started by make
	@set -euo pipefail; \
	if [[ ! -f "$(PID_FILE)" ]]; then echo "Network Atlas is not running (no PID file)."; exit 0; fi; \
	pid="$$(cat "$(PID_FILE)" 2>/dev/null || true)"; \
	if [[ ! "$$pid" =~ ^[0-9]+$$ ]]; then echo "Invalid PID file; refusing to signal a process." >&2; exit 1; fi; \
	if ! kill -0 "$$pid" 2>/dev/null; then rm -f "$(PID_FILE)"; echo "Removed stale PID file."; exit 0; fi; \
	if ! ps -p "$$pid" -o args= | grep -qE 'network_atlas.*serve'; then echo "PID $$pid is not a Network Atlas viewer; refusing to stop it." >&2; exit 1; fi; \
	kill -TERM "$$pid"; \
	for _ in $$(seq 1 40); do kill -0 "$$pid" 2>/dev/null || break; sleep 0.25; done; \
	if kill -0 "$$pid" 2>/dev/null; then kill -KILL "$$pid"; fi; \
	rm -f "$(PID_FILE)"; \
	echo "Network Atlas stopped."

restart: stop start ## Restart the background viewer

status: ## Show viewer status
	@set -euo pipefail; \
	if [[ -f "$(PID_FILE)" ]]; then \
		pid="$$(cat "$(PID_FILE)" 2>/dev/null || true)"; \
		if [[ "$$pid" =~ ^[0-9]+$$ ]] && kill -0 "$$pid" 2>/dev/null && ps -p "$$pid" -o args= | grep -qE 'network_atlas.*serve'; then \
			echo "running (PID $$pid) — http://$(HOST):$(PORT)"; exit 0; \
		fi; \
	fi; \
	echo "stopped"; exit 1

logs: ## Follow viewer logs
	@mkdir -p "$(STATE_DIR)"
	@touch "$(LOG_FILE)"
	@tail -f "$(LOG_FILE)"

url: ## Print the local viewer URL
	@echo "http://$(HOST):$(PORT)"

doctor: ## Check required and optional local tools
	@for tool in $(PYTHON) nmap arp-scan snmpwalk avahi-browse; do \
		if command -v "$$tool" >/dev/null 2>&1; then printf '  [ok] %s\n' "$$tool"; else printf '  [missing] %s\n' "$$tool"; fi; \
	done

install-hooks: ## Enable repository privacy checks before commits and pushes
	@git config core.hooksPath .githooks
	@echo "Git privacy hooks enabled for this clone."

scan: ## Run a scan: make scan TARGET=10.23.45.0/24 PROFILE=discovery|inventory
	@test -n "$(TARGET)" || { echo "TARGET is required, e.g. make scan TARGET=10.23.45.0/24" >&2; exit 2; }
	@$(ATLAS) scan --sudo --target "$(TARGET)" --profile "$(PROFILE)"

scan-dry: ## Print the validated Nmap command without scanning
	@test -n "$(TARGET)" || { echo "TARGET is required, e.g. make scan-dry TARGET=10.23.45.0/24" >&2; exit 2; }
	@$(ATLAS) scan --target "$(TARGET)" --profile "$(PROFILE)" --dry-run

scan-discovery: ## Discover hosts: make scan-discovery TARGET=10.23.45.0/24
	@$(MAKE) --no-print-directory scan TARGET="$(TARGET)" PROFILE=discovery

scan-inventory: ## Inventory services and OSes: make scan-inventory TARGET=10.23.45.0/24
	@$(MAKE) --no-print-directory scan TARGET="$(TARGET)" PROFILE=inventory

arp: ## Discover the local LAN: make arp INTERFACE=eth0
	@$(ATLAS) arp --sudo --interface "$(INTERFACE)"

mdns: ## Collect mDNS/DNS-SD advertisements (requires avahi-daemon)
	@$(ATLAS) mdns

snmp: ## Collect switch topology: make snmp SNMP_CONFIG=switches.json
	@test -f "$(SNMP_CONFIG)" || { echo "Missing $(SNMP_CONFIG); copy config.example.json and keep the result untracked." >&2; exit 2; }
	@$(ATLAS) snmp --config "$(SNMP_CONFIG)"

classify: ## Recalculate device classifications without scanning
	@$(ATLAS) classify

summary: ## Print the current inventory summary
	@$(ATLAS) summary

test: ## Run the offline test suite
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests -v
	@node --check network_atlas/static/app.js 2>/dev/null || true

privacy: ## Check tracked files and Git history for private data and secrets
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/privacy_check.py
	@if command -v gitleaks >/dev/null 2>&1; then \
		gitleaks dir . --no-banner --redact --no-color && gitleaks git . --no-banner --redact --no-color; \
	else echo "gitleaks not installed; built-in privacy checks passed."; fi

clean: ## Remove generated Python caches from the working tree
	@find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
	@find . -depth -type d -name '__pycache__' -empty -delete
