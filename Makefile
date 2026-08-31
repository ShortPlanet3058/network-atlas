SHELL := /bin/bash

# ---------------------------------------------------------------------------
# Configuration. Override any of these on the command line:
#   make scan TARGET=10.23.45.0/24 PROFILE=deep
# ---------------------------------------------------------------------------
PYTHON      ?= python3
HOST        ?= 127.0.0.1
PORT        ?= 8765

# The compose files read ATLAS_PORT. Exporting it from PORT means one variable
# controls both the native viewer and the container; without this,
# `make docker-up PORT=8766` printed 8766 while the container still bound 8765.
export ATLAS_PORT := $(PORT)

TARGET      ?=
PROFILE     ?= standard
INTERFACE   ?=
DURATION    ?= 60
LIMIT       ?= 40
SEVERITY    ?=
SNMP_CONFIG ?= switches.json

STATE_DIR   ?= $(HOME)/.local/state/network-atlas
DB          ?= $(STATE_DIR)/atlas.db
PID_FILE    ?= $(STATE_DIR)/viewer.pid
LOG_FILE    ?= $(STATE_DIR)/viewer.log

# Container image coordinates. Set DOCKER_USER to your Docker Hub account to
# push; the compose file reads ATLAS_IMAGE with the same default.
DOCKER_USER ?= shortplanet
IMAGE_NAME  ?= network-atlas

# Read from the code so a published tag can never disagree with what it contains.
VERSION     := $(shell $(PYTHON) -c 'import network_atlas; print(network_atlas.__version__)' 2>/dev/null)
TAG         ?= latest
REPOSITORY  ?= $(if $(DOCKER_USER),$(DOCKER_USER)/$(IMAGE_NAME),$(IMAGE_NAME))
IMAGE       ?= $(REPOSITORY):$(TAG)

# Provenance stamped into the image. The Kali base image carries its own created
# and revision labels, so without these the published image reports Kali's build
# date and git revision as its own.
VCS_REF     := $(shell git rev-parse --short=8 HEAD 2>/dev/null || echo unknown)
BUILD_DATE  := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# arm64 is what makes a Raspberry Pi deployment possible; arm/v7 covers the
# older 32-bit models.
PLATFORMS   ?= linux/amd64,linux/arm64
SETUP_STATE ?= $(STATE_DIR)/docker-setup.state

# Documentation lives in the GitHub wiki; referenced from a few messages.
WIKI ?= https://github.com/ShortPlanet3058/network-atlas/wiki

ATLAS = PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m network_atlas --db "$(DB)"

# Compose v2 exists in two shapes: the CLI plugin (`docker compose`, from Docker's
# own repository) and a standalone binary (`docker-compose`, which is what Debian
# packages -- it does not ship the plugin at all). Features are equivalent, so use
# whichever is installed.
COMPOSE ?= $(shell docker compose version >/dev/null 2>&1 && echo "docker compose" || echo "docker-compose")

# Shared guard used by start/stop/status: prints the viewer's PID and succeeds
# only when the PID file names a live Network Atlas process. Defined once so the
# three targets cannot drift apart on what counts as "running".
define VIEWER_PID
viewer_pid() { local pid; [[ -f "$(PID_FILE)" ]] || return 1; pid="$$(cat "$(PID_FILE)" 2>/dev/null || true)"; [[ "$$pid" =~ ^[0-9]+$$ ]] || return 1; kill -0 "$$pid" 2>/dev/null || return 1; ps -p "$$pid" -o args= | grep -qE 'network_atlas.*serve' || return 1; printf '%s' "$$pid"; }
endef

.DEFAULT_GOAL := help
.PHONY: help init ensure-db run start stop restart status logs url doctor install-hooks \
	scan scan-dry sweep passive names neighbours web-identity \
	audit findings events monitor monitor-off wifi \
	snmp classify summary check \
	docker-setup docker-revert docker-build docker-up docker-down docker-logs \
	macvlan-create macvlan-remove \
	docker-shell docker-push docker-push-single docker-pull \
	version release-tag \
	wiki-sync wiki-check test check privacy clean

help: ## Show available commands
	@awk 'BEGIN { \
		FS = ":.*## "; \
		printf "Network Atlas\n\nUsage: make <target> [VARIABLE=value]\n" \
	} \
	/^##@ / { printf "\n\033[1m%s\033[0m\n", substr($$0, 5); next } \
	/^[a-zA-Z0-9_-]+:.*## / { printf "  %-16s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@printf '\nExamples:\n'
	@printf '  make start                    Start the viewer\n'
	@printf '  make sweep                    Discover everything, then audit\n'
	@printf '  make findings                 What to fix, with remediation\n'
	@printf '  make monitor                  Keep the map current automatically\n'
	@printf '  make docker-up                Run it in a container\n\n'

##@ Viewer

init: ## Create or migrate the local database
	@mkdir -p "$(STATE_DIR)"
	@$(ATLAS) init

# Same thing without the JSON, for targets that only need the database to exist.
ensure-db:
	@mkdir -p "$(STATE_DIR)"
	@$(ATLAS) init >/dev/null

run: ensure-db ## Run the viewer in the foreground
	@$(ATLAS) serve --host "$(HOST)" --port "$(PORT)"

start: ensure-db ## Start the viewer in the background
	@set -euo pipefail; $(VIEWER_PID); \
	if pid="$$(viewer_pid)"; then \
		echo "Already running (PID $$pid): http://$(HOST):$(PORT)"; exit 0; \
	fi; \
	if ss -ltn 2>/dev/null | grep -q ":$(PORT) "; then \
		echo "Port $(PORT) is already in use on this host." >&2; \
		echo "" >&2; \
		if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx network-atlas; then \
			echo "The Network Atlas container is running, and it uses host networking --" >&2; \
			echo "so it holds the host's port $(PORT) directly. Run one or the other:" >&2; \
			echo "    make docker-down          # stop the container" >&2; \
			echo "    make start PORT=8766      # or put the native viewer elsewhere" >&2; \
		else \
			echo "Something else is listening there. Find it with:" >&2; \
			echo "    ss -ltnp | grep :$(PORT)" >&2; \
			echo "then stop it, or start the viewer elsewhere:" >&2; \
			echo "    make start PORT=8766" >&2; \
		fi; \
		exit 2; \
	fi; \
	rm -f "$(PID_FILE)"; \
	before=$$(wc -l <"$(LOG_FILE)" 2>/dev/null || echo 0); \
	nohup env PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m network_atlas --db "$(DB)" \
		serve --host "$(HOST)" --port "$(PORT)" >>"$(LOG_FILE)" 2>&1 & \
	echo $$! >"$(PID_FILE)"; \
	sleep 0.5; \
	if pid="$$(viewer_pid)"; then \
		echo "Started (PID $$pid): http://$(HOST):$(PORT)"; \
		banner="$$(tail -n +$$((before + 1)) "$(LOG_FILE)" 2>/dev/null \
			| sed -n '/They are shown once/,/^  └/p' \
			| sed -n '/username/p;/password/p' || true)"; \
		if [ -n "$$banner" ]; then \
			echo ""; \
			echo "The viewer created its login. This is the only time it is shown:"; \
			echo ""; \
			printf '%s\n' "$$banner"; \
			echo ""; \
			echo "Change it from the account button in the viewer, or run:"; \
			echo "    make account-reset"; \
		fi; \
	else \
		echo "Viewer failed to start. Output from this attempt:" >&2; \
		tail -n +$$((before + 1)) "$(LOG_FILE)" >&2 || true; \
		rm -f "$(PID_FILE)"; exit 1; \
	fi

stop: ## Stop the background viewer
	@set -euo pipefail; $(VIEWER_PID); \
	if ! pid="$$(viewer_pid)"; then \
		rm -f "$(PID_FILE)"; echo "Not running."; exit 0; \
	fi; \
	kill -TERM "$$pid"; \
	for _ in $$(seq 1 40); do kill -0 "$$pid" 2>/dev/null || break; sleep 0.25; done; \
	if kill -0 "$$pid" 2>/dev/null; then kill -KILL "$$pid"; fi; \
	rm -f "$(PID_FILE)"; \
	echo "Stopped."

restart: stop start ## Restart the background viewer

status: ## Show whether the viewer is running
	@set -euo pipefail; $(VIEWER_PID); \
	if pid="$$(viewer_pid)"; then \
		echo "running (PID $$pid) — http://$(HOST):$(PORT)"; \
	elif ss -ltn 2>/dev/null | grep -q ":$(PORT) "; then \
		if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx network-atlas; then \
			echo "stopped — but the container is serving on $(PORT) (make docker-logs)"; \
		else \
			echo "stopped — but something else is listening on $(PORT) (ss -ltnp | grep :$(PORT))"; \
		fi; \
	else \
		echo "stopped"; \
	fi

logs: ## Follow viewer logs
	@mkdir -p "$(STATE_DIR)"; touch "$(LOG_FILE)"; tail -f "$(LOG_FILE)"

##@ Discovery

scan: ## Active scan: make scan [TARGET=10.23.45.0/24] [PROFILE=quick|standard|deep]
	@$(ATLAS) scan --profile "$(PROFILE)" $(if $(TARGET),--target "$(TARGET)",)

scan-dry: ## Print the target and Nmap command without sending packets
	@$(ATLAS) scan --profile "$(PROFILE)" --dry-run $(if $(TARGET),--target "$(TARGET)",)

sweep: ## Recommended first run: caches, scan, names, passive listen, audit
	@$(ATLAS) neighbours
	@$(MAKE) --no-print-directory scan
	@$(ATLAS) names $(if $(TARGET),--target "$(TARGET)",)
	@$(MAKE) --no-print-directory passive
	@$(ATLAS) audit

passive: ## Discover by listening only: make passive [DURATION=120] [INTERFACE=eth0]
	@$(ATLAS) passive --duration "$(DURATION)" $(if $(INTERFACE),--interface "$(INTERFACE)",)

names: ## Resolve names over DNS, mDNS and NetBIOS
	@$(ATLAS) names $(if $(TARGET),--target "$(TARGET)",)

neighbours: ## Import the kernel ARP and IPv6 neighbour caches
	@$(ATLAS) neighbours

web-identity: ## Identify devices from their web interface (reads the landing page)
	@$(ATLAS) web-identity

snmp: ## Collect switch topology and ARP tables: make snmp SNMP_CONFIG=switches.json
	@test -f "$(SNMP_CONFIG)" || { echo "Missing $(SNMP_CONFIG); copy config.example.json and keep the result untracked." >&2; exit 2; }
	@$(ATLAS) snmp --config "$(SNMP_CONFIG)"

wifi: ## Map Wi-Fi clients to access points (needs sudo; drops the connection)
	@echo "This puts the wireless card into monitor mode and will disconnect it."
	@sudo -E env PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m network_atlas --db "$(DB)" \
		wifi --duration "$(DURATION)" $(if $(INTERFACE),--interface "$(INTERFACE)",)

##@ Findings and monitoring

audit: ## Check the inventory for issues and record how to fix them
	@$(ATLAS) audit

findings: ## List open findings: make findings [SEVERITY=high]
	@$(ATLAS) findings $(if $(SEVERITY),--severity "$(SEVERITY)",)

events: ## Show what has changed on the network
	@$(ATLAS) events --limit $(LIMIT)

monitor: ## Turn on continuous monitoring (runs while the viewer runs)
	@$(ATLAS) monitor on

monitor-off: ## Turn off continuous monitoring
	@$(ATLAS) monitor off

##@ Inventory maintenance

classify: ## Recalculate device classifications without scanning
	@$(ATLAS) classify

summary: ## Print the inventory summary as JSON
	@$(ATLAS) summary

doctor: ## Report local tools, detected network and scan capabilities
	@for tool in $(PYTHON) ip nmap tshark dumpcap p0f nbtscan avahi-browse avahi-resolve \
		searchsploit sslscan airodump-ng arp-scan snmpwalk; do \
		if command -v "$$tool" >/dev/null 2>&1; then printf '  [ok]      %s\n' "$$tool"; \
		else printf '  [missing] %s\n' "$$tool"; fi; \
	done
	@$(ATLAS) doctor

##@ Container

docker-setup: ## Prepare this machine to run the container (reversible)
	@set -euo pipefail; \
	mkdir -p "$(STATE_DIR)"; \
	echo "Checking what the container needs on this machine."; \
	ok=1; \
	if command -v docker >/dev/null 2>&1; then \
		printf '  [ok]      docker (%s)\n' "$$(docker --version | awk '{print $$3}' | tr -d ,)"; \
	else \
		printf '  [missing] docker — install it first: https://docs.docker.com/engine/install/\n'; ok=0; \
	fi; \
	if docker compose version >/dev/null 2>&1; then \
		printf '  [ok]      compose v2 as a CLI plugin (docker compose)\n'; \
	elif command -v docker-compose >/dev/null 2>&1; then \
		printf '  [ok]      compose as the standalone binary (docker-compose %s)\n' \
			"$$(docker-compose version --short 2>/dev/null)"; \
		printf '            Debian packages this rather than the plugin; the Makefile\n'; \
		printf '            uses whichever it finds, so nothing more is needed.\n'; \
	else \
		printf '  [missing] compose — install docker-compose (Debian) or\n'; \
		printf '            docker-compose-plugin (Docker repository)\n'; ok=0; \
	fi; \
	if [[ "$$ok" == 1 ]] && docker info >/dev/null 2>&1; then \
		printf '  [ok]      daemon reachable without sudo\n'; \
	elif [[ "$$ok" == 1 ]]; then \
		if id -nG | tr ' ' '\n' | grep -qx docker; then \
			printf '  [warn]    in the docker group but the daemon is unreachable — is it running?\n'; \
			printf '            try: sudo systemctl start docker\n'; \
		else \
			printf '  [action]  adding %s to the docker group (needs sudo)\n' "$$USER"; \
			sudo usermod -aG docker "$$USER"; \
			echo "docker-group-added=$$USER" >>"$(SETUP_STATE)"; \
			printf '            done — log out and back in for it to take effect\n'; \
		fi; \
	fi; \
	if [[ "$$(uname -s)" != Linux ]]; then \
		printf '  [warn]    not Linux: host networking maps to a VM, so broadcast\n'; \
		printf '            discovery and LLDP/CDP will not see your LAN.\n'; \
		printf '            See %s\n' "$(WIKI)/Docker"; \
	fi; \
	printf '\nNothing else is required: the image grants capabilities to its own\n'; \
	printf 'binaries, so no daemon configuration is changed.\n'; \
	printf 'Next: make docker-build && make docker-up\n'; \
	printf 'Undo anything this changed with: make docker-revert\n'

docker-revert: ## Undo docker-setup and remove the container, image and data
	@set -euo pipefail; \
	echo "This removes the Network Atlas container, image and its data volume."; \
	read -r -p "Continue? [y/N] " answer; \
	case "$$answer" in y|Y|yes|YES) ;; *) echo "Cancelled."; exit 0;; esac; \
	$(COMPOSE) down --volumes --remove-orphans 2>/dev/null || true; \
	docker image rm "$(IMAGE)" 2>/dev/null || true; \
	docker image rm "$(IMAGE_NAME):$(TAG)" 2>/dev/null || true; \
	if [[ -f "$(SETUP_STATE)" ]] && grep -q '^docker-group-added=' "$(SETUP_STATE)"; then \
		user="$$(grep '^docker-group-added=' "$(SETUP_STATE)" | tail -1 | cut -d= -f2)"; \
		printf 'Removing %s from the docker group (added by docker-setup).\n' "$$user"; \
		sudo gpasswd -d "$$user" docker || true; \
		grep -v '^docker-group-added=' "$(SETUP_STATE)" >"$(SETUP_STATE).tmp" || true; \
		mv "$(SETUP_STATE).tmp" "$(SETUP_STATE)"; \
	fi; \
	echo "Reverted. Your native install and its database are untouched."

macvlan-create: ## Create a macvlan network so the container gets its own LAN address
	@set -euo pipefail; \
	if [[ "$$(uname -s)" != Linux ]]; then \
		echo "macvlan needs the host kernel to own the interface; it does nothing on this platform." >&2; \
		exit 2; \
	fi; \
	if docker network inspect atlas-lan >/dev/null 2>&1; then \
		echo "Network atlas-lan already exists."; exit 0; \
	fi; \
	iface="$(INTERFACE)"; \
	if [[ -z "$$iface" ]]; then iface="$$(ip -4 route show default | awk 'NR==1{print $$5}')"; fi; \
	gateway="$$(ip -4 route show default | awk 'NR==1{print $$3}')"; \
	cidr="$$(ip -o -4 addr show dev "$$iface" scope global | awk 'NR==1{print $$4}')"; \
	if [[ -z "$$iface" || -z "$$gateway" || -z "$$cidr" ]]; then \
		echo "Could not detect the interface, gateway and subnet. Pass INTERFACE=eth0." >&2; exit 2; \
	fi; \
	read -r subnet range <<<"$$($(PYTHON) -c 'import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1], strict=False); h=list(n.hosts()); print(n, ipaddress.ip_network(f"{h[-8]}/29", strict=False))' "$$cidr")"; \
	echo "Creating atlas-lan: parent=$$iface subnet=$$subnet gateway=$$gateway range=$$range"; \
	echo "The range reserves the last few addresses of your subnet. Make sure your"; \
	echo "DHCP server does not hand those out."; \
	docker network create -d macvlan --subnet="$$subnet" --gateway="$$gateway" \
		--ip-range="$$range" -o parent="$$iface" atlas-lan >/dev/null; \
	echo "Done. Start it with: $(COMPOSE) -f docker-compose.macvlan.yml up -d"

macvlan-remove: ## Remove the macvlan network
	@docker network rm atlas-lan 2>/dev/null && echo "Removed atlas-lan." || echo "No atlas-lan network."

docker-pull: ## Pull the published image instead of building it
	@set -euo pipefail; \
	if [[ -z "$(DOCKER_USER)" ]] && [[ -z "$${ATLAS_IMAGE:-}" ]]; then \
		echo "Set DOCKER_USER or ATLAS_IMAGE to say which published image to pull:" >&2; \
		echo "    make docker-pull DOCKER_USER=someone" >&2; \
		exit 2; \
	fi; \
	docker pull "$${ATLAS_IMAGE:-$(IMAGE)}"

docker-build: ## Build the container image locally
	@VCS_REF="$(VCS_REF)" BUILD_DATE="$(BUILD_DATE)" $(COMPOSE) build

docker-up: ## Start the container (host networking; full discovery on Linux only)
	@set -euo pipefail; \
	if ss -ltn 2>/dev/null | grep -q ":$(PORT) "; then \
		echo "Port $(PORT) is already in use on this host." >&2; \
		echo "" >&2; \
		echo "Host networking means the container uses the host's ports directly, so it" >&2; \
		echo "cannot share $(PORT) with anything else -- including a natively running" >&2; \
		echo "viewer. Either stop that:" >&2; \
		echo "    make stop" >&2; \
		echo "or run the container on a different port:" >&2; \
		echo "    make docker-up PORT=8766" >&2; \
		exit 2; \
	fi; \
	$(COMPOSE) up -d; \
	echo "Viewer: http://127.0.0.1:$(PORT) — see the wiki for the caveats: https://github.com/ShortPlanet3058/network-atlas/wiki/Docker"

docker-down: ## Stop the container (the data volume is kept)
	@$(COMPOSE) down

docker-logs: ## Follow container logs
	@$(COMPOSE) logs -f

docker-shell: ## Open a shell inside the running container
	@$(COMPOSE) exec network-atlas bash

docker-push: ## Publish to Docker Hub, tagged :VERSION and :latest
	@set -euo pipefail; \
	if [[ -z "$(DOCKER_USER)" ]]; then \
		echo "Set DOCKER_USER to your Docker Hub account." >&2; exit 2; \
	fi; \
	if [[ -z "$(VERSION)" ]]; then \
		echo "Could not read the version from network_atlas.__version__." >&2; exit 2; \
	fi; \
	if ! docker buildx version >/dev/null 2>&1; then \
		echo "docker buildx is not installed, so only this machine's architecture" >&2; \
		echo "can be built -- a Raspberry Pi could not run the result." >&2; \
		echo "" >&2; \
		echo "    sudo apt install docker-buildx" >&2; \
		echo "" >&2; \
		echo "To publish single-architecture anyway: make docker-push-single" >&2; \
		exit 2; \
	fi; \
	echo "Publishing $(REPOSITORY) version $(VERSION) for $(PLATFORMS)."; \
	if ! docker buildx inspect atlas-builder >/dev/null 2>&1; then \
		docker buildx create --name atlas-builder --driver docker-container --bootstrap >/dev/null; \
	fi; \
	docker buildx build --builder atlas-builder --platform "$(PLATFORMS)" \
		--tag "$(REPOSITORY):$(VERSION)" --tag "$(REPOSITORY):latest" \
		--label org.opencontainers.image.version="$(VERSION)" \
		--build-arg VCS_REF="$(VCS_REF)" \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		--push .; \
	echo ""; \
	echo "Published:"; \
	echo "  $(REPOSITORY):$(VERSION)"; \
	echo "  $(REPOSITORY):latest"; \
	echo "Users get it with: docker compose pull && docker compose up -d"

docker-describe: ## Upload the Docker Hub repository description from .github/
	@bash scripts/push-dockerhub-description.sh "$(REPOSITORY)"

docker-push-single: ## Publish only this machine's architecture (no buildx needed)
	@set -euo pipefail; \
	if [[ -z "$(DOCKER_USER)" || -z "$(VERSION)" ]]; then \
		echo "Need DOCKER_USER and a readable version." >&2; exit 2; \
	fi; \
	echo "Building $(REPOSITORY):$(VERSION) for $$(uname -m) only."; \
	echo "A Raspberry Pi will NOT be able to run this image."; \
	docker build -t "$(REPOSITORY):$(VERSION)" -t "$(REPOSITORY):latest" \
		--build-arg VCS_REF="$(VCS_REF)" \
		--build-arg BUILD_DATE="$(BUILD_DATE)" .; \
	docker push "$(REPOSITORY):$(VERSION)"; \
	docker push "$(REPOSITORY):latest"

account: ## Show the viewer's login account
	@$(ATLAS) account

account-reset: ## Set a new random viewer password and print it
	@$(ATLAS) account --reset-password

version: ## Print the version that would be published
	@echo "$(VERSION)"

release-tag: ## Tag the current commit as vVERSION and push the tag
	@set -euo pipefail; \
	if [[ -n "$$(git status --porcelain)" ]]; then \
		echo "Working tree is dirty; commit before tagging a release." >&2; exit 2; \
	fi; \
	if git rev-parse "v$(VERSION)" >/dev/null 2>&1; then \
		echo "Tag v$(VERSION) already exists. Bump __version__ first." >&2; exit 2; \
	fi; \
	git tag -a "v$(VERSION)" -m "Network Atlas $(VERSION)"; \
	git push origin "v$(VERSION)"; \
	echo "Tagged and pushed v$(VERSION)."

##@ Development

wiki-sync: ## Publish wiki/*.md to the GitHub wiki
	@scripts/sync-wiki.sh

wiki-check: ## Verify the wiki sources link to pages that exist
	@$(PYTHON) scripts/check-wiki.py

test: ## Run the offline test suite
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests -v
	@node --check network_atlas/static/app.js 2>/dev/null || true

check: ## Everything CI would run: tests, wiki links, then the privacy scan
	@$(MAKE) --no-print-directory test
	@$(MAKE) --no-print-directory wiki-check
	@$(MAKE) --no-print-directory privacy

privacy: ## Check tracked files and history for private data and secrets
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/privacy_check.py
	@if command -v gitleaks >/dev/null 2>&1; then \
		gitleaks dir . --no-banner --redact --no-color && gitleaks git . --no-banner --redact --no-color; \
	else echo "gitleaks not installed; built-in privacy checks passed."; fi

install-hooks: ## Enable repository privacy checks before commits and pushes
	@git config core.hooksPath .githooks
	@echo "Git privacy hooks enabled for this clone."

clean: ## Remove generated Python caches from the working tree
	@find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
