.PHONY: data index build up down clean test bench info help

CARGO := . "$(HOME)/.cargo/env" && cargo

REFS  := resources/references.json.gz
MCC   := resources/mcc_risk.json
NORM  := resources/normalization.json
INDEX := resources/index.bin

GH_RAW := https://github.com/zanfranceschi/rinha-de-backend-2026/raw/main/resources

help:
	@echo "Targets:"
	@echo "  make data    fetch references.json.gz, mcc_risk.json, normalization.json"
	@echo "  make index   build resources/index.bin from references (~5s, deterministic)"
	@echo "  make build   docker compose build (depends on index)"
	@echo "  make up      docker compose up (builds first)"
	@echo "  make down    docker compose down -v"
	@echo "  make bench   run api in MODE=bench (Mac/dev only)"
	@echo "  make test    cargo test"
	@echo "  make clean   remove built index.bin"

data: $(REFS) $(MCC) $(NORM)

$(REFS):
	@mkdir -p resources
	curl -sSfL $(GH_RAW)/references.json.gz -o $@

$(MCC):
	@mkdir -p resources
	curl -sSfL $(GH_RAW)/mcc_risk.json -o $@

$(NORM):
	@mkdir -p resources
	curl -sSfL $(GH_RAW)/normalization.json -o $@

index: $(INDEX)

$(INDEX): $(REFS)
	$(CARGO) run --release -p build-index -- $(REFS) $@

build: index
	docker compose build

up: build
	docker compose up

down:
	docker compose down -v

bench: index
	$(CARGO) run --release -p api

test:
	$(CARGO) test

clean:
	rm -f $(INDEX)

info:
	@echo "Workspace state:"
	@echo "  REFS:  $$( [ -f $(REFS) ] && du -h $(REFS) | cut -f1 || echo MISSING )"
	@echo "  INDEX: $$( [ -f $(INDEX) ] && du -h $(INDEX) | cut -f1 || echo MISSING )"
	@$(CARGO) --version
