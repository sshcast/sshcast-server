SHELL := /bin/bash
spec ?= sshcast-server.spec
outdir ?= .

SPEC_ABS := $(abspath $(spec))
OUTDIR_ABS := $(abspath $(outdir))
REPO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)

.PHONY: srpm

srpm:
	@set -euo pipefail; \
	if ! command -v go >/dev/null 2>&1 || ! command -v rpmbuild >/dev/null 2>&1; then \
		dnf -y install golang git-core rpm-build; \
	fi; \
	SPEC="$(SPEC_ABS)"; \
	if [ -z "$$SPEC" ] || [ -d "$$SPEC" ]; then SPEC="$(REPO_ROOT)/sshcast-server.spec"; fi; \
	OUTDIR="$(OUTDIR_ABS)"; \
	ROOT="$(REPO_ROOT)"; \
	VER=$$(grep -E '^Version:' "$$SPEC" | awk '{print $$2}'); \
	if [ -z "$$VER" ]; then echo "Failed to parse Version from $$SPEC" >&2; exit 1; fi; \
	mkdir -p "$$OUTDIR"; \
	STAGE=$$(mktemp -d); \
	trap 'rm -rf "$$STAGE"' EXIT; \
	STAGE_SRC="$$STAGE/sshcast-server-$$VER"; \
	mkdir -p "$$STAGE_SRC"; \
	tar --exclude='.git' --exclude='./vendor' --exclude='./sshcast-server' --exclude='*.rpm' --exclude='*.src.rpm' -cf - -C "$$ROOT" . | tar -xf - -C "$$STAGE_SRC"; \
	(cd "$$STAGE_SRC" && GOWORK=off go mod vendor); \
	tar -C "$$STAGE" --exclude='.git' -czf "$$STAGE/sshcast-server-$$VER.tar.gz" "sshcast-server-$$VER"; \
	cp "$$SPEC" "$$STAGE/"; \
	rpmbuild -bs \
		--define "_topdir $$STAGE/rpmbuild" \
		--define "_sourcedir $$STAGE" \
		--define "_specdir $$STAGE" \
		--define "_srcrpmdir $$OUTDIR" \
		"$$STAGE/$$(basename "$$SPEC")"
