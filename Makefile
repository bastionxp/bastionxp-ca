# Copyright 2026 Ampas Labs Inc.
# SPDX-License-Identifier: Apache-2.0

.PHONY: build build-linux test cover test-e2e e2e-tools test-container test-samba test-keycloak test-cert-manager lint spec fuzz

# The version from git: the tag, or "dev" before the first one.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

build:
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o bin/bxp ./cmd/bxp

# Static Linux binaries, e.g. to copy to a server from a Mac:
# bin/linux_amd64/bxp and bin/linux_arm64/bxp.
build-linux:
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath \
			-ldflags "-X main.version=$(VERSION)" -o bin/linux_$$arch/bxp ./cmd/bxp || exit 1; \
	done

test:
	go test ./...

# Statement coverage of BastionXP CA's own code (cmd/bxp and internal/,
# not the test stand-ins) by the unit and integration tests. A line counts
# when any test runs it, also a test in another package. Per function:
# go tool cover -func=coverage.out; as a page: go tool cover -html=coverage.out
COVER_PKGS = $(shell go list ./cmd/... ./internal/... | grep -v 'test$$' | paste -sd, -)

cover:
	@go test -coverpkg=$(COVER_PKGS) -coverprofile=coverage.out ./... > coverage.log 2>&1 || (cat coverage.log; rm -f coverage.log; exit 1)
	@rm -f coverage.log
	@go tool cover -func=coverage.out | tail -1 | awk '{print "statement coverage:", $$NF}'

lint:
	go vet ./...
	go vet -tags e2e ./test/e2e
	@go run ./test/spec -check
	@test -z "$$(gofmt -l .)" || (echo "run gofmt on:"; gofmt -l .; exit 1)
	@missing=$$(find . \( -path ./.git -o -path ./.tools \) -prune -o -type f \( -name '*.go' -o -name Dockerfile -o -name Makefile -o -path './.github/workflows/*' \) -print \
		| grep -v '/testdata/fuzz/' | xargs grep -L 'SPDX-License-Identifier: Apache-2.0'); \
		test -z "$$missing" || (echo "add the copyright header (see CONTRIBUTING.md) to:"; echo "$$missing"; exit 1)

# The test specification's case tables (docs/testing/), from the tests.
# make lint checks they are up to date.
spec:
	go run ./test/spec

# End-to-end tests: build the real bxp binary and run it as people do,
# with real ACME and SCEP clients. The clients are downloaded once into
# .tools/, at the versions below; openssl and ssh-keygen come from the
# system. See test/e2e/README.md.
E2E_TOOLS        := $(CURDIR)/.tools
CERTBOT_VERSION  := 5.10.0
LEGO_VERSION     := v4.35.2
SCEP_VERSION     := v2.3.0
ACMESH_VERSION   := 3.1.6
CADDY_VERSION    := v2.11.9
KIND_VERSION     := v0.33.0

test-e2e: e2e-tools
	BXP_E2E_TOOLS=$(E2E_TOOLS) go test -tags e2e -count=1 -v ./test/e2e

e2e-tools: $(E2E_TOOLS)/.certbot-$(CERTBOT_VERSION) $(E2E_TOOLS)/.lego-$(LEGO_VERSION) \
	$(E2E_TOOLS)/.scepclient-$(SCEP_VERSION) $(E2E_TOOLS)/.acmesh-$(ACMESH_VERSION) \
	$(E2E_TOOLS)/.caddy-$(CADDY_VERSION)

$(E2E_TOOLS)/.certbot-$(CERTBOT_VERSION):
	rm -rf $(E2E_TOOLS)/certbot && python3 -m venv $(E2E_TOOLS)/certbot
	$(E2E_TOOLS)/certbot/bin/pip install --quiet certbot==$(CERTBOT_VERSION)
	mkdir -p $(E2E_TOOLS)/bin && ln -sf ../certbot/bin/certbot $(E2E_TOOLS)/bin/certbot
	touch $@

$(E2E_TOOLS)/.lego-$(LEGO_VERSION):
	GOBIN=$(E2E_TOOLS)/bin go install github.com/go-acme/lego/v4/cmd/lego@$(LEGO_VERSION)
	touch $@

$(E2E_TOOLS)/.scepclient-$(SCEP_VERSION):
	GOBIN=$(E2E_TOOLS)/bin go install github.com/micromdm/scep/v2/cmd/scepclient@$(SCEP_VERSION)
	touch $@

$(E2E_TOOLS)/.caddy-$(CADDY_VERSION):
	GOBIN=$(E2E_TOOLS)/bin go install github.com/caddyserver/caddy/v2/cmd/caddy@$(CADDY_VERSION)
	touch $@

$(E2E_TOOLS)/.acmesh-$(ACMESH_VERSION):
	rm -rf $(E2E_TOOLS)/acme.sh
	git -c advice.detachedHead=false clone --quiet --depth 1 --branch $(ACMESH_VERSION) https://github.com/acmesh-official/acme.sh $(E2E_TOOLS)/acme.sh
	mkdir -p $(E2E_TOOLS)/bin && ln -sf ../acme.sh/acme.sh $(E2E_TOOLS)/bin/acme.sh
	touch $@

# The container image, built here and used as the docs say: init, serve,
# a certificate from this machine, a clean stop. Needs Docker.
test-container:
	docker build -t bastionxp-ca:smoke --build-arg VERSION=$(VERSION) \
		--build-arg COMMIT="$$(git rev-parse --verify -q HEAD)" \
		--build-arg COMMIT_TIME="$$(git log -1 --format=%cI 2>/dev/null)" .
	test/container/smoke.sh bastionxp-ca:smoke

# Tests against a real Active Directory (Samba in Docker). Needs Docker.
test-samba:
	BXP_TEST_SAMBA=1 go test -count=1 -v -run Samba ./internal/ldap

# Tests of the browser login against Keycloak in Docker. Needs Docker.
test-keycloak:
	BXP_TEST_KEYCLOAK=1 go test -count=1 -v -run Keycloak ./cmd/bxp

# cert-manager in a Kubernetes cluster made with kind (Kubernetes in
# Docker), getting certificates from BastionXP CA running in the cluster
# from its container image. Needs Docker; takes a few minutes. The kind
# version fixes the Kubernetes version (v0.33.0: Kubernetes v1.37.0); the
# cert-manager version is in test/kubernetes.
test-cert-manager: $(E2E_TOOLS)/.kind-$(KIND_VERSION)
	BXP_TEST_CERT_MANAGER=1 BXP_E2E_TOOLS=$(E2E_TOOLS) go test -count=1 -v -timeout 30m ./test/kubernetes

$(E2E_TOOLS)/.kind-$(KIND_VERSION):
	GOBIN=$(E2E_TOOLS)/bin go install sigs.k8s.io/kind@$(KIND_VERSION)
	touch $@

# Fuzz every parser of untrusted input, one after the other. Their seeds
# also run with "make test". Longer: make fuzz FUZZTIME=5m
FUZZTIME ?= 30s
FUZZ_TARGETS = \
	internal/acme:FuzzACME \
	internal/server:FuzzOCSP internal/server:FuzzCSR internal/server:FuzzRenew \
	internal/scep:FuzzPKIOperation internal/scep:FuzzChallenge \
	internal/token:FuzzVerify \
	internal/keyfile:FuzzParse \
	internal/ldap:FuzzUserFilter internal/ldap:FuzzGroupFilter \
	internal/policy:FuzzCheckDomain

fuzz:
	$(foreach t,$(FUZZ_TARGETS),go test -run='^$$' -fuzz='^$(word 2,$(subst :, ,$(t)))$$' -fuzztime=$(FUZZTIME) ./$(word 1,$(subst :, ,$(t))) && ) true
