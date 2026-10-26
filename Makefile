PYTHON ?= python3

.PHONY: spec-check
spec-check:
	$(PYTHON) scripts/check-specs.py

.PHONY: design-check ui-check
design-check:
	$(PYTHON) scripts/check-design.py

# Optional browser gate. Supply development-only modules and browser via environment.
ui-check:
	node scripts/check-ui.cjs

# Production console: locked local build tools, no runtime Node dependency.
.PHONY: console-install console-check console-build console-browser-check
console-install:
	cd web && npm ci --ignore-scripts --no-audit

console-check:
	cd web && npm run check

console-build:
	cd web && npm run build

console-browser-check: console-build
	ASSERVAT_CONSOLE_BROWSER_TEST=1 TMPDIR="$(ASSERVAT_BUILD_TMP)" go test -count=1 -run '^TestConsole(Browser|NativeRestart)WithBuiltPackage$$' -v ./test/integration

.PHONY: openapi-check
openapi-check:
	$(PYTHON) scripts/check-openapi.py

.PHONY: live-check
live-check:
	$(PYTHON) scripts/check-live-watch.py

.PHONY: architecture-check
architecture-check:
	$(PYTHON) scripts/check-architecture.py

.PHONY: download-check
download-check:
	$(PYTHON) scripts/check-downloads.py

.PHONY: investigation-check
investigation-check:
	$(PYTHON) scripts/check-investigation.py

# Product component gates. The integration target creates/removes owned fixtures.
.PHONY: go-check go-architecture-check context-integration
go-check: manifest-schema-check permission-schema-check policy-schema-check permission-crd-check control-schema-check start-crd-check retention-crd-check capacity-crd-check investigation-schema-check
	go vet ./...
	# Preserve race/count/deadline checks with exact sequential Kubernetes groups.
	$(PYTHON) scripts/test-go-shards.py
	$(PYTHON) scripts/check-go-tests.py

go-architecture-check:
	$(PYTHON) scripts/check-go-architecture.py

context-integration:
	$(PYTHON) scripts/test-context-storage.py

.PHONY: go-vuln-check
go-vuln-check:
	go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

ASSERVAT_TOOL_BIN ?= $(HOME)/.cache/asservat-build/bin
ASSERVAT_BUILD_TMP ?= $(HOME)/.cache/asservat-build/tmp
SQLC ?= $(ASSERVAT_TOOL_BIN)/sqlc
.PHONY: sql-tools sql-check custody-integration
sql-tools:
	mkdir -p "$(ASSERVAT_TOOL_BIN)" "$(ASSERVAT_BUILD_TMP)"
	TMPDIR="$(ASSERVAT_BUILD_TMP)" GOBIN="$(ASSERVAT_TOOL_BIN)" go install github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1
	TMPDIR="$(ASSERVAT_BUILD_TMP)" GOBIN="$(ASSERVAT_TOOL_BIN)" go install -tags='no_clickhouse no_libsql no_mssql no_mysql no_sqlite3 no_vertica no_ydb' github.com/pressly/goose/v3/cmd/goose@v3.28.0

sql-check:
	TMPDIR="$(ASSERVAT_BUILD_TMP)" $(PYTHON) scripts/check-sql-generation.py "$(SQLC)"

custody-integration:
	$(PYTHON) scripts/test-custody.py

.PHONY: audit-storage-integration
audit-storage-integration:
	$(PYTHON) scripts/test-custody.py --scoped-audit


.PHONY: database-recovery-integration
database-recovery-integration:
	$(PYTHON) scripts/test-custody.py --database-recovery

.PHONY: initial-installation-integration
initial-installation-integration:
	$(PYTHON) scripts/test-custody.py --initial-installation

.PHONY: manifest-schema-check
.PHONY: investigation-schema-check
investigation-schema-check:
	$(PYTHON) scripts/investigation-schemas.py

manifest-schema-check:
	$(PYTHON) scripts/manifest-schemas.py

.PHONY: permission-schema-check
permission-schema-check:
	$(PYTHON) scripts/manifest-schemas.py --bundle permissions

.PHONY: policy-schema-check
policy-schema-check:
	$(PYTHON) scripts/manifest-schemas.py --bundle policies

.PHONY: permission-crd-check
permission-crd-check:
	$(PYTHON) scripts/permission-crds.py

.PHONY: permission-integration
permission-integration:
	$(PYTHON) scripts/test-permissions.py

.PHONY: control-schema-check
control-schema-check:
	$(PYTHON) scripts/manifest-schemas.py --bundle control

.PHONY: start-crd-check
start-crd-check:
	$(PYTHON) scripts/start-crd.py

.PHONY: fleet-integration
fleet-integration:
	$(PYTHON) scripts/test-custody.py --fleet

.PHONY: retention-crd-check
retention-crd-check:
	$(PYTHON) scripts/retention-crd.py

.PHONY: capacity-crd-check
capacity-crd-check:
	$(PYTHON) scripts/capacity-crds.py

.PHONY: identity-integration
identity-integration:
	$(PYTHON) scripts/test-identity.py

.PHONY: helm-check helm-integration
helm-check: permission-crd-check start-crd-check retention-crd-check
	$(PYTHON) scripts/check-helm.py

helm-integration: helm-check
	$(PYTHON) scripts/test-helm.py

.PHONY: initial-handover-integration
initial-handover-integration:
	$(PYTHON) scripts/test-context-storage.py --initial-handover

.PHONY: initial-schema-handover-integration
initial-schema-handover-integration:
	$(PYTHON) scripts/test-context-storage.py --initial-schema-handover

# Fast local gates before a push: the checks job's gates and self-tests, the
# go job's vet and sql-check, the console job's console-check (including
# generated-contract drift) and gofmt. No fixtures, race tests or browser.
# Use the spec virtual environment: make pre-push PYTHON=<spec-venv>/bin/python
PRE_PUSH_GATES := spec-check architecture-check design-check openapi-check live-check download-check investigation-check \
	go-architecture-check manifest-schema-check investigation-schema-check permission-schema-check policy-schema-check \
	permission-crd-check control-schema-check start-crd-check retention-crd-check capacity-crd-check helm-check \
	gate-self-tests sql-check console-check gofmt-check go-vet
.PHONY: pre-push gate-self-tests gofmt-check go-vet
pre-push:
	$(MAKE) -k -j4 -O $(PRE_PUSH_GATES)

gate-self-tests:
	for f in scripts/test-ci-changes.py scripts/test-go-shards.py scripts/test-kept-cleanup.py scripts/test-*-selection.py scripts/test-direct-helper-regression.py; do $(PYTHON) "$$f" || exit 1; done

gofmt-check:
	@unformatted=$$(gofmt -l api cmd internal migrations test); if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

go-vet:
	TMPDIR="$(ASSERVAT_BUILD_TMP)" go vet ./...
