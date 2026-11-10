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
	ASSERVAT_CONSOLE_BROWSER_TEST=1 TMPDIR="$(ASSERVAT_BUILD_TMP)" go test -count=1 -run '^TestConsole(Browser|NativeRestart|ProfileComparison|HeapProfile|PacketSummary|PacketQuery|SyscallQuery|SyscallCaptureAuthoring|LogsQuery|LiveObservation|Processing)WithBuiltPackage$$' -v ./test/integration

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
go-check: manifest-schema-check permission-schema-check policy-schema-check permission-crd-check control-schema-check start-crd-check retention-crd-check capacity-crd-check profile-crd-check investigation-schema-check authority-window-check
	go vet ./...
	# Preserve race/count/deadline checks with exact sequential Kubernetes groups.
	$(PYTHON) scripts/test-go-shards.py
	$(PYTHON) scripts/check-go-tests.py

go-architecture-check:
	$(PYTHON) scripts/check-go-architecture.py

# New hand-built authority validity windows fail; the baseline only shrinks
# (docs/reviews/authority-window-plan-2026-11-08.md). -write updates it.
.PHONY: authority-window-check
authority-window-check:
	TMPDIR="$(ASSERVAT_BUILD_TMP)" go run scripts/check-authority-windows.go

context-integration:
	$(PYTHON) scripts/test-context-storage.py

# Local installed loop (docs/development-workflow.md): one installed focus on
# owned kind clusters, e.g. make installed-focus FOCUS=manual-logs. The harness
# refuses collector focuses without the disposable-host guard; this target
# additionally accepts only the collector-free focuses below.
LOCAL_FOCUSES = chain journey browser restart clusters upgrade policy alert logresource share manual-logs journey-store-failure journey-start-failure
.PHONY: installed-focus
installed-focus:
	$(if $(and $(filter 1,$(words $(FOCUS))),$(filter $(FOCUS),$(LOCAL_FOCUSES))),,$(error FOCUS must be one collector-free focus: $(LOCAL_FOCUSES)))
	mkdir -p "$(ASSERVAT_BUILD_TMP)"
	TMPDIR="$(ASSERVAT_BUILD_TMP)" ASSERVAT_JOURNEY_FOCUS="$(FOCUS)" $(PYTHON) scripts/test-context-storage.py --initial-bootstrap-chain --runtime-provider-pair --installer-continuation $(ARGS)

# Development only, never a qualification (docs/development-workflow.md):
# installed-keep installs once and keeps it; installed-rerun runs only the
# focus on it (KEPT defaults to the newest kept manifest); installed-teardown
# removes it and verifies nothing is left.
KEPT ?= $(shell ls -t $(HOME)/.cache/asservat-build/kept/context-*.json 2>/dev/null | head -n 1)
.PHONY: installed-keep installed-rerun installed-teardown
installed-keep:
	$(MAKE) --no-print-directory installed-focus FOCUS="$(or $(FOCUS),manual-logs)" ARGS="--keep-installed $(ARGS)"
installed-rerun:
	$(if $(KEPT),,$(error no kept installation; run make installed-keep))
	mkdir -p "$(ASSERVAT_BUILD_TMP)"
	TMPDIR="$(ASSERVAT_BUILD_TMP)" $(PYTHON) scripts/test-context-storage.py --rerun-installed "$(KEPT)"
installed-teardown:
	$(if $(KEPT),,$(error no kept installation))
	$(PYTHON) scripts/test-context-storage.py --cleanup-kept "$(KEPT)"

.PHONY: go-vuln-check
go-vuln-check:
	go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

ASSERVAT_TOOL_BIN ?= $(HOME)/.cache/asservat-build/bin
ASSERVAT_BUILD_TMP ?= $(HOME)/.cache/asservat-build/tmp
SQLC ?= $(ASSERVAT_TOOL_BIN)/sqlc
# ADR-243 (S2): the hub's pcap filter compiler links a pinned, dependency-free
# static libpcap through cgo (build tag libpcap). Every other build, including
# the default cgo-free product binary, uses a stub that compiles no filter.
LIBPCAP_VERSION := 1.11.0
LIBPCAP_SHA256 := 9237f5bae9dcf3a91823d9963ec43b7c0e2e3374ef2ad57d92c8cd39530f4723
LIBPCAP_PREFIX ?= $(HOME)/.cache/asservat-build/libpcap-$(LIBPCAP_VERSION)
PCAP_ENV = CGO_ENABLED=1 CGO_CFLAGS="-I$(LIBPCAP_PREFIX)/include" CGO_LDFLAGS="-L$(LIBPCAP_PREFIX)/lib" TMPDIR="$(ASSERVAT_BUILD_TMP)"
# The fully static hub build a FROM-scratch image needs (netgo/osusergo; the
# linker's NSS warnings concern libpcap name lookups the planner never reaches).
HUB_BUILD = $(PCAP_ENV) go build -tags libpcap,netgo,osusergo -trimpath -buildvcs=false -ldflags '-extldflags "-static"'
HUB_BINARY ?= $(ASSERVAT_BUILD_TMP)/asservat-hub
.PHONY: libpcap pcap-check hub-binary
libpcap:
	mkdir -p "$(ASSERVAT_BUILD_TMP)"
	LIBPCAP_VERSION=$(LIBPCAP_VERSION) LIBPCAP_SHA256=$(LIBPCAP_SHA256) LIBPCAP_PREFIX="$(LIBPCAP_PREFIX)" TMPDIR="$(ASSERVAT_BUILD_TMP)" scripts/build-libpcap.sh

# Real libpcap compilation tests plus the static hub build. User space only:
# no capture or BPF load.
pcap-check: libpcap
	$(PCAP_ENV) go test -tags libpcap -count=1 ./internal/adapters/pcap/
	$(PCAP_ENV) go test -tags libpcap -count=1 -run '^TestPacketQueryPinnedLibpcapWireLengthAndTruncation$$' ./internal/bootstrap
	$(PCAP_ENV) go test -tags libpcap -count=1 -run '^TestRawPolicyApprovedTimingReplayIgnoresRequireAllSwitch$$' ./internal/adapters/postgres/
	$(HUB_BUILD) -o "$(ASSERVAT_BUILD_TMP)/asservat-hub" ./cmd/asservat 2>/dev/null
	file "$(ASSERVAT_BUILD_TMP)/asservat-hub" | grep -q 'statically linked'
	rm -f "$(ASSERVAT_BUILD_TMP)/asservat-hub"

# ADR-243 decision 4: the installed product image's binary (hub-api,
# hub-worker, connector, installers) with the filter compiler linked, written
# to HUB_BINARY. The native harness builds its FROM-scratch image from it; the
# collector image keeps its own gadget-tagged build.
hub-binary: libpcap
	$(HUB_BUILD) -o "$(HUB_BINARY)" ./cmd/asservat
	file "$(HUB_BINARY)" | grep -q 'statically linked'

# ADR-246 (S1): only the collector image links Inspektor Gadget (build tag
# gadget); every other build carries a stub. Vet and build the static
# collector binary. Compilation only: nothing is loaded into the kernel.
.PHONY: gadget-check
gadget-check:
	TMPDIR="$(ASSERVAT_BUILD_TMP)" go vet -tags gadget ./internal/adapters/gadget/ ./internal/bootstrap/
	TMPDIR="$(ASSERVAT_BUILD_TMP)" CGO_ENABLED=0 go build -tags gadget,netgo,osusergo -trimpath -buildvcs=false -o "$(ASSERVAT_BUILD_TMP)/asservat-collector" ./cmd/asservat
	rm -f "$(ASSERVAT_BUILD_TMP)/asservat-collector"

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
policy-schema-check: policy-crd-check
	$(PYTHON) scripts/manifest-schemas.py --bundle policies

.PHONY: policy-crd-check
policy-crd-check:
	$(PYTHON) scripts/policy-crd.py

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

.PHONY: profile-crd-check
profile-crd-check:
	$(PYTHON) scripts/profile-crd.py

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
helm-check: permission-crd-check policy-crd-check start-crd-check retention-crd-check profile-crd-check
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
# generated-contract drift), gofmt and the test shards' race tests for the
# packages the diff affects (go-affected-test). No fixtures or browser.
# Use the spec virtual environment: make pre-push PYTHON=<spec-venv>/bin/python
PRE_PUSH_GATES := spec-check architecture-check design-check openapi-check live-check download-check investigation-check \
	go-architecture-check manifest-schema-check investigation-schema-check permission-schema-check policy-schema-check \
	permission-crd-check control-schema-check start-crd-check retention-crd-check capacity-crd-check helm-check \
	gate-self-tests sql-check console-check gofmt-check go-vet go-affected-test authority-window-check
.PHONY: pre-push gate-self-tests gofmt-check go-vet go-affected-test
pre-push:
	$(MAKE) -k -j4 -O $(PRE_PUSH_GATES)

gate-self-tests:
	for f in scripts/test-ci-changes.py scripts/test-go-shards.py scripts/test-kept-cleanup.py scripts/test-*-selection.py scripts/test-direct-helper-regression.py scripts/test-collector-provenance.py scripts/test-pod-log-stream.py; do $(PYTHON) "$$f" || exit 1; done

gofmt-check:
	@unformatted=$$(gofmt -l api cmd internal migrations test); if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

go-vet:
	TMPDIR="$(ASSERVAT_BUILD_TMP)" go vet ./...

# Race tests of packages the diff against origin/main (plus uncommitted and
# untracked files) changes, and of every package whose tests reach them.
go-affected-test:
	LIBPCAP_PREFIX="$(LIBPCAP_PREFIX)" TMPDIR="$(ASSERVAT_BUILD_TMP)" $(PYTHON) scripts/test-affected-go.py

# Metadata-only capability qualification; one owned pinned S3 fixture, no collector.
.PHONY: history-storage-integration
history-storage-integration:
	$(PYTHON) scripts/test-history-storage.py $(or $(HISTORY_RESULT_NAME),history-storage-native-1)

# Fast component preflight for the complete profile path. No external fixtures.
.PHONY: profile-preflight
profile-preflight:
	TMPDIR="$(ASSERVAT_BUILD_TMP)" go test -race -count=1 -timeout=30s test/fixtures/worker-resource-probe/main.go test/fixtures/worker-resource-probe/main_test.go
	TMPDIR="$(ASSERVAT_BUILD_TMP)" go test -race -count=1 -timeout=3m -run '^(TestRecordingProfileUnavailable|TestCaseView|TestAcquisitionWindow|TestContextVerificationAcquisition|TestContextVerificationReturns|TestPolicyProfile|TestPolicyEndpoint|TestPolicyExecutor|TestGoProfileEndpoint|TestInstalledProfile|TestDownloadWorkerProfileAndPathTemplate|TestPublicProfile|TestComparison|TestProjectionComparison|TestNativeComparison|TestPublicSnapshotCancellation|TestSourceWork|TestConnectorProfile|TestProfile|TestPprof|TestReadProfile|TestSharedManifest|TestNativeTypeRegistry|TestNodeProfile|TestOneShotProfile|TestCurrentDownloadEnvironment)' ./internal/bootstrap ./internal/domain/catalog ./internal/domain/collector ./internal/domain/execution ./internal/domain/capture ./internal/domain/planning ./internal/domain/targets ./internal/domain/authorization ./internal/domain/privacy ./internal/domain/artifact ./internal/domain/audit ./internal/domain/analysis ./internal/application/catalog ./internal/application/planning ./internal/application/authorization ./internal/application/capture ./internal/application/analysis ./internal/application/evidence ./internal/adapters/kubernetes ./internal/transport/presentation ./internal/transport/browser ./internal/transport/mcp ./internal/adapters/diagnostics ./internal/adapters/objectstore ./internal/adapters/objectstore/manifest ./internal/adapters/jose ./internal/transport/contextstart ./internal/transport/native ./internal/adapters/postgres
	TMPDIR="$(ASSERVAT_BUILD_TMP)" go test -race -count=1 -timeout=3m -run '^(TestPolicy(Profile|Recorder)AdmissionFixtureOfflineBindings|TestInstalled(PolicyProfile|ManualProfile|ProfileComparison|PacketSummary|RecordingPassive|ApprovedRecordingFixtureShape))' ./test/integration

# Finite argument composition, without loading a collector or external services.
.PHONY: argument-preflight
argument-preflight:
	TMPDIR="$(ASSERVAT_BUILD_TMP)" go test -race -count=1 -timeout=3m ./internal/contracts
	TMPDIR="$(ASSERVAT_BUILD_TMP)" go test -race -count=1 -timeout=3m -run 'Test.*(Argument|CaseProjection|InitialSchema|InitialBootstrapSchema|InitialInstallerSchema|RecordingStop|RecordingCollection|SourceWork|PublicSnapshotCancellation)' ./internal/bootstrap ./internal/adapters/kubernetes ./internal/domain/artifact ./internal/domain/collector ./internal/domain/authorization ./internal/application/evidence ./internal/application/delivery ./internal/application/capture ./internal/application/execution ./internal/application/planning ./internal/adapters/gadget ./internal/adapters/postgres ./internal/adapters/jose ./internal/adapters/syscalls ./internal/adapters/objectstore/manifest ./internal/transport/contextstart ./internal/transport/presentation ./internal/transport/mcp
	TMPDIR="$(ASSERVAT_BUILD_TMP)" go test -race -count=1 -timeout=3m -run '^TestInstalledManualArguments' ./test/integration

# Owned SQL/S3 service composition, after local preflight and source freeze.
.PHONY: profile-service-preflight
profile-service-preflight:
	# Each protected capacity-root fixture requires its own pristine database.
	$(PYTHON) scripts/test-custody.py --fleet --run '^TestProfileComparisonQueryLedgerWithRealPostgres$$' --result-name profile-comparison-service-preflight
	$(PYTHON) scripts/test-custody.py --fleet --run '^(TestCustodyProfileWriteOnlyWithRealServices|TestProfileSummaryQueryLedgerWithRealPostgres|TestCustodyUpgradeSchemaWithRealPostgres)$$' --result-name profile-service-preflight

# Saved packet summaries: local parser, authority, wire and UI-admission checks.
# No external services, collector, acquisition or installed qualification.
.PHONY: packet-summary-preflight
packet-summary-preflight:
	TMPDIR="$(ASSERVAT_BUILD_TMP)" go test -race -count=1 -timeout=3m -run '^(TestRawPacket|TestPacketQuery|TestNativePacketQuery|TestPacketSummary|TestPacketProjection|TestSavedPacketMigration|TestProjectionSource|TestProjectionScope|TestProjectionResult|TestProfileSummarySource|TestContextQueryAuditNamesFormatsAndEffects)' ./internal/domain/analysis ./internal/domain/audit ./internal/application/analysis ./internal/application/authorization ./internal/application/evidence ./internal/adapters/packets ./internal/adapters/objectstore ./internal/adapters/postgres ./internal/contracts ./internal/transport/native ./internal/transport/presentation ./internal/bootstrap
	TMPDIR="$(ASSERVAT_BUILD_TMP)" go test -race -count=1 -timeout=3m -run '^TestInstalledPacket(Summary|Query)' ./test/integration

# Optional fresh-host qualification; local CPU schedulers may not enforce quotas.
.PHONY: logs-resource-check
logs-resource-check:
	$(PYTHON) scripts/test-logs-resource.py
