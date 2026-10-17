#!/bin/bash
set -euo pipefail
export GOMAXPROCS=2 GOFLAGS=-p=2 TMPDIR=/home/phil/.cache/asservat-build/tmp
stage=/home/phil/.cache/asservat-build/planning/context-native-content-20261012
cd /home/phil/Projekte/asservat
find "$stage/changes" -name '*.go' -print0 | xargs -0 gofmt -w
/home/phil/.cache/asservat-build/bin/sqlc generate -f "$stage/sql-generation/sqlc.json" > "$stage/evidence/sqlc-final.log" 2>&1
go test -overlay "$stage/overlay-all.json" -vet=off -race ./internal/application/evidence ./internal/application/audit ./internal/domain/audit ./internal/transport/browser ./internal/transport/presentation ./internal/adapters/postgres -count=1 > "$stage/evidence/affected-races-final.log" 2>&1
go test -overlay "$stage/overlay-all.json" -vet=off -race ./internal/adapters/kubernetes -run '^TestWorkerStartupWaitExcludesKnownExecutionAndTermination$' -count=1 > "$stage/evidence/pending-races-final.log" 2>&1
go test -overlay "$stage/overlay-all.json" -vet=off ./test/integration ./internal/bootstrap -run '^$' -count=1 > "$stage/evidence/integration-compile-final.log" 2>&1
go vet -overlay "$stage/overlay-all.json" ./internal/application/evidence ./internal/application/audit ./internal/domain/audit ./internal/transport/browser ./internal/transport/presentation ./internal/adapters/postgres ./internal/adapters/kubernetes ./internal/bootstrap ./test/integration > "$stage/evidence/vet-final.log" 2>&1
