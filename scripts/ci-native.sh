#!/usr/bin/env bash
# Native suites for .github/workflows/native.yml. Each suite owns one fresh
# runner, so the local one-native-slot and load gates do not apply there.
#   ci-native.sh --list          JSON list of all suites
#   ci-native.sh SUITE [PATTERN] run SUITE; PATTERN is the harness --run filter
set -euo pipefail
context="python3 scripts/test-context-storage.py"
declare -A suites=(
  [custody]="make custody-integration"
  [fleet]="make fleet-integration"
  [database-recovery]="make database-recovery-integration"
  [initial-installation]="make initial-installation-integration"
  [audit-storage]="make audit-storage-integration"
  [connector-retirement]="make connector-retirement-integration"
  [owner-audit-inventory]="python3 scripts/test-custody.py --owner-audit-inventory"
  [permission]="make permission-integration"
  [identity]="make identity-integration"
  [helm]="make helm-integration"
  # The context suite (make context-integration, too long for one run) in two
  # shards of about 8 min of tests each, so each run stays within the
  # 20-minute limit (TestI* and everything else).
  [context-1]="$context --run ^TestI"
  [context-2]="$context --run ^Test[A-HJ-Z]"
  # The installed journey in runs of at most 20 minutes (the unsplit
  # continuation takes about 25 and is not a CI suite). Only the chain run keeps the full
  # installation-process checks (interrupted and resumed runner, baseline
  # edit, demand lane, regional installer rerun, connector readmission and
  # source-write denial, workload added after the join) and stops after one
  # short journey; every other run uses the fast feature fixture that skips
  # them (installedFastFixture, docs/implementation-progress.md).
  [continuation-chain]="env ASSERVAT_JOURNEY_FOCUS=chain $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-journey]="env ASSERVAT_JOURNEY_FOCUS=journey $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  # The console checks of the first cluster's journey (browser submission,
  # console/MCP preview, case, approved extract and native download agreement),
  # and the approved read-only projection, split from the journey run so each
  # stays within about 15 minutes.
  [continuation-browser]="env ASSERVAT_JOURNEY_FOCUS=browser $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-restart]="env ASSERVAT_JOURNEY_FOCUS=restart $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-clusters]="env ASSERVAT_JOURNEY_FOCUS=clusters $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  # ADR-227: upgrade of hub-api and hub-worker to a second release image and
  # image-only rollback, with a capture on each side of the upgrade.
  [continuation-upgrade]="env ASSERVAT_JOURNEY_FOCUS=upgrade $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  # ADR-228: the restart-trigger policy journey (activation, one policy
  # capture and download, a bounded three-replica crash storm).
  [continuation-policy]="env ASSERVAT_JOURNEY_FOCUS=policy $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [direct-observation]="$context --run ^TestDirectHolderObservationWithRealKubernetes\$"
  [federation-regional]="$context --run ^TestFederationRegionalProductWithRealKubernetes\$"
  [initial-handover]="$context --initial-handover"
  [initial-schema-handover]="$context --initial-schema-handover"
  [helm-bootstrap]="$context --helm-bootstrap"
  [helm-cluster]="$context --helm-cluster"
  [regional-journey]="$context --regional-context-start journey"
  [runtime-object-roundtrip]="$context --runtime-object-roundtrip"
  [owner-provider-auth]="$context --owner-provider-auth"
)
if [[ ${1:-} == --list ]]; then
  printf '%s\n' "${!suites[@]}" | sort | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().split()))'
  exit
fi
command=${suites[${1:?suite}]:?unknown suite $1}
# A filter selects tests inside a suite's own fixture: custody/fleet and context only.
if [[ -n ${2:-} ]]; then
  case $1 in
    custody) command="python3 scripts/test-custody.py --run" ;;
    fleet) command="python3 scripts/test-custody.py --fleet --run" ;;
    context) command="$context --run" ;;
    *) echo "suite $1 owns its exact test selection" >&2; exit 2 ;;
  esac
  exec $command "$2"
fi
echo "+ $command" >&2
exec $command
