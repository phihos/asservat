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
  [context]="make context-integration"
  [continuation]="$context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
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
