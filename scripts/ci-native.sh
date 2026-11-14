#!/usr/bin/env bash
# Native suites for .github/workflows/native.yml. Each suite owns one fresh
# runner, so the local one-native-slot and load gates do not apply there.
#   ci-native.sh --list          JSON list of all suites
#   ci-native.sh SUITE [PATTERN] run SUITE; PATTERN is the harness --run filter
set -euo pipefail
context="python3 scripts/test-context-storage.py"
declare -A suites=(
  # The custody suite (make custody-integration, about 15 minutes, too long
  # for one run) in four disjoint shards (CUSTODY_SHARDS in
  # scripts/test-custody.py).
  [custody-1]="python3 scripts/test-custody.py --shard 1"
  [custody-2]="python3 scripts/test-custody.py --shard 2"
  [custody-3]="python3 scripts/test-custody.py --shard 3"
  [custody-4]="python3 scripts/test-custody.py --shard 4"
  [fleet]="make fleet-integration"
  [database-recovery]="make database-recovery-integration"
  [logs-resource]="python3 scripts/test-logs-resource.py"
  [audit-storage]="make audit-storage-integration"
  [owner-audit-inventory]="python3 scripts/test-custody.py --owner-audit-inventory"
  [permission]="make permission-integration"
  [identity]="make identity-integration"
  [helm]="make helm-integration"
  # The context suite (make context-integration, too long for one run) in two
  # shards of about 8 min of tests each, so each run stays within the
  # 20-minute limit (TestI* and everything else).
  [context-1]="$context --run ^TestI"
  [context-2]="$context --run ^Test[A-HJ-Z]"
  # The single-cluster owned node→Pod traffic probe: the harness installs its
  # helper only for this exact selection, so the context shards skip it.
  [native-traffic]="$context --run ^TestNativePacingTrafficWithRealKubernetes\$"
  [regional-journey]="$context --regional-context-start journey"
  # ADR-246 (S-04 increment 3): the node collector skeleton. Loads BPF on the
  # runner's kernel, so the harness refuses without the disposable-host guard
  # that native.yml creates on its fresh runner.
  [collector-packet]="python3 scripts/test-collector.py packet"
  [collector-profile]="python3 scripts/test-collector.py profile"
  [collector-argument-engine]="python3 scripts/test-collector.py argument-engine"
  # S-04 row 17 (EXP-02 subset): the packet suite on the pinned Cilium chart.
  [collector-cilium]="python3 scripts/test-collector.py cilium"
  # ADR-278: the encrypted-disk ring volume on a real node (byte cap, crash
  # restart, full volume).
  [collector-ringdisk]="python3 scripts/test-collector.py ringdisk"
)
# The setup each suite needs on its runner (native.yml).
needs() {
  local suite=$1 collector=false helm=false plain=true
  [[ $suite == collector-* ]] && collector=true
  [[ $suite == helm* || $collector == true ]] && helm=true
  [[ $suite == logs-resource ]] && plain=false
  local sql=$plain go_cache=race
  [[ $collector == true ]] && sql=false go_cache=collector
  printf '{"suite":"%s","go-cache":"native-%s","sql-tools":%s,"kind":%s,"pull":%s,"libpcap":%s,"helm":%s,"guard":%s,"tshark":%s}' \
    "$suite" "$go_cache" "$sql" "$plain" "$plain" "$sql" "$helm" "$collector" "$collector"
}
if [[ ${1:-} == --list ]]; then
  # The "all" dispatch: every suite.
  printf '%s\n' "${!suites[@]}" | sort | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().split()))'
  exit
fi
if [[ ${1:-} == --names ]]; then
  # Every dispatchable suite.
  printf '%s\n' "${!suites[@]}" | sort | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().split()))'
  exit
fi
if [[ ${1:-} == --matrix ]]; then
  # native.yml's job matrix for a JSON list of suites.
  sep="" out='{"include":['
  for suite in $(python3 -c 'import json,sys; print(" ".join(json.loads(sys.argv[1])))' "${2:?suites JSON}"); do
    out+=$sep$(needs "$suite") sep=,
  done
  echo "$out]}"
  exit
fi
# context and custody exist only for filtered dispatch (ci-native.sh SUITE
# PATTERN): each whole suite exceeds the 20-minute limit, so neither is in
# --list; their numbered shards run the whole suite.
if [[ ${1:-} == context || ${1:-} == custody ]] && [[ -z ${2:-} ]]; then
  echo "$1 needs a --run filter; use its numbered shards for the whole suite" >&2; exit 2
fi
command=${suites[${1:?suite}]:-}
[[ -n $command || $1 == context || $1 == custody ]] || { echo "unknown suite $1" >&2; exit 2; }
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
