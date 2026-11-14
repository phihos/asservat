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
  [initial-installation]="make initial-installation-integration"
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
  # The installed journey in runs of at most 20 minutes (the unsplit
  # continuation takes about 25 and is not a CI suite). Only the chain run keeps the full
  # installation-process checks (interrupted and resumed runner, baseline
  # edit, demand lane, regional installer rerun, connector readmission and
  # source-write denial, workload added after the join) and stops after one
  # short journey; every other run uses the fast feature fixture that skips
  # them (installedFastFixture, docs/implementation-progress.md).
  [continuation-chain]="env ASSERVAT_JOURNEY_FOCUS=chain $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-journey]="env ASSERVAT_JOURNEY_FOCUS=journey $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  # S-02 exit failure states in the installed run: an object-store failure
  # ends an accepted capture Indeterminate/StorageOutcomeUnconfirmed and an
  # exhausted workload context reserve refuses CapacityUnavailable.
  [continuation-journey-store-failure]="env ASSERVAT_JOURNEY_FOCUS=journey-store-failure $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  # ADR-223: a hub-worker crash during an accepted capture never repeats the
  # collection and resolves terminal; a key-service failure before the start
  # stays Pending until the original deadline marks Indeterminate.
  [continuation-journey-start-failure]="env ASSERVAT_JOURNEY_FOCUS=journey-start-failure $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-approved-recording]="env ASSERVAT_JOURNEY_FOCUS=approved-recording $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-manual-syscall]="env ASSERVAT_JOURNEY_FOCUS=manual-syscall $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-manual-logs]="env ASSERVAT_JOURNEY_FOCUS=manual-logs $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-manual-arguments]="env ASSERVAT_JOURNEY_FOCUS=manual-arguments $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-manual-mixed]="env ASSERVAT_JOURNEY_FOCUS=manual-mixed $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-manual-raw]="env ASSERVAT_JOURNEY_FOCUS=manual-raw $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-manual-http]="env ASSERVAT_JOURNEY_FOCUS=manual-http $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-manual-peers]="env ASSERVAT_JOURNEY_FOCUS=manual-peers $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-manual-profile]="env ASSERVAT_JOURNEY_FOCUS=manual-profile ASSERVAT_PROFILE_VARIANT=cpu ASSERVAT_PROFILE_TRANSPORT=http ASSERVAT_PROFILE_AUTH=none $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-manual-profile-tls]="env ASSERVAT_JOURNEY_FOCUS=manual-profile ASSERVAT_PROFILE_VARIANT=cpu ASSERVAT_PROFILE_TRANSPORT=tls ASSERVAT_PROFILE_AUTH=none $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-manual-profile-auth]="env ASSERVAT_JOURNEY_FOCUS=manual-profile ASSERVAT_PROFILE_VARIANT=cpu ASSERVAT_PROFILE_TRANSPORT=tls ASSERVAT_PROFILE_AUTH=required $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-manual-heap]="env ASSERVAT_JOURNEY_FOCUS=manual-profile ASSERVAT_PROFILE_VARIANT=heap ASSERVAT_PROFILE_TRANSPORT=http ASSERVAT_PROFILE_AUTH=none $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-manual-trace]="env ASSERVAT_JOURNEY_FOCUS=manual-profile ASSERVAT_PROFILE_VARIANT=trace ASSERVAT_PROFILE_TRANSPORT=http ASSERVAT_PROFILE_AUTH=none $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-profile-comparison]="env ASSERVAT_JOURNEY_FOCUS=profile-comparison ASSERVAT_PROFILE_TRANSPORT=http ASSERVAT_PROFILE_AUTH=none $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-profile-comparison-heavy]="env ASSERVAT_JOURNEY_FOCUS=profile-comparison ASSERVAT_PROFILE_VARIANT=accepted-heavy ASSERVAT_PROFILE_TRANSPORT=http ASSERVAT_PROFILE_AUTH=none $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-policy-recording]="env ASSERVAT_JOURNEY_FOCUS=policy-recording $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-policy-arguments]="env ASSERVAT_JOURNEY_FOCUS=policy-arguments $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-policy-profile]="env ASSERVAT_JOURNEY_FOCUS=policy-profile $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-ongoing-save]="env ASSERVAT_JOURNEY_FOCUS=ongoing-save $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-ongoing-save-disk]="env ASSERVAT_JOURNEY_FOCUS=ongoing-save-disk $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-ongoing-incident]="env ASSERVAT_JOURNEY_FOCUS=ongoing-incident $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-ongoing-syscall]="env ASSERVAT_JOURNEY_FOCUS=ongoing-syscall $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-ongoing-mixed]="env ASSERVAT_JOURNEY_FOCUS=ongoing-mixed $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-ongoing-live]="env ASSERVAT_JOURNEY_FOCUS=live-observation ASSERVAT_LIVE_EPISODES=policy $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-ongoing-live-manual]="env ASSERVAT_JOURNEY_FOCUS=live-observation ASSERVAT_LIVE_EPISODES=manual $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-native-paced]="env ASSERVAT_JOURNEY_FOCUS=native-paced $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
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
  # ADR-231: the alert-trigger policy against a real in-cluster Alertmanager
  # (occurrence, capture, dedup while firing, re-arm after resolution).
  [continuation-alert]="env ASSERVAT_JOURNEY_FOCUS=alert $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  # ADR-241: log (pods/log) and resource (metrics-server metrics API)
  # policies against the synthetic signal workload (one capture each).
  [continuation-logresource]="env ASSERVAT_JOURNEY_FOCUS=logresource $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  # ADR-232: a short journey, then share the artifact with the unrelated
  # principal over MCP (get_case works, download refused, revoke refuses).
  [continuation-share-retirement]="env ASSERVAT_JOURNEY_FOCUS=share-retirement $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  [continuation-share]="env ASSERVAT_JOURNEY_FOCUS=share $context --initial-bootstrap-chain --runtime-provider-pair --installer-continuation"
  # The single-cluster owned node→Pod traffic probe: the harness installs its
  # helper only for this exact selection, so the context shards skip it.
  [native-traffic]="$context --run ^TestNativePacingTrafficWithRealKubernetes\$"
  [initial-handover]="$context --initial-handover"
  [initial-schema-handover]="$context --initial-schema-handover"
  [helm-bootstrap]="$context --helm-bootstrap"
  [helm-cluster]="$context --helm-cluster"
  [regional-journey]="$context --regional-context-start journey"
  [runtime-object-roundtrip]="$context --runtime-object-roundtrip"
  [owner-provider-auth]="$context --owner-provider-auth"
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
# Grouped installed suites: several focuses after one bootstrap
# (ASSERVAT_JOURNEY_FOCUS=a,b), each focus its own subtest, run in the order
# listed; a later focus runs only after the earlier ones passed, behind a
# teardown of their policies, bindings and sources (installedFocusTeardown).
# The Go test refuses focuses whose bootstrap differs or whose order is
# unsafe (installed_multi_focus_test.go). A group's name joins its members,
# whose commands may differ only in their focus (a member with further
# fixture variables, such as the profile or live variants, needs its own
# installation). The member suites stay dispatchable for targeted
# reruns; the "all" dispatch runs each group instead of its members.
# Measured focus durations and the bins are in
# docs/reviews/test-runtime-plan-2026-11-08.md (step 6).
groups=(
  "journey policy"
  "browser alert"
  "share logresource"
  "restart upgrade"
  "approved-recording manual-mixed"
  "manual-http manual-peers"
)
declare -A grouped=()
for group in "${groups[@]}"; do
  name="" foci="" rest=""
  for member in $group; do
    command=${suites[continuation-$member]:?unknown group member $member}
    [[ $command =~ ^env\ ASSERVAT_JOURNEY_FOCUS=([a-z-]+)\ (.*)$ && ${BASH_REMATCH[2]} != *=* ]] || { echo "group member $member sets more than its focus" >&2; exit 2; }
    [[ -z $rest || $rest == "${BASH_REMATCH[2]}" ]] || { echo "group $group: member commands differ" >&2; exit 2; }
    foci+=${foci:+,}${BASH_REMATCH[1]} rest=${BASH_REMATCH[2]} name+=${name:++}$member grouped[continuation-$member]=1
  done
  suites[continuation-$name]="env ASSERVAT_JOURNEY_FOCUS=$foci $rest"
done
# The setup each suite needs on its runner (native.yml): suite names joined
# by + need what any member needs.
needs() {
  local suite=$1 part installed=false collector=false helm=false guard=false tshark=false playwright=false builder=false
  local base=${suite#continuation-}
  [[ $suite == continuation-* ]] && installed=true
  [[ $suite == collector-* ]] && collector=true
  for part in ${base//+/ }; do
    [[ $installed == true ]] && part=continuation-$part || part=$suite
    case $part in
      helm*|collector-*|continuation-approved-recording|continuation-manual-*|continuation-profile-comparison*|continuation-native-paced|continuation-policy-recording|continuation-policy-arguments|continuation-policy-profile|continuation-ongoing-*) helm=true ;;
    esac
    case $part in
      continuation-manual-logs) ;;
      collector-*|continuation-approved-recording|continuation-manual-*|continuation-profile-comparison*|continuation-native-paced|continuation-policy-recording|continuation-policy-arguments|continuation-policy-profile|continuation-ongoing-*)
        guard=true
        case $part in
          continuation-manual-profile*|continuation-manual-heap|continuation-manual-trace|continuation-profile-comparison*|continuation-manual-arguments|continuation-policy-arguments|continuation-policy-profile) ;;
          *) tshark=true ;;
        esac ;;
    esac
    case $part in
      continuation-approved-recording|continuation-profile-comparison*|continuation-manual-heap|continuation-manual-mixed|continuation-manual-raw|continuation-manual-arguments|continuation-manual-logs|continuation-ongoing-live|continuation-ongoing-live-manual) playwright=true ;;
    esac
    case $part in
      continuation-manual-raw|continuation-manual-arguments|continuation-manual-syscall|continuation-profile-comparison*|continuation-policy-profile) builder=true ;;
    esac
  done
  local go_cache=race
  [[ $installed == true ]] && go_cache=installed
  [[ $collector == true ]] && go_cache=collector
  local plain=true
  [[ $suite == logs-resource ]] && plain=false
  local sql=$plain
  [[ $collector == true ]] && sql=false
  printf '{"suite":"%s","go-cache":"native-%s","console":%s,"sql-tools":%s,"kind":%s,"pull":%s,"libpcap":%s,"helm":%s,"guard":%s,"tshark":%s,"playwright":%s,"builder":%s}' \
    "$suite" "$go_cache" "$installed" "$sql" "$plain" "$plain" "$sql" "$helm" "$guard" "$tshark" "$playwright" "$builder"
}
if [[ ${1:-} == --list ]]; then
  # The "all" dispatch: every suite except the members of a group.
  for suite in "${!suites[@]}"; do [[ -n ${grouped[$suite]:-} ]] || echo "$suite"; done | sort | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().split()))'
  exit
fi
if [[ ${1:-} == --names ]]; then
  # Every dispatchable suite, grouped members included.
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
