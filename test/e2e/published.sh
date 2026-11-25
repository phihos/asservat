#!/usr/bin/env bash
# Installs the published images in a fresh kind cluster as the README says,
# with the chart's own image settings, and records one capture: what people
# pull installs and works on this machine's architecture.
#
#   test/e2e/published.sh [tag]   the tag to install (default: main)
#
# Needs docker (or podman as docker), kind, kubectl, helm, curl and jq.
set -euo pipefail

cd "$(dirname "$0")/../.."
TAG="${1:-main}"
WORK="${WORK:-${XDG_CACHE_HOME:-$HOME/.cache}/asservat-e2e}"
NAME=asv-published PORT=18090
URL="http://127.0.0.1:$PORT"
ROOT=root-token-0123456789abcdef0123456789ab
mkdir -p "$WORK"
export KUBECONFIG="$WORK/published-kubeconfig"
k() { kubectl --context "kind-$NAME" "$@"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
cleanup() {
  if [ $? != 0 ]; then
    k -n asservat get pods -o wide 2>&1 || true
    k -n asservat logs deploy/asservat-hub --tail=30 2>&1 || true
    k -n asservat logs ds/asservat-agent --tail=30 2>&1 || true
  fi
  [ -z "${FORWARD:-}" ] || kill "$FORWARD" 2>/dev/null || true
  [ -n "${KEEP:-}" ] || kind delete cluster --name "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

kind delete cluster --name "$NAME" >/dev/null 2>&1 || true
kind create cluster --name "$NAME" >/dev/null 2>&1
k create namespace asservat >/dev/null
helm --kube-context "kind-$NAME" install asservat charts/asservat -n asservat --wait --timeout 8m \
  --set image.tag="$TAG" \
  --set hub.users[0].name=root,hub.users[0].token=$ROOT,hub.users[0].groups[0]=asservat-admins >/dev/null

arch=$(k get nodes -o jsonpath='{.items[0].status.nodeInfo.architecture}')
k -n asservat port-forward svc/asservat-hub "$PORT:80" >/dev/null 2>&1 &
FORWARD=$!
api() { curl -sS -H "Authorization: Bearer $ROOT" "$@"; }
for _ in $(seq 50); do curl -s -o /dev/null "$URL/healthz" && break; sleep 0.2; done
# The agent is back within seconds of the hub's start.
for _ in $(seq 60); do [ "$(api "$URL/api/clusters" | jq '.[0].nodes | length')" = 1 ] && break; sleep 1; done
[ "$(api "$URL/api/clusters" | jq '.[0].nodes | length')" = 1 ] || fail "the agent did not connect to the hub"

id=$(api -X POST "$URL/api/captures" -d '{"cluster":"local","namespace":"asservat","workload":"Deployment/asservat-hub","recordings":[{"kind":"logs"},{"kind":"pod-state"}]}' | jq -r .id)
for _ in $(seq 60); do
  state=$(api "$URL/api/captures/$id" | jq -r .state)
  case $state in Completed) break ;; Failed|Denied|Cancelled) fail "the capture ended as $state: $(api "$URL/api/captures/$id" | jq -c '[.message, .tasks]')" ;; esac
  sleep 1
done
[ "$state" = Completed ] || fail "the capture stayed $state"
file=$(api "$URL/api/captures/$id" | jq -r '.artifacts[] | select(.name | endswith(".log")) | .name' | head -1)
[ -n "$(api "$URL/api/captures/$id/artifacts/$file" | head -c 1)" ] || fail "the hub's log is empty"
echo "PASS: $TAG installs and records on $arch"
