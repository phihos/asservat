#!/usr/bin/env bash
# Installs the published images in a fresh kind cluster as the README says,
# with the chart's own image settings, and records one capture: what people
# pull installs and works on this machine's architecture.
#
#   test/e2e/published.sh [tag]   the tag to install (default: main)
#   FROM=<commit> test/e2e/published.sh <commit>
#       installs the images and the chart of the commit FROM first, records
#       with them and makes a watch, then upgrades to the tag with this
#       tree's chart: what was recorded before is there after, and the watch
#       still records. Left out, with a word, where FROM has no images, as a
#       commit whose run another one overtook.
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
  [ -z "${BEFORE:-}" ] || rm -rf "$BEFORE"
  [ -n "${KEEP:-}" ] || kind delete cluster --name "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

api() { curl -sS -H "Authorization: Bearer $ROOT" "$@"; }
# release installs or upgrades the release from a chart with a tag's images.
release() {
  helm --kube-context "kind-$NAME" upgrade --install asservat "$1" -n asservat --wait --timeout 8m \
    --set image.tag="$2" \
    --set hub.users[0].name=root,hub.users[0].token=$ROOT,hub.users[0].groups[0]=asservat-admins >/dev/null
}
# reach forwards a port to the hub, whose pod an upgrade replaces, and waits for the agent.
reach() {
  [ -z "${FORWARD:-}" ] || kill "$FORWARD" 2>/dev/null || true
  k -n asservat port-forward svc/asservat-hub "$PORT:80" >/dev/null 2>&1 &
  FORWARD=$!
  for _ in $(seq 50); do curl -s -o /dev/null "$URL/healthz" && break; sleep 0.2; done
  # The agent is back within seconds of the hub's start.
  for _ in $(seq 60); do [ "$(api "$URL/api/clusters" | jq '.[0].nodes | length')" = 1 ] && break; sleep 1; done
  [ "$(api "$URL/api/clusters" | jq '.[0].nodes | length')" = 1 ] || fail "the agent did not connect to the hub"
}
# recorded makes a capture of the hub's own pod and waits for it; it prints its ID.
recorded() {
  local id state
  id=$(api -X POST "$URL/api/captures" -d '{"cluster":"local","namespace":"asservat","workload":"Deployment/asservat-hub","recordings":[{"kind":"logs"},{"kind":"pod-state"}]}' | jq -r .id)
  for _ in $(seq 60); do
    state=$(api "$URL/api/captures/$id" | jq -r .state)
    case $state in Completed) break ;; Failed|Denied|Cancelled) fail "the capture ended as $state: $(api "$URL/api/captures/$id" | jq -c '[.message, .tasks]')" ;; esac
    sleep 1
  done
  [ "$state" = Completed ] || fail "the capture stayed $state"
  printf '%s' "$id"
}
# told is what a capture's record says of it and its files.
told() { api "$URL/api/captures/$1" | jq -c '[.state, .number, (.artifacts[] | [.name, .size, .sha256])]'; }

kind delete cluster --name "$NAME" >/dev/null 2>&1 || true
kind create cluster --name "$NAME" >/dev/null 2>&1
k create namespace asservat >/dev/null

# The version before, where one is named and was published.
upgraded=""
if [ -n "${FROM:-}" ] && [ "$FROM" != "$TAG" ]; then
  image=$(helm show values charts/asservat | sed -n 's/^  repository: //p' | head -1)
  if docker manifest inspect "$image:$FROM" >/dev/null 2>&1 && docker manifest inspect "$image:$FROM-agent" >/dev/null 2>&1 && git cat-file -e "$FROM^{commit}" 2>/dev/null; then
    BEFORE=$(mktemp -d)
    git archive "$FROM" charts/asservat | tar -x -C "$BEFORE"
    release "$BEFORE/charts/asservat" "$FROM"
    reach
    old=$(recorded)
    before=$(told "$old")
    watch=$(api -X POST "$URL/api/watches" -d '{"cluster":"local","namespace":"asservat","workload":"Deployment/asservat-hub","kind":"logs","count":2}' | jq -r .id)
    upgraded=" after an upgrade from ${FROM:0:8}"
  else
    # Said so that it shows on the run: an upgrade that was not tried is not one that passed.
    echo "::warning::the upgrade from $FROM was left out: it has no published images, the registry did not answer, or the commit is not in this checkout"
  fi
fi

release charts/asservat "$TAG"
reach
arch=$(k get nodes -o jsonpath='{.items[0].status.nodeInfo.architecture}')

if [ -n "$upgraded" ]; then
  [ "$(told "$old")" = "$before" ] || fail "what was recorded before the upgrade reads differently after it: $(told "$old")"
  file=$(jq -r '.[2][0]' <<<"$before")
  [ "$(api "$URL/api/captures/$old/artifacts/$file" | sha256sum | cut -d' ' -f1)" = "$(jq -r '.[2][2]' <<<"$before")" ] || fail "a file from before the upgrade is not the one that was recorded"
  [ "$(api -o /dev/null -w '%{http_code}' -X POST "$URL/api/watches/$watch/record")" = 201 ] || fail "a watch from before the upgrade does not record"
fi

id=$(recorded)
file=$(api "$URL/api/captures/$id" | jq -r '.artifacts[] | select(.name | endswith(".log")) | .name' | head -1)
[ -n "$(api "$URL/api/captures/$id/artifacts/$file" | head -c 1)" ] || fail "the hub's log is empty"
echo "PASS: $TAG installs and records on $arch$upgraded"
