#!/usr/bin/env bash
# End-to-end test with two kind clusters: "hub" runs the hub and its own node
# agents, "edge" runs only agents that join the hub. It records every kind of
# evidence from a demo workload, including a core dump that an administrator
# approves and the captures of a crash watch, and checks the downloaded files.
#
#   test/e2e/run.sh          build the image, create the clusters, test, delete
#   KEEP=1 test/e2e/run.sh   keep the clusters for inspection
#   CORE_HANDLER=1 test/e2e/run.sh   also record the core of a crashed process
#   SAMPLE_CPU=1 test/e2e/run.sh     also sample profiles of CPU time and memory growth
#   CHROME=<path> test/e2e/run.sh    the browser that looks at the pages (default: the first of chromium, chromium-browser, google-chrome that is installed)
#   REQUIRE_BROWSER=1 test/e2e/run.sh   fail where no browser is installed, instead of leaving the pages out
#
# CORE_HANDLER changes kernel.core_pattern of the machine that runs kind,
# because kind nodes share its kernel. Use it only on a disposable machine
# such as a CI runner; it needs sudo to create the spool directory.
# SAMPLE_CPU=1 also samples profiles. That loads eBPF programs into the
# kernel of the machine that runs kind, which rootless containers cannot do.
#
# Needs docker (or podman as docker), kind, kubectl, helm, curl and jq.
set -euo pipefail

cd "$(dirname "$0")/../.."
WORK="${WORK:-${XDG_CACHE_HOME:-$HOME/.cache}/asservat-e2e}"
IMAGE=localhost/asservat:e2e
HUB=asv-hub EDGE=asv-edge
PORT=18080
URL="http://127.0.0.1:$PORT"
mkdir -p "$WORK"
export KUBECONFIG="$WORK/kubeconfig"

log() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [ $? != 0 ] && [ -n "${FORWARD:-}" ]; then
    log "hub log"; kubectl --context "kind-$HUB" -n asservat logs deploy/asservat-hub --tail=30 2>&1 || true
    for c in "$HUB" "$EDGE"; do
      log "agent log of $c"; kubectl --context "kind-$c" -n asservat logs ds/asservat-agent --tail=30 2>&1 || true
    done
    if [ -n "${CORE_HANDLER:-}" ]; then
      log "core handler"; cat /proc/sys/kernel/core_pattern /proc/sys/kernel/core_pipe_limit; sudo ls -laR "$SPOOL"; sudo cat "$SPOOL/last-core" 2>&1 || true
    fi
  fi
  [ -n "${FORWARD:-}" ] && kill "$FORWARD" 2>/dev/null || true
  if [ -z "${KEEP:-}" ]; then
    kind delete cluster --name "$HUB" >/dev/null 2>&1 || true
    kind delete cluster --name "$EDGE" >/dev/null 2>&1 || true
  fi
  [ -z "${PATTERN_BEFORE:-}" ] || echo "$PATTERN_BEFORE" | sudo tee /proc/sys/kernel/core_pattern >/dev/null
}
trap cleanup EXIT

# api TOKEN METHOD PATH [JSON]: prints the body, then the status on a last line.
api() {
  local token=$1 method=$2 path=$3
  curl -sS -o - -w '\n%{http_code}' -X "$method" -H "Authorization: Bearer $token" ${4:+-H 'Content-Type: application/json' -d "$4"} "$URL$path"
}
# ok TOKEN METHOD PATH [JSON]: the body of a successful call.
ok() {
  local out; out=$(api "$@")
  case "${out##*$'\n'}" in 2*) printf '%s' "${out%$'\n'*}" ;; *) fail "$2 $3: $out" ;; esac
}
# status TOKEN METHOD PATH [JSON]: only the status code.
status() { local out; out=$(api "$@"); printf '%s' "${out##*$'\n'}"; }

# wait_state TOKEN ID: follows the capture until it leaves Queued and Running.
wait_state() {
  local state
  for _ in $(seq 150); do
    state=$(ok "$1" GET "/api/captures/$2" | jq -r .state)
    case "$state" in Queued|Running) sleep 1 ;; *) printf '%s' "$state"; return ;; esac
  done
  fail "capture $2 stayed $state"
}
# capture TOKEN JSON: requests a capture and prints its ID.
capture() { ok "$1" POST /api/captures "$2" | jq -r .id; }
# completed TOKEN ID: waits and requires Completed.
completed() {
  local state; state=$(wait_state "$1" "$2")
  [ "$state" = Completed ] || fail "capture $2 is $state: $(ok "$1" GET "/api/captures/$2" | jq -c '[.message, .tasks]')"
}
# fetch TOKEN ID NAME FILE: downloads an artifact and verifies its checksum.
fetch() {
  curl -sS --fail -H "Authorization: Bearer $1" -o "$4" "$URL/api/captures/$2/artifacts/$3"
  local want; want=$(ok "$1" GET "/api/captures/$2" | jq -r --arg n "$3" '.artifacts[] | select(.name == $n) | .sha256')
  [ "$(sha256sum "$4" | cut -d' ' -f1)" = "$want" ] || fail "checksum of $3"
}
first_artifact() { ok "$1" GET "/api/captures/$2" | jq -r '.artifacts[0].name'; }

if [ -z "${SKIP_BUILD:-}" ]; then
  log "build image"
  docker build -q --target agent -t "$IMAGE-agent" .
  docker build -q -t "$IMAGE" .
fi
rm -f "$WORK/image.tar"
docker save "$IMAGE" "$IMAGE-agent" -o "$WORK/image.tar"

# The kernel runs the core handler from the machine's own file system, so
# the spool is one directory at the same path there, in the kind node and in
# the agent.
SPOOL=/var/lib/asservat-e2e
if [ -n "${CORE_HANDLER:-}" ]; then
  sudo mkdir -p "$SPOOL"
  # The machine's core handler from before the agent's, which gets the cores
  # that Asservat does not keep: here one that notes what it was given.
  printf '#!/bin/sh\necho "$1 $2 $(wc -c)" >%s/passed-on\n' "$SPOOL" | sudo tee "$SPOOL/node-handler" >/dev/null
  sudo chmod 755 "$SPOOL/node-handler"
  PATTERN_BEFORE=$(cat /proc/sys/kernel/core_pattern)
  echo "|$SPOOL/node-handler %s %e" | sudo tee /proc/sys/kernel/core_pattern >/dev/null
  printf 'kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n  - role: control-plane\n    extraMounts:\n      - {hostPath: %s, containerPath: %s}\n' "$SPOOL" "$SPOOL" >"$WORK/$EDGE.yaml"
fi

log "create clusters"
for c in "$HUB" "$EDGE"; do
  kind get clusters 2>/dev/null | grep -qx "$c" || kind create cluster --name "$c" --wait 120s $([ -f "$WORK/$c.yaml" ] && echo "--config $WORK/$c.yaml") >/dev/null
  kind load image-archive "$WORK/image.tar" --name "$c" >/dev/null
done
hub() { kubectl --context "kind-$HUB" "$@"; }
edge() { kubectl --context "kind-$EDGE" "$@"; }

log "demo workload and RBAC in both clusters"
for k in hub edge; do
  $k create namespace shop --dry-run=client -o yaml | $k apply -f - >/dev/null
  $k apply -f - >/dev/null <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  replicas: 2
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      securityContext: {runAsNonRoot: true, runAsUser: 1000, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: web
          image: docker.io/library/busybox:1.37
          # Serves a page and requests it over loopback, so the pod has traffic.
          # It also serves stand-ins for Go's profile endpoints.
          # It crashes when the file /tmp/crash appears, and after a child
          # died of a segmentation fault when /tmp/segv appears. Kubernetes
          # turns $$$$ into $$, the shell's own process ID.
          command: [sh, -c, "mkdir -p /tmp/www/debug/pprof; cd /tmp/www; echo hello > index.html; echo goroutine > debug/pprof/index.html; echo cpu-profile > debug/pprof/profile; echo heap-profile > debug/pprof/heap; httpd -p 8080 -h /tmp/www; while [ ! -e /tmp/crash ] && [ ! -e /tmp/segv ]; do wget -qO- http://127.0.0.1:8080/ >/dev/null; echo served a request; sleep 0.2; done; echo crashing; [ -e /tmp/segv ] && sh -c 'kill -SEGV $$$$'; exit 3"]
          securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
---
# Members of the group "devs" may exec into pods of this namespace; that right
# also lets them capture its workloads.
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: exec, namespace: shop}
rules:
  - apiGroups: [""]
    resources: [pods/exec]
    verbs: [create]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: devs-exec, namespace: shop}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: exec}
subjects:
  - {apiGroup: rbac.authorization.k8s.io, kind: Group, name: devs}
EOF
  # The workload namespace keeps Pod Security "restricted".
  $k label namespace shop pod-security.kubernetes.io/enforce=restricted --overwrite >/dev/null
done

log "install hub and local agents"
TOKEN=edge-join-token-0123456789abcdef0123456789abcdef
BOB=bob-token-0123456789abcdef0123456789abc ALICE=alice-token-0123456789abcdef0123456789 ROOT=root-token-0123456789abcdef0123456789ab MALLORY=mallory-token-0123456789abcdef012345
ALERTS=alert-token-0123456789abcdef0123456789abcd
hub create namespace asservat --dry-run=client -o yaml | hub apply -f - >/dev/null
helm --kube-context "kind-$HUB" upgrade --install asservat charts/asservat -n asservat --wait --timeout 5m \
  --set image.repository=localhost/asservat,image.tag=e2e,image.pullPolicy=Never \
  --set hub.service.type=NodePort,hub.service.nodePort=30080 \
  --set hub.users[0].name=alice,hub.users[0].token=$ALICE,hub.users[0].groups[0]=devs \
  --set hub.users[1].name=root,hub.users[1].token=$ROOT,hub.users[1].groups[0]=asservat-admins \
  --set hub.users[2].name=mallory,hub.users[2].token=$MALLORY \
  --set hub.users[3].name=bob,hub.users[3].token=$BOB,hub.users[3].groups[0]=devs \
  --set hub.alertToken=$ALERTS \
  --set hub.clusters[0].name=edge,hub.clusters[0].token=$TOKEN >/dev/null
hub -n asservat port-forward svc/asservat-hub "$PORT:80" >/dev/null 2>&1 &
FORWARD=$!
for _ in $(seq 50); do curl -s -o /dev/null "$URL/healthz" && break; sleep 0.2; done

log "join the edge cluster"
# The edge cluster and its join token are part of the hub's configuration.
case "$(status "$ROOT" POST /api/clusters '{"name":"other"}')" in 404|405) ;; *) fail "a cluster was added through the API" ;; esac
HUB_IP=$(docker inspect "$HUB-control-plane" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
edge create namespace asservat --dry-run=client -o yaml | edge apply -f - >/dev/null
helm --kube-context "kind-$EDGE" upgrade --install asservat charts/asservat -n asservat --wait --timeout 5m \
  --set image.repository=localhost/asservat,image.tag=e2e,image.pullPolicy=Never \
  --set hub.enabled=false,agent.hubURL="http://$HUB_IP:30080",agent.token="$TOKEN" \
  ${CORE_HANDLER:+--set agent.coreHandler.enabled=true,agent.coreHandler.hostPath=$SPOOL} >/dev/null
hub -n shop rollout status deployment/web --timeout 180s >/dev/null
edge -n shop rollout status deployment/web --timeout 180s >/dev/null
for _ in $(seq 60); do
  [ "$(ok "$ALICE" GET /api/clusters | jq -c '[.[] | select(.nodes | length > 0) | .name]')" = '["edge","local"]' ] && break
  sleep 1
done
ok "$ALICE" GET /api/clusters | jq -c .
[ "$(ok "$ALICE" GET /api/clusters | jq '[.[] | select(.nodes | length > 0)] | length')" = 2 ] || fail "agents of both clusters did not connect"

log "permissions follow the cluster's RBAC"
[ "$(ok "$ALICE" GET /api/clusters/edge/namespaces)" = '["shop"]' ] || fail "namespaces that alice may capture in"
[ "$(ok "$MALLORY" GET /api/clusters/edge/namespaces)" = '[]' ] || fail "namespaces offered to mallory"
[ "$(ok "$ALICE" GET /api/clusters/edge/namespaces/shop/workloads)" = '["Deployment/web"]' ] || fail "workloads of edge/shop"
[ "$(ok "$ALICE" GET '/api/clusters/edge/namespaces/shop/containers?workload=Deployment/web')" = '["web"]' ] || fail "containers of the workload"
[ "$(status "$MALLORY" GET /api/clusters/edge/namespaces/shop/workloads)" = 403 ] || fail "mallory listed workloads"
[ "$(status "$ALICE" GET /api/clusters/edge/namespaces/kube-system/workloads)" = 403 ] || fail "alice listed kube-system"
# target CLUSTER KIND [JSON]: a request for the demo workload; an empty kind leaves the recordings to JSON.
target() { jq -cn --arg c "$1" --arg k "$2" --argjson extra "${3:-{\}}" '{cluster: $c, namespace: "shop", workload: "Deployment/web"} + (if $k == "" then {} else {kind: $k} end) + $extra'; }
[ "$(status "$MALLORY" POST /api/captures "$(target edge pod-state)")" = 403 ] || fail "mallory captured"

log "pod state and logs (edge, both replicas)"
id=$(capture "$ALICE" "$(target edge pod-state)"); completed "$ALICE" "$id"
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq '.artifacts | length')" = 4 ] || fail "pod-state files of two pods"
name=$(ok "$ALICE" GET "/api/captures/$id" | jq -r '.artifacts[] | select(.name | endswith("pod.json")) | .name' | head -1)
fetch "$ALICE" "$id" "$name" "$WORK/pod.json"
[ "$(jq -r .metadata.namespace "$WORK/pod.json")" = shop ] || fail "pod.json"
[ "$(status "$MALLORY" GET "/api/captures/$id/artifacts/$name")" = 404 ] || fail "mallory downloaded evidence"
id=$(capture "$ALICE" "$(target edge logs '{"params":{"tailLines":"20"}}')"); completed "$ALICE" "$id"
fetch "$ALICE" "$id" "$(first_artifact "$ALICE" "$id")" "$WORK/web.log"
grep -q 'served a request' "$WORK/web.log" || fail "log content"

log "packet capture, headers only (hub cluster)"
id=$(capture "$ALICE" "$(target local pcap '{"durationSeconds":5,"params":{"filter":"tcp port 8080"}}')")
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -r .sensitive)" = false ] || fail "header capture marked sensitive"
completed "$ALICE" "$id"
fetch "$ALICE" "$id" "$(first_artifact "$ALICE" "$id")" "$WORK/capture.pcap"
magic=$(od -An -tx1 -N4 "$WORK/capture.pcap" | tr -d ' ')
case "$magic" in d4c3b2a1|a1b2c3d4|4d3cb2a1|a1b23c4d) ;; *) fail "not a pcap file: $magic" ;; esac
[ "$(stat -c %s "$WORK/capture.pcap")" -gt 1000 ] || fail "pcap holds no packets"
grep -q 'GET /' "$WORK/capture.pcap" && fail "header capture contains payload"
# Port 8080 (0x1f90) appears in the TCP headers.
LC_ALL=C grep -q $'\x1f\x90' "$WORK/capture.pcap" || fail "pcap lacks the filtered traffic"
# The capture opens in the browser's viewer: Wireshark's sharkd reads it in
# the hub for as long as the opening stream lasts.
: >"$WORK/view" # a kept work directory holds the last run's view
curl -sSN -H "Authorization: Bearer $ALICE" "$URL/api/captures/$id/views/$(first_artifact "$ALICE" "$id")" >"$WORK/view" &
viewer=$!
for _ in $(seq 100); do grep -q '^data: ' "$WORK/view" && break; sleep 0.1; done
view=$(sed -n 's/^data: //p' "$WORK/view")
frames=$(ok "$ALICE" POST "/api/views/$view/frames" '{"filter":"tcp.port == 8080","limit":5}')
jq -e 'length == 5 and (.[0].c | index("TCP") != null)' <<<"$frames" >/dev/null || fail "packet list of the view: $frames"
ok "$ALICE" POST "/api/views/$view/frame" '{"frame":1,"proto":true,"bytes":true}' | jq -e '(.tree | length > 2) and (.bytes | length > 0)' >/dev/null || fail "packet details of the view"
ok "$ALICE" POST "/api/views/$view/tap" '{"tap0":"conv:TCP","tap1":"phs","tap2":"expert"}' | jq -e '(.taps | map({(.tap): .}) | add) as $t | ($t["conv:TCP"].convs | length > 0) and ($t.phs.protos[0].frames > 0) and ($t.expert.type == "expert")' >/dev/null || fail "statistics of the view"
[ "$(status "$ALICE" POST "/api/views/$view/tap" '{"tap0":"eo:http"}')" = 400 ] || fail "a statistic that does more than count"
[ "$(status "$MALLORY" POST "/api/views/$view/status" '{}')" = 404 ] || fail "mallory asked alice's view"
kill $viewer
# The other viewers read in the browser; the hub names them and serves them.
ok "$ALICE" GET /api/captures | jq -e '[.[].artifacts[].viewer] | contains(["kube", "log", "pcap"])' >/dev/null || fail "viewers of the files so far"
for v in gotrace heap kube log pcap pprof stacks strace; do curl -sS --fail -o /dev/null "$URL/view/$v.js" "$URL/view/$v.css" || fail "viewer $v is not served"; done
grep -q '/view/common.js' <<<"$(curl -sS --fail "$URL/view")" || fail "viewer page"
# The look is served by the hub itself: style, mark and fonts.
for a in identity.css mark.svg barlow-condensed-700.woff2 ibm-plex-sans-400.woff2 ibm-plex-mono-400.woff2; do curl -sS --fail -o /dev/null "$URL/assets/$a" || fail "asset $a is not served"; done
[ "$(ok "$ALICE" GET /api/captures | jq '[.[].number] | (length > 0) and (unique | length) == length and all(. > 0)')" = true ] || fail "numbers of the captures"

log "what runs and who talks: the choices for a process and a packet filter (edge)"
processes=$(ok "$ALICE" GET '/api/clusters/edge/namespaces/shop/processes?workload=Deployment/web')
jq -e '(.pods | length == 2) and (.processes[0] | .container == "web" and .executable == "/bin/sh" and .main and .pods == 2 and .processes == 2) and ([.processes[].executable] | index("/bin/httpd") != null)' <<<"$processes" >/dev/null || fail "processes: $processes"
[ "$(status "$MALLORY" POST '/api/clusters/edge/namespaces/shop/traffic?workload=Deployment/web')" = 403 ] || fail "mallory sampled traffic"
sample=$(ok "$ALICE" POST '/api/clusters/edge/namespaces/shop/traffic?workload=Deployment/web&seconds=3')
flow=$(jq -c '.flows[] | select(.direction == "local" and .port == 8080)' <<<"$sample")
[ "$(jq -r .label <<<"$flow")" = "Inside the pod on TCP port 8080" ] || fail "traffic sample: $sample"
# The filter of a sampled flow selects that traffic in a capture.
id=$(capture "$ALICE" "$(target edge pcap "$(jq -c '{durationSeconds: 3, params: {filter: .filter}}' <<<"$flow")")"); completed "$ALICE" "$id"
fetch "$ALICE" "$id" "$(first_artifact "$ALICE" "$id")" "$WORK/sampled.pcap"
[ "$(stat -c %s "$WORK/sampled.pcap")" -gt 1000 ] || fail "the sampled flow's filter matched no packets"
# Every process of a program instead of the main process.
id=$(capture "$ALICE" "$(target edge strace '{"durationSeconds":2,"params":{"container":"web","process":"/bin/httpd"}}')"); completed "$ALICE" "$id"
[ "$(status "$ALICE" POST /api/captures "$(target edge strace '{"params":{"process":"/usr/bin/absent"}}')")" = 201 ] || fail "a capture for a program that does not run is accepted and fails on the pods"

log "one request with several recordings: same pods, same time frame, one approval (edge)"
several='{"recordings":[{"kind":"pod-state"},{"kind":"logs","params":{"tailLines":"5"}},{"kind":"pcap","params":{"filter":"tcp port 8080"}},{"kind":"strace"},{"kind":"coredump"}],"durationSeconds":3,"pods":[],"reason":"all at once"}'
id=$(capture "$ALICE" "$(target edge "" "$several")")
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -r '[.state, .sensitive, (.recordings | length), (.artifacts | length)] | @csv')" = '"PendingApproval",true,5,0' ] || fail "a request with a core dump did not wait as a whole"
ok "$ROOT" POST "/api/captures/$id/approve" >/dev/null
completed "$ALICE" "$id"
bundle=$(ok "$ALICE" GET "/api/captures/$id")
# Each of the two pods delivers the files of all five recordings, and the description of its core.
[ "$(jq -c '[.artifacts[].name | split("/")[1]] | unique' <<<"$bundle")" = '["capture.pcap","core.web","core.web.analysis.json","core.web.files.tar","events.json","pod.json","web.log","web.strace"]' ] || fail "files of the recordings: $(jq -c '[.artifacts[].name]' <<<"$bundle")"
[ "$(jq -c '[(.artifacts | length), ([.tasks[].message // ""] | unique)]' <<<"$bundle")" = '[16,[""]]' ] || fail "recordings per pod: $(jq -c .tasks <<<"$bundle")"

log "progress, and stopping a capture with what it has (edge)"
id=$(capture "$ALICE" "$(target edge "" '{"durationSeconds":300,"recordings":[{"kind":"pcap"},{"kind":"logs"},{"kind":"pod-state"}]}')")
for _ in $(seq 30); do
  running=$(ok "$ALICE" GET "/api/captures/$id")
  # Until the packet captures run and the pod states, which take no time, are done.
  [ "$(jq -c '[([.tasks[].recordings[]? | select(.kind == "pcap") | .state] | unique), ([.tasks[].recordings[]? | select(.kind == "pod-state") | .state] | unique)]' <<<"$running")" = '[["Running"],["Completed"]]' ] && break
  sleep 1
done
# Each pod shows how its recordings get on, and most of the five minutes are left.
[ "$(jq -c '[.state, ([.tasks[].recordings[] | select(.kind == "pod-state") | .state] | unique), (.remainingSeconds > 250)]' <<<"$running")" = '["Running",["Completed"],true]' ] || fail "progress of a running capture: $(jq -c '[.state, .remainingSeconds, .tasks]' <<<"$running")"
[ "$(status "$MALLORY" POST "/api/captures/$id/stop")" = 404 ] || fail "mallory stopped a capture"
sleep 2
ok "$ALICE" POST "/api/captures/$id/stop" >/dev/null
completed "$ALICE" "$id"
stopped=$(ok "$ALICE" GET "/api/captures/$id")
[ "$(jq -c '[([.tasks[].recordings[] | select(.kind == "pcap" or .kind == "logs") | .message] | unique), ([.artifacts[].name | split("/")[1]] | unique)]' <<<"$stopped")" = '[["stopped early"],["capture.pcap","events.json","pod.json","web.log"]]' ] || fail "stopped capture: $(jq -c '[.tasks, [.artifacts[].name]]' <<<"$stopped")"
fetch "$ALICE" "$id" "$(jq -r '.artifacts[] | select(.name | endswith("capture.pcap")) | .name' <<<"$stopped" | head -1)" "$WORK/stopped.pcap"
[ "$(stat -c %s "$WORK/stopped.pcap")" -gt 1000 ] || fail "the stopped packet capture kept no packets"
[ "$(status "$ALICE" POST "/api/captures/$id/stop")" = 409 ] || fail "stopped a finished capture"

log "system call trace (edge)"
id=$(capture "$ALICE" "$(target edge strace '{"durationSeconds":3}')"); completed "$ALICE" "$id"
fetch "$ALICE" "$id" "$(first_artifact "$ALICE" "$id")" "$WORK/web.strace"
grep -Eq '(wait4|nanosleep|clock_nanosleep|execve|read)\(' "$WORK/web.strace" || fail "strace content: $(head -3 "$WORK/web.strace")"

log "HTTP profile endpoint, fetched inside the pod's network namespace (edge)"
# The demo serves files as its profiles: a synthetic one in pprof's format
# as the CPU profile, a word as the heap profile, a synthetic execution trace.
# kubectl sometimes loses the end of what it copies into a pod: a file is
# copied again until the pod holds all of it.
put() {
  for _ in 1 2 3; do
    edge -n shop exec -i "$1" -- sh -c "cat >$3" <"$2" || true
    [ "$(edge -n shop exec "$1" -- sh -c "wc -c <$3" | tr -d ' ')" = "$(wc -c <"$2" | tr -d ' ')" ] && return
  done
  fail "copying $2 into $1"
}
for p in $(edge -n shop get pods -l app=web -o name); do
  put "$p" test/e2e/synthetic-cpu.pprof /tmp/www/debug/pprof/profile
  put "$p" test/e2e/synthetic-trace.out /tmp/www/debug/pprof/trace
done
# Sampled profiles need no endpoint: the agent takes the stacks of the pods' processes in the node's kernel.
if [ -n "${SAMPLE_CPU:-}" ]; then
  # A Python program that computes and keeps taking memory (up to 400 MiB) is sampled: an
  # interpreter's stacks are those of the program it runs, so its functions
  # are named as such, in the profile of CPU time and in that of memory growth.
  edge apply -f - >/dev/null <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata: {name: py, namespace: shop}
spec:
  selector: {matchLabels: {app: py}}
  template:
    metadata: {labels: {app: py}}
    spec:
      securityContext: {runAsNonRoot: true, runAsUser: 1000, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: py
          image: docker.io/library/python:3.12-slim
          command: [python3, -c, "held = []\ndef grow():\n    held.append(b'x' * (1 << 14))\n    if len(held) > 25000: held.clear()\ndef burn():\n    return sum(i * i for i in range(100000))\nwhile True:\n    burn()\n    grow()"]
          securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
EOF
  edge -n shop rollout status deployment/py --timeout 180s >/dev/null
  # A core of the Python program is described with its Python stacks: the
  # interpreter's own threads tell nothing of what the program did. The
  # agent's image has no tool for them: the hub adds them when the core has
  # arrived, and who opens the core meanwhile waits for that, as here.
  id=$(capture "$ALICE" '{"cluster":"edge","namespace":"shop","workload":"Deployment/py","recordings":[{"kind":"coredump"}]}')
  ok "$ROOT" POST "/api/captures/$id/approve" >/dev/null
  completed "$ALICE" "$id"
  pod=$(ok "$ALICE" GET "/api/captures/$id" | jq -r '.tasks[0].pod')
  ok "$ALICE" POST "/api/captures/$id/describe" "{\"name\":\"$pod/core.py\"}" >/dev/null
  fetch "$ALICE" "$id" "$pod/core.py.analysis.json" "$WORK/core.py.analysis.json"
  # The program is in one of its functions; in about one core of a hundred the
  # interpreter is just entering the generator, whose frame then stands alone.
  jq -e '(.awaits | not) and (.runtimeStacks[0] | .runtime == "python" and (.version | startswith("3.12")) and (.threads | length == 1) and (.threads[0].frames[0] | .line > 0 and (.function | IN("<module>", "burn", "grow", "<genexpr>"))))' "$WORK/core.py.analysis.json" >/dev/null \
    || fail "the Python stacks of a core: $(jq -c '[.awaits, .runtimeStacks]' "$WORK/core.py.analysis.json" | head -c 600)"
  id=$(capture "$ALICE" '{"cluster":"edge","namespace":"shop","workload":"Deployment/py","recordings":[{"kind":"cpu"},{"kind":"memory"}],"durationSeconds":10}'); completed "$ALICE" "$id"
  pod=$(ok "$ALICE" GET "/api/captures/$id" | jq -r '.tasks[0].pod')
  [ "$(ok "$ALICE" GET "/api/captures/$id" | jq -r '[.sensitive, .artifacts[0].name, .artifacts[1].name, .artifacts[1].viewer] | @csv')" = "false,\"$pod/sampled-cpu.pprof\",\"$pod/sampled-memory.pprof\",\"pprof\"" ] || fail "the sampled CPU profile: $(ok "$ALICE" GET "/api/captures/$id" | jq -c '[.message, .tasks, .artifacts]')"
  : >"$WORK/view"
  curl -sSN -H "Authorization: Bearer $ALICE" "$URL/api/captures/$id/views/$pod/sampled-cpu.pprof" >"$WORK/view" &
  viewer=$!
  for _ in $(seq 100); do grep -q '^data: ' "$WORK/view" && break; sleep 0.2; done
  view=$(sed -n 's/^data: //p' "$WORK/view" | head -1)
  # The flame graph holds every function; the top list only those with the most weight of their own.
  graph=$(curl -sS --fail -H "Authorization: Bearer $ALICE" "$URL/api/views/$view/pages/flamegraph")
  fetch "$ALICE" "$id" "$pod/sampled-cpu.pprof" "$WORK/sampled-cpu.pprof"
  grep -q 'burn' <<<"$graph" && grep -q 'genexpr' <<<"$graph" || fail "Python's functions in the profile of CPU time: $(go tool pprof -traces "$WORK/sampled-cpu.pprof" 2>&1 | head -150)"
  kill "$viewer"
  : >"$WORK/view"
  curl -sSN -H "Authorization: Bearer $ALICE" "$URL/api/captures/$id/views/$pod/sampled-memory.pprof" >"$WORK/view" &
  viewer=$!
  for _ in $(seq 100); do grep -q '^data: ' "$WORK/view" && break; sleep 0.2; done
  view=$(sed -n 's/^data: //p' "$WORK/view" | head -1)
  graph=$(curl -sS --fail -H "Authorization: Bearer $ALICE" "$URL/api/views/$view/pages/flamegraph")
  fetch "$ALICE" "$id" "$pod/sampled-memory.pprof" "$WORK/sampled-memory.pprof"
  grep -q 'grow' <<<"$graph" || fail "Python's functions in the flame graph of memory growth: a page of ${#graph} bytes for view '$view'; the profile's stacks: $(go tool pprof -traces "$WORK/sampled-memory.pprof" 2>&1 | head -40)"
  grown=$(go tool pprof -top "$WORK/sampled-memory.pprof" 2>&1)
  grep -q 'Total samples = [1-9][0-9.]*[kMG]B' <<<"$grown" || fail "the amount of memory growth: $(head -8 <<<"$grown")"
  kill "$viewer"
  # A watch keeps the CPU profile running: the capture of the busy program,
  # made as soon as its CPU use is measured, holds the seconds before that
  # moment as well as the two after it.
  busy=$(ok "$ALICE" POST /api/watches '{"cluster":"edge","namespace":"shop","workload":"Deployment/py","recordings":[{"kind":"cpu"}],"durationSeconds":2,"beforeSeconds":30,"when":{"kind":"cpu","params":{"above":"0.2","seconds":"5"}}}' | jq -r .id)
  for _ in $(seq 60); do
    noticed=$(ok "$ALICE" GET /api/captures | jq -c --arg w "$busy" '[.[] | select(.watch == $w)][0]')
    [ "$noticed" != null ] && break
    sleep 1
  done
  [ "$noticed" != null ] || fail "the watch for CPU use did not record"
  id=$(jq -r .id <<<"$noticed"); completed "$ALICE" "$id"
  pod=$(ok "$ALICE" GET "/api/captures/$id" | jq -r '.tasks[0].pod')
  fetch "$ALICE" "$id" "$pod/sampled-cpu.pprof" "$WORK/before.pprof"
  sampled=$(go tool pprof -top "$WORK/before.pprof" 2>/dev/null | sed -n 's/.*Total samples = \([0-9.]*\)s.*/\1/p')
  awk -v s="${sampled:-0}" 'BEGIN { exit !(s > 3.5) }' || fail "the profile of a watch that reaches back holds ${sampled:-no} seconds of samples, not more than its two seconds after the moment"
  edge -n shop delete deployment py --wait=false >/dev/null
  # Once nothing is sampled, the agent gives the kernel back the profiler's
  # programs and maps, which count as the agent's memory: over 100 MiB while
  # the profiler runs, a few without it.
  seen=
  # The watch above ended half a minute ago at most: its profile runs that much longer.
  for _ in $(seq 90); do
    held=$(edge -n asservat exec ds/asservat-agent -- sh -c 'grep "^kernel " /sys/fs/cgroup/memory.stat | cut -d" " -f2')
    seen="$seen $((held >> 20))"
    [ "$held" -lt $((40 << 20)) ] && break
    sleep 1
  done
  [ "$held" -lt $((40 << 20)) ] || fail "the agent still holds $((held >> 20)) MiB of kernel memory after sampling (second by second:$seen)"
fi
# The pod's ports are asked for the known profile endpoints; the found ones are fetched at once.
found=$(ok "$ALICE" POST '/api/clusters/edge/namespaces/shop/profiles?workload=Deployment/web')
[ "$(jq -c '[.ports, [.profiles[] | select(.endpoint == "go-cpu" or .endpoint == "go-heap") | [.port, .endpoint, .timed, .sensitive]]]' <<<"$found")" = '[[8080],[[8080,"go-cpu",true,false],[8080,"go-heap",false,false]]]' ] || fail "profile endpoints: $found"
id=$(capture "$ALICE" "$(target edge pprof '{"durationSeconds":1,"params":{"endpoints":"8080/go-cpu,8080/go-heap,8080/go-trace"}}')"); completed "$ALICE" "$id"
pod=$(ok "$ALICE" GET "/api/captures/$id" | jq -r '.tasks[0].pod')
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -r '[.sensitive, (.artifacts | length)] | @csv')" = 'false,6' ] || fail "profiles of three endpoints on two pods"
fetch "$ALICE" "$id" "$pod/cpu.pprof" "$WORK/cpu.pprof"; fetch "$ALICE" "$id" "$pod/heap.pprof" "$WORK/heap.pprof"
cmp -s "$WORK/cpu.pprof" test/e2e/synthetic-cpu.pprof && [ "$(cat "$WORK/heap.pprof")" = heap-profile ] || fail "profile contents"
# A profile in pprof's format opens in pprof's own web interface, served by the hub for the view.
: >"$WORK/view" # a kept work directory holds the last run's view
curl -sSN -H "Authorization: Bearer $ALICE" "$URL/api/captures/$id/views/$pod/cpu.pprof" >"$WORK/view" &
viewer=$!
for _ in $(seq 100); do grep -q '^data: ' "$WORK/view" && break; sleep 0.1; done
view=$(sed -n 's/^data: //p' "$WORK/view")
top=$(curl -sS --fail -H "Authorization: Bearer $ALICE" "$URL/api/views/$view/pages/top")
grep -q 'shop.priceOf' <<<"$top" || fail "pprof's top page"
grep -q '/view/framed.css' <<<"$top" && curl -sS --fail -o /dev/null "$URL/view/framed.css" || fail "pprof's page in Asservat's type"
grep -q '<svg' <<<"$(curl -sS --fail -H "Authorization: Bearer $ALICE" "$URL/api/views/$view/pages/graph")" || fail "pprof's graph page, drawn by dot"
kill $viewer
[ "$(status "$ALICE" GET "/api/captures/$id/views/$pod/heap.pprof")" = 422 ] || fail "a file that is no profile opened in pprof"
# Against a base, here the other pod's profile, pprof shows the difference: none.
other=$(ok "$ALICE" GET "/api/captures/$id" | jq -r '.tasks[1].pod')
: >"$WORK/view"
curl -sSN -H "Authorization: Bearer $ALICE" "$URL/api/captures/$id/views/$pod/cpu.pprof?base=$id/$other/cpu.pprof" >"$WORK/view" &
viewer=$!
for _ in $(seq 100); do grep -q '^data: ' "$WORK/view" && break; sleep 0.1; done
view=$(sed -n 's/^data: //p' "$WORK/view")
grep -q 'accounting for 0' <<<"$(curl -sS --fail -H "Authorization: Bearer $ALICE" "$URL/api/views/$view/pages/top")" || fail "pprof's difference to a base"
kill $viewer
# An execution trace opens in Go's own trace tool, which the hub runs for the view; its links lead to the view's pages.
: >"$WORK/view"
curl -sSN -H "Authorization: Bearer $ALICE" "$URL/api/captures/$id/views/$pod/trace.out" >"$WORK/view" &
viewer=$!
for _ in $(seq 100); do grep -q '^data: ' "$WORK/view" && break; sleep 0.1; done
view=$(sed -n 's/^data: //p' "$WORK/view")
grep -q "href=\"/api/views/$view/pages/goroutines\"" <<<"$(curl -sS --fail -H "Authorization: Bearer $ALICE" "$URL/api/views/$view/pages/")" || fail "the first page of Go's trace tool"
grep -q 'Goroutines' <<<"$(curl -sS --fail -H "Authorization: Bearer $ALICE" "$URL/api/views/$view/pages/goroutines")" || fail "goroutine analysis of Go's trace tool"
kill $viewer
# An endpoint that Asservat does not know can return anything: it needs approval.
id=$(capture "$ALICE" "$(target edge pprof '{"params":{"port":"8080","path":"/index.html"}}')")
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -r .state)" = PendingApproval ] || fail "an unknown endpoint did not wait for approval"
ok "$ROOT" POST "/api/captures/$id/approve" >/dev/null
completed "$ALICE" "$id"
fetch "$ALICE" "$id" "$(first_artifact "$ALICE" "$id")" "$WORK/profile.out"
[ "$(cat "$WORK/profile.out")" = hello ] || fail "content of the unknown endpoint"
[ "$(status "$ALICE" POST /api/captures "$(target edge pprof)")" = 400 ] || fail "a profile without an endpoint was accepted"

log "the managed stacks of .NET programs, on glibc and on Alpine's musl (edge)"
# One synthetic program, built once on this machine, runs in Microsoft's
# runtime image for glibc and in the one for Alpine. The core of each is
# described with its managed stacks, which the hub reads: with the tool's
# runtime for glibc and with the one for musl.
mkdir -p "$WORK/dotnet"
cat >"$WORK/dotnet/Program.cs" <<'EOF2'
namespace Shop {
    static class Billing {
        public static void Charge(decimal amount) { Hold(new System.InvalidOperationException("card declined for " + amount)); }
        static void Hold(System.Exception e) { System.Console.WriteLine("ready"); System.Threading.Thread.Sleep(System.Threading.Timeout.Infinite); System.GC.KeepAlive(e); }
    }
    static class Program { static void Main() { Billing.Charge(12.5m); } }
}
EOF2
docker run --rm -v "$WORK/dotnet:/work" mcr.microsoft.com/dotnet/sdk:10.0 sh -c 'mkdir /src && cd /src && dotnet new console -n shop -o . >/dev/null && cp /work/Program.cs . && dotnet build -c Debug -o /work/out >/work/build.log 2>&1 && chmod -R a+rX /work/out' \
  || fail "the .NET program was not built: $(tail -5 "$WORK/dotnet/build.log" 2>&1)"
edge -n shop create configmap dotnet-app --from-file="$WORK/dotnet/out/shop.dll" --from-file="$WORK/dotnet/out/shop.pdb" --from-file="$WORK/dotnet/out/shop.runtimeconfig.json" >/dev/null
for libc in glibc musl; do
  image=mcr.microsoft.com/dotnet/runtime:10.0; [ $libc = musl ] && image=$image-alpine
  edge apply -f - >/dev/null <<EOF2
apiVersion: apps/v1
kind: Deployment
metadata: {name: dotnet-$libc, namespace: shop}
spec:
  selector: {matchLabels: {app: dotnet-$libc}}
  template:
    metadata: {labels: {app: dotnet-$libc}}
    spec:
      securityContext: {runAsNonRoot: true, runAsUser: 1000, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: app
          image: $image
          command: [dotnet, /app/shop.dll]
          securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
          volumeMounts: [{name: app, mountPath: /app}]
      volumes: [{name: app, configMap: {name: dotnet-app}}]
EOF2
done
for libc in glibc musl; do
  edge -n shop rollout status deployment/dotnet-$libc --timeout 240s >/dev/null
  pod=$(edge -n shop get pods -l app=dotnet-$libc -o jsonpath='{.items[0].metadata.name}')
  for _ in $(seq 60); do edge -n shop logs "$pod" | grep -q ready && break; sleep 1; done
  id=$(capture "$ALICE" "{\"cluster\":\"edge\",\"namespace\":\"shop\",\"workload\":\"Deployment/dotnet-$libc\",\"recordings\":[{\"kind\":\"coredump\"}]}")
  ok "$ROOT" POST "/api/captures/$id/approve" >/dev/null
  completed "$ALICE" "$id"
  # The hub adds the stacks when the core has arrived; who opens it meanwhile waits for that.
  ok "$ALICE" POST "/api/captures/$id/describe" "{\"name\":\"$pod/core.app\"}" >/dev/null
  fetch "$ALICE" "$id" "$pod/core.app.analysis.json" "$WORK/core.dotnet-$libc.analysis.json"
  jq -e '(.awaits | not) and (.runtimeStacks[0] | .runtime == "dotnet" and (.version | startswith("10.")) and ([.threads[].frames[] | select((.function | startswith("Shop.Billing.Charge(")) and (.file | endswith("Program.cs")) and .line > 0)] | length == 1))' "$WORK/core.dotnet-$libc.analysis.json" >/dev/null \
    || fail "the managed stacks of a .NET core on $libc: $(jq -c '[.awaits, .runtimeStacks]' "$WORK/core.dotnet-$libc.analysis.json" | head -c 700); the hub said: $(hub -n asservat logs deploy/asservat-hub --tail=8 2>&1 | tail -c 900)"
  edge -n shop delete deployment dotnet-$libc --wait=false >/dev/null
done

log "a JVM's own diagnostics, asked over its attach socket (edge)"
# A Java program that serves nothing: threads with names to recognize wait
# in a method to recognize. It runs as any workload does, as a user that is
# not root, so the agent has to ask as that user.
edge -n shop create configmap blocked --from-file=internal/agent/testdata/Blocked.java --dry-run=client -o yaml | edge apply -f - >/dev/null
edge apply -f - >/dev/null <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata: {name: jvm, namespace: shop}
spec:
  selector: {matchLabels: {app: jvm}}
  template:
    metadata: {labels: {app: jvm}}
    spec:
      securityContext: {runAsNonRoot: true, runAsUser: 1000, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: app
          image: docker.io/library/eclipse-temurin:21-jdk
          command: [java, /src/Blocked.java]
          securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
          volumeMounts: [{name: src, mountPath: /src}]
      volumes: [{name: src, configMap: {name: blocked}}]
EOF
edge -n shop rollout status deployment/jvm --timeout 300s >/dev/null
jvm=$(edge -n shop get pods -l app=jvm -o jsonpath='{.items[0].metadata.name}')
for _ in $(seq 60); do edge -n shop logs "$jvm" | grep -q waiting && break; sleep 1; done
jvm_target() { jq -cn --argjson extra "$1" '{cluster: "edge", namespace: "shop", workload: "Deployment/jvm", kind: "pprof"} + $extra'; }
found=$(ok "$ALICE" POST '/api/clusters/edge/namespaces/shop/profiles?workload=Deployment/jvm')
[ "$(jq -c '[.profiles[] | [.container, .endpoint, .timed, .sensitive]]' <<<"$found")" = '[["app","jvm-threads",false,false],["app","jvm-histogram",false,false],["app","jvm-heapdump",false,true],["app","jvm-recording",true,false]]' ] || fail "the JVM's diagnostics were not found: $found"
# Looking for them wrote nothing into the container.
[ -z "$(edge -n shop exec "$jvm" -- ls -A /tmp | grep -v hsperfdata)" ] || fail "the search left something in the container's /tmp"
id=$(capture "$ALICE" "$(jvm_target '{"durationSeconds":2,"params":{"endpoints":"app/jvm-threads,app/jvm-histogram,app/jvm-recording"}}')"); completed "$ALICE" "$id"
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -c '[.sensitive, ([.artifacts[] | [.name, .viewer // ""]] | sort)]')" = "[false,[[\"$jvm/jvm-histogram.txt\",\"log\"],[\"$jvm/jvm-recording.jfr\",\"\"],[\"$jvm/jvm-threaddump.txt\",\"stacks\"]]]" ] \
  || fail "the files of a JVM's diagnostics: $(ok "$ALICE" GET "/api/captures/$id" | jq -c '[.sensitive, .message, .artifacts]')"
fetch "$ALICE" "$id" "$jvm/jvm-threaddump.txt" "$WORK/jvm-threaddump.txt"
grep -q '"asservat-courier-2"' "$WORK/jvm-threaddump.txt" && grep -q 'Blocked.waitForParcel' "$WORK/jvm-threaddump.txt" || fail "the thread dump does not name the program's threads: $(head -5 "$WORK/jvm-threaddump.txt")"
fetch "$ALICE" "$id" "$jvm/jvm-histogram.txt" "$WORK/jvm-histogram.txt"
grep -q 'Blocked\$Parcel' "$WORK/jvm-histogram.txt" || fail "the class histogram does not name the program's class: $(head -5 "$WORK/jvm-histogram.txt")"
fetch "$ALICE" "$id" "$jvm/jvm-recording.jfr" "$WORK/jvm-recording.jfr"
[ "$(head -c 3 "$WORK/jvm-recording.jfr")" = FLR ] || fail "the flight recording is none"
# A heap dump is the program's memory: it waits for an administrator.
id=$(capture "$ALICE" "$(jvm_target '{"params":{"endpoints":"app/jvm-heapdump"}}')")
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -r .state)" = PendingApproval ] || fail "a heap dump did not wait for approval"
ok "$ROOT" POST "/api/captures/$id/approve" >/dev/null
completed "$ALICE" "$id"
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -r '.artifacts[0] | [.name, .viewer] | @csv')" = "\"$jvm/jvm-heapdump.hprof\",\"heap\"" ] || fail "the heap dump's file"
fetch "$ALICE" "$id" "$jvm/jvm-heapdump.hprof" "$WORK/jvm-heapdump.hprof"
[ "$(head -c 12 "$WORK/jvm-heapdump.hprof")" = 'JAVA PROFILE' ] || fail "the heap dump is none"
# Nothing stays in the container but the JVM's own socket and the empty
# directory of its flight recorder, and the JVM ran on: it was not
# restarted and wrote no thread dump to its output, as it does at a SIGQUIT
# that asks for nothing.
left=$(edge -n shop exec "$jvm" -- sh -c 'ls -A /tmp; find /tmp -type f')
[ -z "$(grep -E 'asservat-|attach_pid|\.hprof|\.jfr' <<<"$left")" ] || fail "left in the JVM's container: $left"
[ "$(edge -n shop get pod "$jvm" -o jsonpath='{.status.containerStatuses[0].restartCount}')" = 0 ] || fail "the JVM was restarted"
[ "$(edge -n shop logs "$jvm")" = waiting ] || fail "the JVM wrote to its output: $(edge -n shop logs "$jvm" | head -5)"
edge -n shop delete deployment/jvm configmap/blocked >/dev/null
edge -n shop wait --for=delete pod -l app=jvm --timeout=120s >/dev/null

log "core dump (edge) waits for an administrator"
id=$(capture "$ALICE" "$(target edge coredump '{"reason":"e2e","pods":[]}')")
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -r .state)" = PendingApproval ] || fail "core dump did not wait for approval"
[ "$(status "$ALICE" POST "/api/captures/$id/approve")" = 403 ] || fail "the requester approved"
sleep 2
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -r '[.state, (.artifacts | length)] | @csv')" = '"PendingApproval",0' ] || fail "core dump ran before approval"
ok "$ROOT" POST "/api/captures/$id/approve" >/dev/null
completed "$ALICE" "$id"
fetch "$ALICE" "$id" "$(first_artifact "$ALICE" "$id")" "$WORK/core.web"
[ "$(od -An -tx1 -N4 "$WORK/core.web" | tr -d ' ')" = 7f454c46 ] || fail "core is not an ELF file"
[ "$(od -An -tu2 -j16 -N2 "$WORK/core.web" | tr -d ' ')" = 4 ] || fail "ELF file is not a core (ET_CORE)"
# gdb described the core on the node, with the program's files at hand; the viewer shows that.
# The shell is caught waiting for a child or starting one, so any function with a name shows that symbols were read.
pod=$(ok "$ALICE" GET "/api/captures/$id" | jq -r '.tasks[0].pod')
fetch "$ALICE" "$id" "$pod/core.web.analysis.json" "$WORK/core.web.analysis.json"
jq -e '.executable == "/bin/sh" and .symbols and (.commandLine | startswith("/bin/sh -c mkdir")) and .stopped == "" and (.threads | length == 1) and (.threads[0].frames | length > 1) and (.threads[0].frames[0].registers | length > 10) and ([.threads[0].frames[].function] | any(. != "")) and (.modules | length > 0) and (.mappings | length > 5)' "$WORK/core.web.analysis.json" >/dev/null || fail "description of the core: $(cat "$WORK/core.web.analysis.json")"
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -c '[.artifacts[] | select(.name | endswith(".files.tar") | not) | .viewer] | unique')" = '["core"]' ] || fail "viewer of cores"
# The program's files are kept with the core, for a debugger and for the hub to describe it again;
# the description is this version's, so the hub leaves it.
fetch "$ALICE" "$id" "$pod/core.web.files.tar" "$WORK/core.web.files.tar"
# Listed first: grep leaves at its first match, and a tar that is still writing then fails the pipe.
listed=$(tar -tf "$WORK/core.web.files.tar")
grep -qx 'bin/busybox\|bin/sh' <<<"$listed" || fail "the core's program files: $(head -5 <<<"$listed")"
[ "$(ok "$ALICE" POST "/api/captures/$id/describe" "{\"name\":\"$pod/core.web\"}" | jq -c .)" = '{"described":false,"reason":""}' ] || fail "an up-to-date core was described again"
curl -sS --fail -o /dev/null "$URL/view/core.js" "$URL/view/core.css" || fail "the core viewer is not served"
edge -n shop get pods -o json | jq -e '[.items[].status.containerStatuses[].restartCount] | add == 0' >/dev/null || fail "a captured pod restarted"

log "packet capture with payload (edge) waits for an administrator; a denied capture never runs"
id=$(capture "$ALICE" "$(target edge pcap '{"durationSeconds":3,"params":{"payload":"true"}}')")
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -r .state)" = PendingApproval ] || fail "payload capture did not wait for approval"
ok "$ROOT" POST "/api/captures/$id/approve" >/dev/null
completed "$ALICE" "$id"
fetch "$ALICE" "$id" "$(first_artifact "$ALICE" "$id")" "$WORK/payload.pcap"
grep -q 'GET / HTTP' "$WORK/payload.pcap" || fail "approved payload capture lacks the payload"
id=$(capture "$ALICE" "$(target edge pcap '{"params":{"payload":"true"}}')")
ok "$ROOT" POST "/api/captures/$id/deny" >/dev/null
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -r '[.state, (.artifacts | length)] | @csv')" = '"Denied",0' ] || fail "denied capture"
log "a crash watch records the crashed pod (edge): packets from before the crash and the crashed instance's logs"
[ "$(status "$MALLORY" POST /api/watches "$(target edge pod-state)")" = 403 ] || fail "mallory watched"
# The packet watch also records the pod's state: one crash, one capture with both.
packets=$(ok "$ALICE" POST /api/watches "$(target edge "" '{"durationSeconds":20,"recordings":[{"kind":"pcap","params":{"filter":"tcp port 8080"}},{"kind":"pod-state"}]}')" | jq -r .id)
logs=$(ok "$ALICE" POST /api/watches "$(target edge logs '{"count":2}')" | jq -r .id)
# A watch that keeps tracing system calls shows the last of them before the crash.
calls=$(ok "$ALICE" POST /api/watches "$(target edge "" '{"durationSeconds":5,"recordings":[{"kind":"strace","params":{"before":"true"}}]}')" | jq -r .id)
sleep 5 # the agents begin to buffer packets and to trace
victim=$(edge -n shop get pods -l app=web -o jsonpath='{.items[0].metadata.name}')
edge -n shop exec "$victim" -- touch /tmp/crash
# triggered WATCH: waits for the capture that the watch created and prints its ID.
triggered() {
  local id
  for _ in $(seq 60); do
    id=$(ok "$ALICE" GET /api/captures | jq -r --arg w "$1" '[.[] | select(.watch == $w)][0].id // empty')
    [ -n "$id" ] && { printf '%s' "$id"; return; }
    sleep 1
  done
  fail "watch $1 created no capture"
}
id=$(triggered "$packets"); completed "$ALICE" "$id"
ok "$ALICE" GET "/api/captures/$id" | jq -e --arg p "$victim" '(.pods == [$p]) and (.reason | startswith("container web crashed: exit code 3"))' >/dev/null || fail "triggered capture: $(ok "$ALICE" GET "/api/captures/$id")"
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -c '[.artifacts[].name | split("/")[1]]')" = '["capture.pcap","events.json","pod.json"]' ] || fail "files of a watch with two recordings"
fetch "$ALICE" "$id" "$victim/capture.pcap" "$WORK/crash.pcap"
[ "$(stat -c %s "$WORK/crash.pcap")" -gt 1000 ] || fail "the packet buffer holds no packets"
grep -q 'GET /' "$WORK/crash.pcap" && fail "the packet buffer contains payload"
LC_ALL=C grep -q $'\x1f\x90' "$WORK/crash.pcap" || fail "the packet buffer lacks the filtered traffic"
id=$(triggered "$calls"); completed "$ALICE" "$id"
fetch "$ALICE" "$id" "$victim/web.strace" "$WORK/crash.strace"
grep -q 'exited with 3' "$WORK/crash.strace" && grep -q 'execve("/bin/wget"\|wait4(' "$WORK/crash.strace" || fail "the system calls before the crash: $(tail -5 "$WORK/crash.strace")"
id=$(triggered "$logs"); completed "$ALICE" "$id"
# The crashed instance is the current or the previous one, depending on
# whether the container had restarted when the logs were read.
: >"$WORK/crash.log"
for name in $(ok "$ALICE" GET "/api/captures/$id" | jq -r '.artifacts[].name'); do
  fetch "$ALICE" "$id" "$name" "$WORK/part.log"; cat "$WORK/part.log" >>"$WORK/crash.log"
done
grep -q crashing "$WORK/crash.log" || fail "the logs lack the crashed instance"
# The packet watch ended with its one crash; the log watch waits for another.
[ "$(ok "$ALICE" GET /api/watches | jq -c '[.[] | [.recordings[0].kind, .remaining]]')" = '[["logs",1]]' ] || fail "watches after the crash: $(ok "$ALICE" GET /api/watches)"
[ "$(status "$ALICE" DELETE "/api/watches/$logs")" = 200 ] || fail "delete watch"
# A watch for a log line: the demo writes "served a request" several times a
# second, so the watch records at once, and its capture quotes the line.
line=$(ok "$ALICE" POST /api/watches "$(target edge pod-state '{"when":{"kind":"log","params":{"pattern":"served a (request|page)"}}}')" | jq -r .id)
for _ in $(seq 60); do
  noticed=$(ok "$ALICE" GET /api/captures | jq -c --arg w "$line" '[.[] | select(.watch == $w)][0]')
  [ "$noticed" != null ] && break
  sleep 1
done
[ "$(jq -r '.on + " " + (.reason | test("a log line of container web matches .*: .*served a request") | tostring)' <<<"$noticed")" = "log true" ] || fail "the capture of a watch for a log line: $noticed"
completed "$ALICE" "$(jq -r .id <<<"$noticed")"
[ "$(ok "$ALICE" GET /api/watches | jq --arg w "$line" '[.[] | select(.id == $w)] | length')" = 0 ] || fail "the log watch outlived its one capture"
# A watch for memory use: any running container uses more than 1 KiB, so the
# agent's first measurement meets it.
[ "$(status "$ALICE" POST /api/watches "$(target edge pod-state '{"when":{"kind":"memory","params":{"above":"much"}}}')")" = 400 ] || fail "a memory watch without a threshold was accepted"
used=$(ok "$ALICE" POST /api/watches "$(target edge pod-state '{"when":{"kind":"memory","params":{"above":"1Ki"}}}')" | jq -r .id)
for _ in $(seq 60); do
  noticed=$(ok "$ALICE" GET /api/captures | jq -c --arg w "$used" '[.[] | select(.watch == $w)][0]')
  [ "$noticed" != null ] && break
  sleep 1
done
[ "$(jq -r '.on + " " + (.reason | test("container web uses [0-9.]+ [KMG]iB of memory \\(above 1Ki\\)") | tostring)' <<<"$noticed")" = "memory true" ] || fail "the capture of a watch for memory use: $noticed"
completed "$ALICE" "$(jq -r .id <<<"$noticed")"
# Other things the agent measures: the demo holds more than one file open.
files=$(ok "$ALICE" POST /api/watches "$(target edge pod-state '{"when":{"kind":"open-files","params":{"above":"1"}}}')" | jq -r .id)
for _ in $(seq 60); do
  noticed=$(ok "$ALICE" GET /api/captures | jq -c --arg w "$files" '[.[] | select(.watch == $w)][0]')
  [ "$noticed" != null ] && break
  sleep 1
done
[ "$(jq -r '.reason | test("container web holds [0-9]+ files open \\(above 1\\)") | tostring' <<<"$noticed")" = true ] || fail "the capture of a watch for open files: $noticed"
completed "$ALICE" "$(jq -r .id <<<"$noticed")"
# A watch for a warning of Kubernetes about the pod, and one that is asked to record.
pod=$(edge -n shop get pods -l app=web -o jsonpath='{.items[0].metadata.name}')
warned=$(ok "$ALICE" POST /api/watches "$(target edge pod-state '{"count":2,"when":{"kind":"event","params":{"reason":"FailedMount"}}}')" | jq -r .id)
sleep 3 # the agent begins to listen
edge -n shop create -f - >/dev/null <<EOF
apiVersion: v1
kind: Event
metadata: {name: $pod.e2e, namespace: shop}
type: Warning
reason: FailedMount
message: MountVolume.SetUp failed for volume "data"
involvedObject: {kind: Pod, namespace: shop, name: $pod, uid: $(edge -n shop get pod "$pod" -o jsonpath='{.metadata.uid}')}
EOF
id=$(triggered "$warned"); completed "$ALICE" "$id"
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -r .reason)" = 'Kubernetes warns: FailedMount: MountVolume.SetUp failed for volume "data"' ] || fail "the capture of a warning: $(ok "$ALICE" GET "/api/captures/$id" | jq -r .reason)"
id=$(ok "$ALICE" POST "/api/watches/$warned/record" "{\"pod\":\"$pod\"}" | jq -r .id); completed "$ALICE" "$id"
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -r '[.on, .reason] | @csv')" = '"asked","asked for by alice"' ] || fail "a watch asked to record"
[ "$(ok "$ALICE" GET /api/watches | jq --arg w "$warned" '[.[] | select(.id == $w)] | length')" = 0 ] || fail "the watch's count was not used up"
# A watch for a Prometheus alert: Alertmanager's notification, with the hub's
# alert token, records the pod that the alert names; told again, nothing more.
ok "$ALICE" POST /api/watches "$(target edge pod-state '{"when":{"kind":"alert","params":{"name":"HighErrorRate"}}}')" >/dev/null
pod=$(edge -n shop get pods -l app=web -o jsonpath='{.items[0].metadata.name}')
firing=$(jq -cn --arg pod "$pod" '{version: "4", status: "firing", alerts: [{status: "firing", startsAt: "2026-01-01T10:00:00Z", fingerprint: "f1a2b3",
  labels: {alertname: "HighErrorRate", namespace: "shop", pod: $pod}, annotations: {summary: "5xx above 5 %"}}]}')
[ "$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ALICE" -d "$firing" "$URL/api/alerts")" = 401 ] || fail "a user's token was taken for the alert token"
[ "$(curl -sS --fail -H "Authorization: Bearer $ALERTS" -d "$firing" "$URL/api/alerts")" = '{"captures":1}' ] || fail "the alert created no capture"
[ "$(curl -sS --fail -H "Authorization: Bearer $ALERTS" -d "$firing" "$URL/api/alerts")" = '{"captures":0}' ] || fail "the alert told again created another capture"
alerted=$(ok "$ALICE" GET /api/captures | jq -c '[.[] | select(.on == "alert")][0]')
[ "$(jq -r --arg pod "$pod" '.reason + " " + (.tasks | length | tostring) + " " + (.tasks[0].pod == $pod | tostring)' <<<"$alerted")" = "alert HighErrorRate fires: 5xx above 5 % 1 true" ] || fail "the capture of an alert: $alerted"
completed "$ALICE" "$(jq -r .id <<<"$alerted")"

if [ -n "${CORE_HANDLER:-}" ]; then
  log "an approved core dump watch records the core of the crashed process (edge)"
  cores=$(ok "$ALICE" POST /api/watches "$(target edge coredump)" | jq -r .id)
  [ "$(status "$ALICE" POST "/api/watches/$cores/approve")" = 403 ] || fail "the requester approved the watch"
  ok "$ROOT" POST "/api/watches/$cores/approve" >/dev/null
  sleep 3 # the agent marks the pods for the node's core handler
  victim=$(edge -n shop get pods -l app=web -o jsonpath='{.items[1].metadata.name}')
  edge -n shop exec "$victim" -- touch /tmp/segv
  id=$(triggered "$cores"); completed "$ALICE" "$id"
  name=$(first_artifact "$ALICE" "$id")
  case "$name" in "$victim"/core.web.*) ;; *) fail "core artifact name: $name" ;; esac
  fetch "$ALICE" "$id" "$name" "$WORK/crash.core"
  [ "$(od -An -tx1 -N4 "$WORK/crash.core" | tr -d ' ')" = 7f454c46 ] || fail "the crash core is not an ELF file"
  [ "$(od -An -tu2 -j16 -N2 "$WORK/crash.core" | tr -d ' ')" = 4 ] || fail "the crash core is not a core (ET_CORE)"
  # The handler kept the program's files while the crashed process was
  # still there: the core is described with them, though the container's
  # next instance may not run yet.
  fetch "$ALICE" "$id" "$name.files.tar" "$WORK/crash.core.files.tar"
  # Listed first: grep leaves at its first match, and a tar that is still writing then fails the pipe.
  listed=$(tar -tf "$WORK/crash.core.files.tar")
  grep -qx 'bin/busybox\|bin/sh' <<<"$listed" || fail "the program files of a crash core: $(head -5 <<<"$listed")"
  # Its description names the signal that the process died of.
  fetch "$ALICE" "$id" "$name.analysis.json" "$WORK/crash.core.analysis.json"
  jq -e '(.stopped | contains("SIGSEGV")) and (.threads | length > 0) and .symbols and .executable == "/bin/sh"' "$WORK/crash.core.analysis.json" >/dev/null || fail "description of the crash core: $(cat "$WORK/crash.core.analysis.json")"
  [ -z "$(sudo find "$SPOOL/cores" "$SPOOL/taken" -type f)" ] || fail "an uploaded core stayed on the node"
  # The core of a process outside of watched pods, here one of the node
  # itself, goes to the handler that the machine had before, with the
  # values that its pattern asks the kernel for: the signal and the program.
  docker exec "$EDGE-control-plane" sh -c 'kill -SEGV $$' || true
  for _ in $(seq 20); do sudo test -s "$SPOOL/passed-on" && break; sleep 0.5; done
  read -r signal program size < <(sudo cat "$SPOOL/passed-on") || true
  [ "${signal:-}" = 11 ] && [ "$program" = sh ] && [ "$size" -gt 1000 ] || fail "the core of an unwatched process was not passed on to the machine's handler: ${signal:-} ${program:-} ${size:-}; $(sudo cat "$SPOOL/last-core" 2>&1)"
fi

mcp=$(ok "$ALICE" POST /mcp '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_workloads","arguments":{"cluster":"local","namespace":"shop"}}}')
[ "$(jq -r '.result.content[0].text' <<<"$mcp")" = '["Deployment/web"]' ] || fail "MCP list_workloads: $mcp"
audit=$(ok "$ROOT" GET '/api/audit?limit=500' | jq -r '[.[].action] | unique | join(" ")')
for action in capture.request capture.approve capture.deny capture.stop artifact.download watch.create capture.trigger watch.delete; do
  case " $audit " in *" $action "*) ;; *) fail "audit lacks $action" ;; esac
done

log "a shared capture is there for a colleague who may capture in its namespace, and for nobody else"
# Bob is in the group that may exec into the namespace's pods, as Alice is; Mallory is not.
id=$(ok "$ALICE" GET /api/captures | jq -r '[.[] | select(.state == "Completed" and (.artifacts | length > 0) and .requester == "alice")][0].id')
file=$(ok "$ALICE" GET "/api/captures/$id" | jq -r '.artifacts[0].name')
[ "$(status "$BOB" GET "/api/captures/$id")" = 404 ] || fail "a colleague read a capture that is not shared"
[ "$(ok "$ALICE" POST "/api/captures/$id/share" '{"shared":true}' | jq -r .shared)" = true ] || fail "sharing a capture"
[ "$(ok "$BOB" GET "/api/captures/$id" | jq -r .requester)" = alice ] || fail "a colleague does not see the shared capture"
ok "$BOB" GET /api/captures | jq -e --arg id "$id" 'any(.[]; .id == $id)' >/dev/null || fail "the shared capture is not in the colleague's list"
[ "$(status "$BOB" GET "/api/captures/$id/artifacts/$file")" = 200 ] || fail "a colleague does not download a shared file"
[ "$(status "$MALLORY" GET "/api/captures/$id")" = 404 ] || fail "someone without the namespace's exec right read a shared capture"
[ "$(status "$BOB" DELETE "/api/captures/$id")" = 403 ] || fail "a colleague deleted a shared capture"
ok "$ALICE" POST "/api/captures/$id/share" '{"shared":false}' >/dev/null
[ "$(status "$BOB" GET "/api/captures/$id")" = 404 ] || fail "the capture is still shared"

# What all of the above recorded is looked at as a person would: the console's
# pages and one file per viewer in a headless browser, at a desk's and at a
# phone's width. Scripts that fail, files that do not open and pages that run
# out of the screen fail the run. Without a browser on the machine it is left out.
log "the console and every viewer in a browser, wide and narrow"
# The demo's heap profile is a word, not a profile: the viewer has to say so.
browsed=0; UNREADABLE=heap.pprof timeout 900 node test/e2e/browser.mjs "$URL" "$ALICE" "$ROOT" || browsed=$?
case $browsed in
  0) ;;
  78) [ -z "${REQUIRE_BROWSER:-}" ] || fail "no Chromium or Chrome is installed, and REQUIRE_BROWSER asks for the pages to be looked at"
      log "left out: no Chromium or Chrome is installed here" ;;
  *) fail "the pages in a browser" ;;
esac

log "PASS"
ls -l "$WORK"/pod.json "$WORK"/web.log "$WORK"/capture.pcap "$WORK"/web.strace "$WORK"/core.web "$WORK"/crash.pcap "$WORK"/crash.log
