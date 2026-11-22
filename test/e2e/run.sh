#!/usr/bin/env bash
# End-to-end test with two kind clusters: "hub" runs the hub and its own node
# agents, "edge" runs only agents that join the hub. It records every kind of
# evidence from a demo workload, including a core dump that an administrator
# approves and the captures of a crash watch, and checks the downloaded files.
#
#   test/e2e/run.sh          build the image, create the clusters, test, delete
#   KEEP=1 test/e2e/run.sh   keep the clusters for inspection
#   CORE_HANDLER=1 test/e2e/run.sh   also record the core of a crashed process
#
# CORE_HANDLER changes kernel.core_pattern of the machine that runs kind,
# because kind nodes share its kernel. Use it only on a disposable machine
# such as a CI runner; it needs sudo to create the spool directory.
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
  docker build -q -t "$IMAGE" .
fi
rm -f "$WORK/image.tar"
docker save "$IMAGE" -o "$WORK/image.tar"

# The kernel runs the core handler from the machine's own file system, so
# the spool is one directory at the same path there, in the kind node and in
# the agent.
SPOOL=/var/lib/asservat-e2e
if [ -n "${CORE_HANDLER:-}" ]; then
  sudo mkdir -p "$SPOOL"
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
ALICE=alice-token-0123456789abcdef0123456789 ROOT=root-token-0123456789abcdef0123456789ab MALLORY=mallory-token-0123456789abcdef012345
hub create namespace asservat --dry-run=client -o yaml | hub apply -f - >/dev/null
helm --kube-context "kind-$HUB" upgrade --install asservat charts/asservat -n asservat --wait --timeout 5m \
  --set image.repository=localhost/asservat,image.tag=e2e,image.pullPolicy=Never \
  --set hub.service.type=NodePort,hub.service.nodePort=30080 \
  --set hub.users[0].name=alice,hub.users[0].token=$ALICE,hub.users[0].groups[0]=devs \
  --set hub.users[1].name=root,hub.users[1].token=$ROOT,hub.users[1].groups[0]=asservat-admins \
  --set hub.users[2].name=mallory,hub.users[2].token=$MALLORY \
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
[ "$(status "$MALLORY" POST "/api/views/$view/status" '{}')" = 404 ] || fail "mallory asked alice's view"
kill $viewer
# The other viewers read in the browser; the hub names them and serves them.
ok "$ALICE" GET /api/captures | jq -e '[.[].artifacts[].viewer] | contains(["kube", "log", "pcap"])' >/dev/null || fail "viewers of the files so far"
for v in kube log pcap pprof stacks strace; do curl -sS --fail -o /dev/null "$URL/view/$v.js" "$URL/view/$v.css" || fail "viewer $v is not served"; done
grep -q '/view/common.js' <<<"$(curl -sS --fail "$URL/view")" || fail "viewer page"

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
[ "$(jq -c '[.artifacts[].name | split("/")[1]] | unique' <<<"$bundle")" = '["capture.pcap","core.web","core.web.analysis.json","events.json","pod.json","web.log","web.strace"]' ] || fail "files of the recordings: $(jq -c '[.artifacts[].name]' <<<"$bundle")"
[ "$(jq -c '[(.artifacts | length), ([.tasks[].message // ""] | unique)]' <<<"$bundle")" = '[14,[""]]' ] || fail "recordings per pod: $(jq -c .tasks <<<"$bundle")"

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
# as the CPU profile, a word as the heap profile.
for p in $(edge -n shop get pods -l app=web -o name); do
  edge -n shop exec -i "$p" -- sh -c 'cat >/tmp/www/debug/pprof/profile' <test/e2e/synthetic-cpu.pprof
done
# The pod's ports are asked for the known profile endpoints; the found ones are fetched at once.
found=$(ok "$ALICE" POST '/api/clusters/edge/namespaces/shop/profiles?workload=Deployment/web')
[ "$(jq -c '[.ports, [.profiles[] | select(.endpoint == "go-cpu" or .endpoint == "go-heap") | [.port, .endpoint, .timed, .sensitive]]]' <<<"$found")" = '[[8080],[[8080,"go-cpu",true,false],[8080,"go-heap",false,false]]]' ] || fail "profile endpoints: $found"
id=$(capture "$ALICE" "$(target edge pprof '{"durationSeconds":1,"params":{"endpoints":"8080/go-cpu,8080/go-heap"}}')"); completed "$ALICE" "$id"
pod=$(ok "$ALICE" GET "/api/captures/$id" | jq -r '.tasks[0].pod')
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -r '[.sensitive, (.artifacts | length)] | @csv')" = 'false,4' ] || fail "profiles of two endpoints on two pods"
fetch "$ALICE" "$id" "$pod/cpu.pprof" "$WORK/cpu.pprof"; fetch "$ALICE" "$id" "$pod/heap.pprof" "$WORK/heap.pprof"
cmp -s "$WORK/cpu.pprof" test/e2e/synthetic-cpu.pprof && [ "$(cat "$WORK/heap.pprof")" = heap-profile ] || fail "profile contents"
# A profile in pprof's format opens in pprof's own web interface, served by the hub for the view.
: >"$WORK/view" # a kept work directory holds the last run's view
curl -sSN -H "Authorization: Bearer $ALICE" "$URL/api/captures/$id/views/$pod/cpu.pprof" >"$WORK/view" &
viewer=$!
for _ in $(seq 100); do grep -q '^data: ' "$WORK/view" && break; sleep 0.1; done
view=$(sed -n 's/^data: //p' "$WORK/view")
grep -q 'shop.priceOf' <<<"$(curl -sS --fail -H "Authorization: Bearer $ALICE" "$URL/api/views/$view/pages/top")" || fail "pprof's top page"
grep -q '<svg' <<<"$(curl -sS --fail -H "Authorization: Bearer $ALICE" "$URL/api/views/$view/pages/graph")" || fail "pprof's graph page, drawn by dot"
kill $viewer
[ "$(status "$ALICE" GET "/api/captures/$id/views/$pod/heap.pprof")" = 422 ] || fail "a file that is no profile opened in pprof"
# An endpoint that Asservat does not know can return anything: it needs approval.
id=$(capture "$ALICE" "$(target edge pprof '{"params":{"port":"8080","path":"/index.html"}}')")
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -r .state)" = PendingApproval ] || fail "an unknown endpoint did not wait for approval"
ok "$ROOT" POST "/api/captures/$id/approve" >/dev/null
completed "$ALICE" "$id"
fetch "$ALICE" "$id" "$(first_artifact "$ALICE" "$id")" "$WORK/profile.out"
[ "$(cat "$WORK/profile.out")" = hello ] || fail "content of the unknown endpoint"
[ "$(status "$ALICE" POST /api/captures "$(target edge pprof)")" = 400 ] || fail "a profile without an endpoint was accepted"

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
pod=$(ok "$ALICE" GET "/api/captures/$id" | jq -r '.tasks[0].pod')
fetch "$ALICE" "$id" "$pod/core.web.analysis.json" "$WORK/core.web.analysis.json"
jq -e '.executable == "/bin/sh" and .symbols and (.commandLine | startswith("/bin/sh -c mkdir")) and .stopped == "" and (.threads | length == 1) and (.threads[0].frames | length > 1) and (.threads[0].frames[0].registers | length > 10) and ([.threads[0].frames[].function] | index("wait4") != null) and (.modules | length > 0) and (.mappings | length > 5)' "$WORK/core.web.analysis.json" >/dev/null || fail "description of the core: $(cat "$WORK/core.web.analysis.json")"
[ "$(ok "$ALICE" GET "/api/captures/$id" | jq -c '[.artifacts[].viewer] | unique')" = '["core"]' ] || fail "viewer of cores"
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
sleep 5 # the agents begin to buffer packets
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
  # Its description names the signal that the process died of.
  fetch "$ALICE" "$id" "$name.analysis.json" "$WORK/crash.core.analysis.json"
  jq -e '(.stopped | contains("SIGSEGV")) and (.threads | length > 0)' "$WORK/crash.core.analysis.json" >/dev/null || fail "description of the crash core: $(cat "$WORK/crash.core.analysis.json")"
  [ -z "$(sudo find "$SPOOL/cores" "$SPOOL/taken" -type f)" ] || fail "an uploaded core stayed on the node"
fi

mcp=$(ok "$ALICE" POST /mcp '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_workloads","arguments":{"cluster":"local","namespace":"shop"}}}')
[ "$(jq -r '.result.content[0].text' <<<"$mcp")" = '["Deployment/web"]' ] || fail "MCP list_workloads: $mcp"
audit=$(ok "$ROOT" GET '/api/audit?limit=500' | jq -r '[.[].action] | unique | join(" ")')
for action in capture.request capture.approve capture.deny capture.stop artifact.download watch.create capture.trigger watch.delete; do
  case " $audit " in *" $action "*) ;; *) fail "audit lacks $action" ;; esac
done

log "PASS"
ls -l "$WORK"/pod.json "$WORK"/web.log "$WORK"/capture.pcap "$WORK"/web.strace "$WORK"/core.web "$WORK"/crash.pcap "$WORK"/crash.log
