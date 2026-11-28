package agent

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"asservat.local/asservat/internal/api"
)

// Inspection answers what a user would otherwise have to know before a
// capture: which processes run in the pods, and whom the pods talk to. It
// reads the node's /proc and the headers of a few seconds of packets, and
// stores nothing.

// nodePods returns the named pods that run on this node, and the names of
// those that do not, or no longer. It asks the API server once, for the
// node's pods in the namespace: asked for each pod, one after another, the
// 150 pods of a workload on a node took 7 seconds.
func (a *Agent) nodePods(ctx context.Context, namespace string, names []string) (pods []*corev1.Pod, skipped []string) {
	here, err := a.Kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{FieldSelector: "spec.nodeName=" + a.Node})
	if err != nil {
		slog.Warn("inspection: pods not read", "namespace", namespace, "error", err)
		return nil, names
	}
	byName := map[string]*corev1.Pod{}
	for i := range here.Items {
		// Asked of the pod too: not every server of pods filters by node.
		if pod := &here.Items[i]; pod.Spec.NodeName == a.Node {
			byName[pod.Name] = pod
		}
	}
	for _, name := range names {
		if pod := byName[name]; pod != nil {
			pods = append(pods, pod)
		} else {
			skipped = append(skipped, name)
		}
	}
	return pods, skipped
}

// processes lists the processes of the pods' running containers, and the
// pods it could not look at.
func (a *Agent) processes(ctx context.Context, q api.Query) ([]api.Process, []string) {
	pods, skipped := a.nodePods(ctx, q.Namespace, q.Pods)
	out := []api.Process{}
	// One reading of the node's processes for all the containers.
	read, err := readCgroups(a.Proc)
	if err != nil {
		slog.Warn("inspection: processes not read", "error", err)
		for _, pod := range pods {
			skipped = append(skipped, pod.Name)
		}
		return out, skipped
	}
	for _, pod := range pods {
		for _, s := range pod.Status.ContainerStatuses {
			_, id, ok := strings.Cut(s.ContainerID, "://")
			if !ok || s.State.Running == nil {
				continue
			}
			pids, main, _, err := read.processesOf(id, ownCgroup(a.Proc, a.own(pod)))
			if err != nil {
				continue // the container ended meanwhile
			}
			for _, pid := range pids {
				p := api.Process{Pod: pod.Name, Container: s.Name, PID: pid, Executable: executable(a.Proc, pid), Main: pid == main}
				status, err := os.ReadFile(filepath.Join(a.Proc, strconv.Itoa(pid), "status"))
				if err != nil || p.Executable == "" {
					continue // the process ended meanwhile, or is a kernel thread
				}
				for _, line := range strings.Split(string(status), "\n") {
					key, value, _ := strings.Cut(line, ":")
					fields := strings.Fields(value)
					if len(fields) == 0 {
						continue
					}
					switch key {
					case "Name":
						p.Name = strings.TrimSpace(value)
					case "VmRSS": // "1234 kB"
						kb, _ := strconv.ParseInt(fields[0], 10, 64)
						p.ResidentBytes = kb << 10
					case "Threads":
						p.Threads, _ = strconv.Atoi(fields[0])
					case "NSpid": // the last one is the ID in the innermost namespace
						p.PID, _ = strconv.Atoi(fields[len(fields)-1])
					}
				}
				out = append(out, p)
			}
		}
	}
	return out, skipped
}

// traffic records the packet headers of the pods for some seconds and
// returns each pod's flows, and the pods it could not record.
func (a *Agent) traffic(ctx context.Context, q api.Query) ([]api.Flow, []string) {
	pods, skipped := a.nodePods(ctx, q.Namespace, q.Pods)
	var mu sync.Mutex
	var wg sync.WaitGroup
	out := []api.Flow{}
	for _, pod := range pods {
		wg.Go(func() {
			flows, err := a.podTraffic(ctx, pod, time.Duration(q.Seconds)*time.Second)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				// For example a pod whose containers restart just now.
				slog.Warn("traffic sample", "pod", pod.Name, "error", err)
				skipped = append(skipped, pod.Name)
				return
			}
			out = append(out, flows...)
		})
	}
	wg.Wait()
	return out, skipped
}

func (a *Agent) podTraffic(ctx context.Context, pod *corev1.Pod, duration time.Duration) ([]api.Flow, error) {
	pid, err := a.podPID(pod, nil)
	if err != nil {
		return nil, err
	}
	table := newFlowTable(listeningPorts(a.Proc, pid))
	for _, ip := range pod.Status.PodIPs {
		if addr, err := netip.ParseAddr(ip.IP); err == nil {
			table.local[addr] = true
		}
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nsenter", tcpdumpArgs(pid, "", false, false)...)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGINT) }
	cmd.WaitDelay = 5 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	packets, err := newPacketReader(stdout)
	for err == nil && packets != nil {
		var record, packet []byte
		if record, packet, err = packets.next(); record == nil {
			break
		}
		// The record holds the packet's length on the wire.
		table.add(dissect(packets.linkType, packet), int64(packets.order.Uint32(record[12:])))
	}
	if waitErr := cmd.Wait(); err == nil && waitErr != nil && ctx.Err() == nil {
		err = fmt.Errorf("tcpdump: %w: %s", waitErr, tail(stderr.Bytes()))
	}
	return table.flows(), err
}

// profiles looks for the profile endpoints that the first of the pods
// serves: it asks every TCP port that the pod listens on for the index or
// information page of each known family. That starts no profiling. It also
// looks whether the pod's containers run a JVM that can be asked for its
// diagnostics, and notes those that cannot.
func (a *Agent) profiles(ctx context.Context, q api.Query) (found []api.ProfileTarget, ports []int, notes, skipped []string) {
	pods, skipped := a.nodePods(ctx, q.Namespace, q.Pods)
	if len(pods) == 0 {
		return nil, nil, nil, skipped
	}
	pid, err := a.podPID(pods[0], nil)
	if err != nil {
		return nil, nil, nil, append(skipped, pods[0].Name)
	}
	diagnostics, notes := a.jvmDiagnostics(pods[0])
	for port := range listeningPorts(a.Proc, pid) {
		ports = append(ports, int(port))
	}
	slices.Sort(ports)
	return append(probeProfiles(ports, func(port int, path string) string {
		// Two seconds: a port that speaks no HTTP may never answer.
		out, _ := exec.CommandContext(ctx, "nsenter", "-t", strconv.Itoa(pid), "-n", "curl", "-sS", "--fail", "-m", "2", "--max-filesize", "1048576",
			"http://127.0.0.1:"+strconv.Itoa(port)+path).Output()
		return string(out)
	}), diagnostics...), ports, notes, skipped
}

// probeProfiles asks every port for the probe page of every family, all at
// once, and returns the endpoints of the families that answered, in the
// order of the ports and the catalog.
func probeProfiles(ports []int, get func(port int, path string) string) []api.ProfileTarget {
	answers := make([][]string, len(ports))
	// Each probe is a process on the node: at most 32 at a time, so that a
	// pod with hundreds of ports cannot exhaust the agent's process limit.
	running := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for i, port := range ports {
		answers[i] = make([]string, len(api.ProfileFamilies))
		for j, family := range api.ProfileFamilies {
			wg.Go(func() {
				running <- struct{}{}
				defer func() { <-running }()
				answers[i][j] = get(port, family.Probe)
			})
		}
	}
	wg.Wait()
	var found []api.ProfileTarget
	for i, port := range ports {
		for j, family := range api.ProfileFamilies {
			body := answers[i][j]
			if !strings.Contains(body, family.Marker) {
				continue
			}
			for _, e := range family.Endpoints {
				// A listed endpoint appears as the end of a link in the page.
				path, _, _ := strings.Cut(e.Path, "?")
				if !family.Listed || strings.Contains(body, path+`"`) {
					found = append(found, api.ProfileTarget{Port: port, ProfileEndpoint: e})
				}
			}
		}
	}
	return found
}

// listeningPorts reads the TCP ports that the network namespace of a
// process accepts connections on.
func listeningPorts(proc string, pid int) map[uint16]bool {
	ports := map[uint16]bool{}
	for _, file := range []string{"tcp", "tcp6"} {
		b, _ := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), "net", file))
		for _, line := range strings.Split(string(b), "\n") {
			// "sl local_address rem_address st ...": "0: 00000000:1F90 00000000:0000 0A"
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[3] != "0A" { // 0A is LISTEN
				continue
			}
			_, port, _ := strings.Cut(fields[1], ":")
			if n, err := strconv.ParseUint(port, 16, 16); err == nil {
				ports[uint16(n)] = true
			}
		}
	}
	return ports
}

// flowTable sorts the packets of one pod into flows.
type flowTable struct {
	local     map[netip.Addr]bool // the pod's own addresses
	listening map[uint16]bool
	byKey     map[flowKey]*api.Flow
	peers     map[flowKey]map[string]bool
	// served remembers for each connection whether the pod serves it, so
	// that all of its packets land in one flow.
	served map[connection]bool
}

type connection struct {
	protocol          string
	peer              netip.Addr
	podPort, peerPort uint16
}

type flowKey struct {
	direction, protocol string
	port                uint16
	peer                netip.Addr
}

func newFlowTable(listening map[uint16]bool) *flowTable {
	return &flowTable{local: map[netip.Addr]bool{}, listening: listening, byKey: map[flowKey]*api.Flow{}, peers: map[flowKey]map[string]bool{}, served: map[connection]bool{}}
}

func (t *flowTable) add(p packetInfo, bytes int64) {
	if p.protocol == "" {
		return
	}
	src, dst := p.src.Unmap(), p.dst.Unmap()
	fromPod, toPod := src.IsLoopback() || t.local[src], dst.IsLoopback() || t.local[dst]
	// Which side serves: the one that a connection is opened to, a port the
	// pod listens on, otherwise the lower port.
	podServes := func(peer netip.Addr, podPort, peerPort uint16) bool {
		c := connection{p.protocol, peer, podPort, peerPort}
		serves, known := t.served[c]
		switch {
		case p.opens:
			serves = toPod
		case known:
		case p.protocol == "tcp" && t.listening[podPort]:
			serves = true
		default:
			serves = podPort < peerPort
		}
		t.served[c] = serves
		return serves
	}
	var key flowKey
	var peer netip.Addr
	switch {
	case fromPod && toPod:
		key = flowKey{api.FlowLocal, p.protocol, min(p.srcPort, p.dstPort), netip.Addr{}}
		if p.opens || t.listening[p.dstPort] {
			key.port = p.dstPort
		} else if t.listening[p.srcPort] {
			key.port = p.srcPort
		}
	case fromPod:
		if peer = dst; podServes(peer, p.srcPort, p.dstPort) {
			key = flowKey{api.FlowIn, p.protocol, p.srcPort, netip.Addr{}}
		} else {
			key = flowKey{api.FlowOut, p.protocol, p.dstPort, peer}
		}
	case toPod:
		if peer = src; podServes(peer, p.dstPort, p.srcPort) {
			key = flowKey{api.FlowIn, p.protocol, p.dstPort, netip.Addr{}}
		} else {
			key = flowKey{api.FlowOut, p.protocol, p.srcPort, peer}
		}
	default:
		return // not the pod's own traffic, such as broadcasts
	}
	f := t.byKey[key]
	if f == nil {
		f = &api.Flow{Direction: key.direction, Protocol: key.protocol, Port: int(key.port), Pods: 1}
		if key.direction == api.FlowOut {
			f.Peer = peer.String()
		}
		t.byKey[key], t.peers[key] = f, map[string]bool{}
	}
	f.Packets++
	f.Bytes += bytes
	if key.direction == api.FlowIn {
		t.peers[key][peer.String()] = true
	}
}

func (t *flowTable) flows() []api.Flow {
	out := []api.Flow{}
	for key, f := range t.byKey {
		for peer := range t.peers[key] {
			f.PeerList = append(f.PeerList, peer)
		}
		slices.Sort(f.PeerList)
		out = append(out, *f)
	}
	return out
}

// peers names what IP addresses belong to: Services and pods of the
// namespace, or of every namespace with All.
func (a *Agent) peers(ctx context.Context, q api.Query) (map[string]string, error) {
	namespace := q.Namespace
	if q.All {
		namespace = metav1.NamespaceAll
	}
	name := func(kind, ns, name string) string {
		if ns != q.Namespace {
			name = ns + "/" + name
		}
		return kind + " " + name
	}
	names := map[string]string{}
	services, err := a.Kube.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, s := range services.Items {
		for _, ip := range s.Spec.ClusterIPs {
			if slices.Contains(q.IPs, ip) {
				names[ip] = name("Service", s.Namespace, s.Name)
			}
		}
	}
	for _, ip := range q.IPs {
		if names[ip] != "" {
			continue
		}
		pods, err := a.Kube.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{FieldSelector: "status.podIP=" + ip})
		if err != nil {
			return nil, err
		}
		for _, p := range pods.Items {
			// Pods on the host network share their node's address.
			if p.Status.PodIP == ip && !p.Spec.HostNetwork {
				names[ip] = name("Pod", p.Namespace, p.Name)
			}
		}
	}
	return names, nil
}
