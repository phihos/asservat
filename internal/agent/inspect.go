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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"asservat.local/asservat/internal/api"
)

// Inspection answers what a user would otherwise have to know before a
// capture: which processes run in the pods, and whom the pods talk to. It
// reads the node's /proc and the headers of a few seconds of packets, and
// stores nothing.

// nodePods returns the named pods that run on this node, and the names of
// those that do not, or no longer.
func (a *Agent) nodePods(ctx context.Context, namespace string, names []string) (pods []*corev1.Pod, skipped []string) {
	for _, name := range names {
		pod, err := a.Kube.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil || pod.Spec.NodeName != a.Node {
			if err != nil && !apierrors.IsNotFound(err) {
				slog.Warn("inspection: pod not read", "pod", name, "error", err)
			}
			skipped = append(skipped, name)
			continue
		}
		pods = append(pods, pod)
	}
	return pods, skipped
}

// processes lists the processes of the pods' running containers, and the
// pods it could not look at.
func (a *Agent) processes(ctx context.Context, q api.Query) ([]api.Process, []string) {
	pods, skipped := a.nodePods(ctx, q.Namespace, q.Pods)
	out := []api.Process{}
	for _, pod := range pods {
		for _, s := range pod.Status.ContainerStatuses {
			_, id, ok := strings.Cut(s.ContainerID, "://")
			if !ok || s.State.Running == nil {
				continue
			}
			pids, main, err := containerPIDs(a.Proc, id)
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
	pid, err := a.podPID(pod)
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
	cmd := exec.CommandContext(ctx, "nsenter", "-t", strconv.Itoa(pid), "-n", "tcpdump", "-Z", "root", "-i", "any", "-U", "-w", "-")
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
