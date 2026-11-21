package agent

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"asservat.local/asservat/internal/api"
)

// fakeProcess adds a process of a container to a fake /proc.
func fakeProcess(proc string, pid, ppid, started int, name, program, cgroup string, rssKB int) {
	dir := filepath.Join(proc, fmt.Sprint(pid))
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::"+cgroup+"\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "stat"), fmt.Appendf(nil, "%d (%s) S %d %s %d 0", pid, name, ppid, strings.Repeat("0 ", 17), started), 0o644)
	os.WriteFile(filepath.Join(dir, "status"), fmt.Appendf(nil, "Name:\t%s\nNSpid:\t%d\t%d\nVmRSS:\t%8d kB\nThreads:\t4\n", name, pid, pid-1000, rssKB), 0o644)
	os.Symlink(program, filepath.Join(dir, "exe"))
}

func TestProcessesAndTargets(t *testing.T) {
	proc := t.TempDir()
	const id = "0123abcd"
	scope := "/kubelet.slice/cri-containerd-" + id + ".scope"
	fakeProcess(proc, 900, 1, 50, "containerd-shim", "/usr/bin/containerd-shim", "/system.slice/containerd.service", 100)
	fakeProcess(proc, 1001, 900, 100, "gunicorn", "/usr/local/bin/python3.12", scope, 30<<10)
	fakeProcess(proc, 1007, 1001, 110, "gunicorn", "/usr/local/bin/python3.12", scope, 200<<10)
	fakeProcess(proc, 1008, 1001, 111, "gunicorn", "/usr/local/bin/python3.12", scope, 210<<10)
	fakeProcess(proc, 1020, 1001, 120, "nginx", "/usr/sbin/nginx (deleted)", scope, 5<<10)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-1", Namespace: "payments"},
		Spec: corev1.PodSpec{NodeName: "node-a", Containers: []corev1.Container{{Name: "app"}}},
		Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{{Name: "app", ContainerID: "containerd://" + id,
			State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{}}}}}}
	elsewhere := pod.DeepCopy()
	elsewhere.Name, elsewhere.Spec.NodeName = "api-2", "node-b"
	a := &Agent{Node: "node-a", Proc: proc, Kube: fake.NewClientset(pod, elsewhere)}

	got, err := a.processes(t.Context(), api.Query{Namespace: "payments", Pods: []string{"api-1", "api-2"}})
	if err != nil || len(got) != 4 {
		t.Fatal("processes", got, err)
	}
	slices.SortFunc(got, func(x, y api.Process) int { return x.PID - y.PID })
	want := api.Process{Pod: "api-1", Container: "app", PID: 1, Executable: "/usr/local/bin/python3.12", Name: "gunicorn", Main: true, ResidentBytes: 30 << 20, Threads: 4}
	if got[0] != want || got[1].Main || got[3].Executable != "/usr/sbin/nginx" {
		t.Fatalf("processes %+v", got)
	}

	// Without a program the main process is the target, with one every
	// process that runs it.
	if pids, container, err := a.targets(pod, "", ""); err != nil || container != "app" || !slices.Equal(pids, []int{1001}) {
		t.Fatal("default target", pids, container, err)
	}
	pids, _, err := a.targets(pod, "app", "/usr/local/bin/python3.12")
	slices.Sort(pids)
	if err != nil || !slices.Equal(pids, []int{1001, 1007, 1008}) {
		t.Fatal("targets of a program", pids, err)
	}
	if _, _, err := a.targets(pod, "app", "/usr/bin/ruby"); err == nil {
		t.Fatal("found a program that does not run")
	}
}

func TestFlowTable(t *testing.T) {
	pod, db, client1, client2, dns := netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("10.96.0.12"), netip.MustParseAddr("10.0.1.7"), netip.MustParseAddr("10.0.1.8"), netip.MustParseAddr("10.96.0.10")
	loopback := netip.MustParseAddr("127.0.0.1")
	table := newFlowTable(map[uint16]bool{8080: true})
	table.local[pod] = true
	packet := func(protocol string, src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16, opens bool) {
		table.add(packetInfo{protocol: protocol, src: src, dst: dst, srcPort: srcPort, dstPort: dstPort, opens: opens}, 100)
	}
	// Two clients of the pod's listening port, replies included.
	packet("tcp", client1, 40001, pod, 8080, true)
	packet("tcp", pod, 8080, client1, 40001, false)
	packet("tcp", client2, 40002, pod, 8080, false)
	// The pod is a client of a database on a higher port than its own
	// ephemeral one would suggest: the opening packet decides.
	packet("tcp", pod, 3000, db, 5432, true)
	packet("tcp", db, 5432, pod, 3000, false)
	// DNS over UDP: the lower port serves.
	packet("udp", pod, 51000, dns, 53, false)
	packet("udp", dns, 53, pod, 51000, false)
	// A health check over loopback, and traffic that is not the pod's.
	packet("tcp", loopback, 45000, loopback, 8080, false)
	packet("udp", client1, 5353, netip.MustParseAddr("224.0.0.251"), 5353, false)
	table.add(packetInfo{}, 100) // not TCP or UDP

	got := map[string]api.Flow{}
	for _, f := range table.flows() {
		got[fmt.Sprint(f.Direction, " ", f.Protocol, " ", f.Port, " ", f.Peer)] = f
	}
	if len(got) != 4 {
		t.Fatalf("flows %+v", got)
	}
	if f := got["in tcp 8080 "]; f.Packets != 3 || f.Bytes != 300 || !slices.Equal(f.PeerList, []string{"10.0.1.7", "10.0.1.8"}) {
		t.Fatalf("incoming %+v", f)
	}
	if f := got["out tcp 5432 10.96.0.12"]; f.Packets != 2 {
		t.Fatalf("outgoing %+v", got)
	}
	if f := got["out udp 53 10.96.0.10"]; f.Packets != 2 {
		t.Fatalf("dns %+v", got)
	}
	if f := got["local tcp 8080 "]; f.Packets != 1 {
		t.Fatalf("loopback %+v", got)
	}
}

func TestListeningPorts(t *testing.T) {
	proc := t.TempDir()
	os.MkdirAll(filepath.Join(proc, "42", "net"), 0o755)
	os.WriteFile(filepath.Join(proc, "42", "net", "tcp"), []byte("  sl  local_address rem_address   st tx_queue\n   0: 00000000:1F90 00000000:0000 0A 00000000\n   1: 0500000A:9C41 0C00600A:1538 01 00000000\n"), 0o644)
	os.WriteFile(filepath.Join(proc, "42", "net", "tcp6"), []byte("   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 0\n"), 0o644)
	got := listeningPorts(proc, 42)
	if len(got) != 2 || !got[8080] || !got[443] {
		t.Fatal("listening ports", got)
	}
}

func TestPeers(t *testing.T) {
	podWithIP := func(namespace, name, ip string, hostNetwork bool) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}, Spec: corev1.PodSpec{HostNetwork: hostNetwork}, Status: corev1.PodStatus{PodIP: ip}}
	}
	a := &Agent{Kube: fake.NewClientset(
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "payments"}, Spec: corev1.ServiceSpec{ClusterIPs: []string{"10.96.0.12"}}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "kube-dns", Namespace: "kube-system"}, Spec: corev1.ServiceSpec{ClusterIPs: []string{"10.96.0.10"}}},
		podWithIP("payments", "cache-0", "10.0.1.7", false), podWithIP("billing", "ledger-0", "10.0.1.8", false), podWithIP("kube-system", "kube-proxy", "192.168.0.2", true))}
	ips := []string{"10.96.0.12", "10.96.0.10", "10.0.1.7", "10.0.1.8", "192.168.0.2", "8.8.8.8"}
	// A user learns the names in the namespace they may capture in.
	got, err := a.peers(t.Context(), api.Query{Namespace: "payments", IPs: ips})
	if err != nil || len(got) != 2 || got["10.96.0.12"] != "Service db" || got["10.0.1.7"] != "Pod cache-0" {
		t.Fatal("peers of the namespace", got, err)
	}
	got, err = a.peers(t.Context(), api.Query{Namespace: "payments", IPs: ips, All: true})
	if err != nil || len(got) != 4 || got["10.96.0.10"] != "Service kube-system/kube-dns" || got["10.0.1.8"] != "Pod billing/ledger-0" {
		t.Fatal("peers of the cluster", got, err)
	}
}
