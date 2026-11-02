package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ADR-283 manual-peers focus: one finite manual packet-header recording of
// the target Pod restricted to a Kubernetes peer. The installed journey's
// ordinary traffic reaches the target through the API server's Pod proxy
// (a node address outside the target namespace), and Kubernetes peers must
// name the target's own namespace. The focus therefore runs one synthetic
// client Pod in the target namespace that exchanges traffic with the target
// and selects it with a frozen resourceRef Pod peer. The proxy traffic keeps
// running in parallel, so the recording proves the peer filter excludes it.
const (
	manualPeersClient = "peer-client"
	manualPeersPort   = 8080
)

// manualPeersArguments is the public request: the builtin network profile
// (header-only packets) with a frozen resourceRef Pod peer on TCP 8080.
func manualPeersArguments(cluster, namespace, workload string) map[string]any {
	return map[string]any{
		"target_ref":                  map[string]string{"cluster_id": cluster, "namespace": namespace, "kind": "Deployment", "name": workload},
		"requested_retention_seconds": 600,
		"profile_composition": map[string]any{
			"components": []any{map[string]any{
				"id":         "network",
				"profileRef": map[string]string{"catalog": "builtin", "name": "network-connections", "version": "v1"},
				"overrides": []any{
					map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp port 8080"},
					map[string]any{"actionID": "sample", "field": "packetPeers", "value": map[string]any{
						"entries":      []any{map[string]any{"resourceRef": map[string]any{"kind": "Pod", "namespace": namespace, "name": manualPeersClient}}},
						"protocol":     "tcp",
						"ports":        []int{manualPeersPort},
						"resolution":   "frozen",
						"maxEndpoints": 4,
						"maxStaleness": "5s",
					}},
					map[string]any{"actionID": "sample", "field": "packetAfter", "value": "2s"},
					map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "10s"},
				},
			}},
			"maxTotalBytes": 16 << 20,
			"maxDuration":   "10s",
		},
	}
}

// createManualPeersClient starts the synthetic client Pod in the target
// namespace from the target Deployment's own restricted Pod template (same
// fixture image, signals server idling), and returns its IPs once Running.
func createManualPeersClient(t *testing.T, ctx context.Context, region kubernetes.Interface, namespace, workload string) []string {
	t.Helper()
	deployment, err := region.AppsV1().Deployments(namespace).Get(ctx, workload, meta.GetOptions{})
	if err != nil {
		t.Fatal("peer client template", err)
	}
	spec := deployment.Spec.Template.Spec.DeepCopy()
	spec.RestartPolicy = core.RestartPolicyAlways
	pod := &core.Pod{ObjectMeta: meta.ObjectMeta{Name: manualPeersClient, Labels: map[string]string{"app": manualPeersClient}}, Spec: *spec}
	if _, err := region.CoreV1().Pods(namespace).Create(ctx, pod, meta.CreateOptions{}); err != nil {
		t.Fatal("peer client Pod", err)
	}
	t.Cleanup(func() {
		c, end := context.WithTimeout(context.Background(), 10*time.Second)
		defer end()
		_ = region.CoreV1().Pods(namespace).Delete(c, manualPeersClient, meta.DeleteOptions{GracePeriodSeconds: new(int64)})
	})
	for until := time.Now().Add(90 * time.Second); time.Now().Before(until); {
		current, err := region.CoreV1().Pods(namespace).Get(ctx, manualPeersClient, meta.GetOptions{})
		if err == nil && current.Status.Phase == core.PodRunning && current.Status.PodIP != "" && !current.Spec.HostNetwork {
			ips := []string{}
			for _, ip := range current.Status.PodIPs {
				ips = append(ips, ip.IP)
			}
			t.Logf("peer client %s/%s uid=%s ips=%v", namespace, manualPeersClient, current.UID, ips)
			return ips
		}
		if err := installedJourneyPause(ctx, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("peer client Pod did not run")
	return nil
}

// manualPeersTraffic runs the fixture's bounded traffic client inside the
// peer Pod against the target Pod IP until ctx ends. Each run lasts at most
// eight seconds (the client's own limit is 8.5 s); stdin stays open because
// the client treats EOF as cancellation. It returns the completed runs.
func manualPeersTraffic(ctx context.Context, regionalConfig, namespace, targetIP string) (runs int) {
	for ctx.Err() == nil {
		deadline := time.Now().Add(8 * time.Second).UTC().Format(time.RFC3339Nano)
		command := exec.CommandContext(ctx, "kubectl", "--kubeconfig", regionalConfig, "-n", namespace, "exec", "-i", manualPeersClient, "--", "/provider-proxy", "traffic-client", targetIP, deadline)
		// Wait closes the held-open pipe after the client exits.
		if _, err := command.StdinPipe(); err == nil && command.Start() == nil && command.Wait() == nil {
			runs++
		}
		if installedJourneyPause(ctx, 500*time.Millisecond) != nil {
			return runs
		}
	}
	return runs
}

var manualPeersWarning = regexp.MustCompile(`^Peers: (\d+) Kubernetes endpoints resolved at preview \(members digest ([0-9a-f.]+)\)`)

// manualPeersEndpoints reads the preview's resolved endpoint count and the
// (bounded) members digest from its review warnings.
func manualPeersEndpoints(warnings []string) (int, string, bool) {
	for _, w := range warnings {
		if m := manualPeersWarning.FindStringSubmatch(w); m != nil {
			n, err := strconv.Atoi(m[1])
			return n, m[2], err == nil
		}
	}
	return 0, "", false
}

// checkManualPeersFields checks tshark's ip.src, ip.dst and tcp.port fields:
// every packet is to or from the peer on the reviewed port.
func checkManualPeersFields(out, peer string) (int, error) {
	packets := 0
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			return packets, fmt.Errorf("packet fields %q", line)
		}
		ports := strings.Split(fields[2], ",")
		if fields[0] != peer && fields[1] != peer {
			return packets, fmt.Errorf("packet outside the reviewed peer %s: %q", peer, line)
		}
		if len(ports) != 2 || (ports[0] != strconv.Itoa(manualPeersPort) && ports[1] != strconv.Itoa(manualPeersPort)) {
			return packets, fmt.Errorf("packet outside the reviewed TCP port: %q", line)
		}
		packets++
	}
	if packets == 0 {
		return 0, fmt.Errorf("no captured packets")
	}
	return packets, nil
}

// qualifyManualPeersPCAP writes the native recording and opens it with
// tshark: at least one packet, and no packet without the peer's address.
func qualifyManualPeersPCAP(t *testing.T, ctx context.Context, native []byte, peer string) int {
	t.Helper()
	path := "../results/manual-peers.pcapng"
	if err := os.WriteFile(path, native, 0600); err != nil {
		t.Fatal(err)
	}
	family := "ip"
	if strings.Contains(peer, ":") {
		family = "ipv6"
	}
	out, err := exec.CommandContext(ctx, "tshark", "-r", path, "-T", "fields", "-e", family+".src", "-e", family+".dst", "-e", "tcp.port").Output()
	if err != nil {
		t.Fatal("peer PCAPNG did not open in tshark", err)
	}
	packets, err := checkManualPeersFields(string(out), peer)
	if err != nil {
		t.Fatal("peer PCAPNG", err)
	}
	others, err := exec.CommandContext(ctx, "tshark", "-r", path, "-Y", "!("+family+".addr=="+peer+")").Output()
	if err != nil {
		t.Fatal("peer PCAPNG display filter", err)
	}
	if strings.TrimSpace(string(others)) != "" {
		t.Fatalf("PCAPNG holds packets without the peer %s: %s", peer, others)
	}
	return packets
}
