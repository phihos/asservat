package bootstrap

import (
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/node"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type nodeVersionBinary struct{ Head, Path, SHA256, SourceInventorySHA string }
type nodeVersionManifest struct {
	Old, New        nodeVersionBinary
	HelperSourceSHA string
}
type nodeVersionResult struct {
	Accepted, Unavailable, Observed, PacketValid bool
	WorkCount                                    int
}
type nodeHelperOutput struct{ bytes.Buffer }

func (b *nodeHelperOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 4096 {
		return 0, errors.New("bounded node helper output exceeded")
	}
	return b.Buffer.Write(p)
}

type nodeVersionStatus struct {
	http.ResponseWriter
	status int
}

func (w *nodeVersionStatus) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
func (w *nodeVersionStatus) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return w.ResponseWriter.Write(p)
}

// Optional local qualification uses actual separately compiled old/new Client.Poll
// binaries. It starts no collector and uses the existing synthetic node authority.
func TestNodeObservationActualOldAndNewClientTLS(t *testing.T) {
	path := os.Getenv("ASSERVAT_NODE_VERSION_HELPERS")
	if path == "" {
		t.Skip("actual old/new helpers not supplied")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 8192 {
		t.Fatal("bounded version manifest unavailable")
	}
	var manifest nodeVersionManifest
	if json.Unmarshal(raw, &manifest) != nil || manifest.Old.Head != "eed8594020645fe6d10f8c6565e69a6235c7507d" || manifest.New.Head == manifest.Old.Head {
		t.Fatal("version manifest identity invalid")
	}
	helperSource, err := os.ReadFile(filepath.Join("..", "transport", "node", "version_helper_test.go"))
	if err != nil || hexSHA(helperSource) != manifest.HelperSourceSHA {
		t.Fatal("helper source binding changed")
	}
	for _, binary := range []nodeVersionBinary{manifest.Old, manifest.New} {
		b, err := os.ReadFile(binary.Path)
		if err != nil || len(b) > 64<<20 || hexSHA(b) != binary.SHA256 || len(binary.SourceInventorySHA) != 64 {
			t.Fatal("frozen helper binary/source binding changed")
		}
	}
	cert, roots, rootPEM := serverCertificate(t)
	att := &testNodeAttester{pod: "11111111-1111-4111-8111-111111111111"}
	server, err := NewNodeChannelServer("50000000-0000-4000-8000-000000000001", att, cert, io.Discard, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var authenticatedOK atomic.Int32
	original := server.handler
	server.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &nodeVersionStatus{ResponseWriter: w}
		original.ServeHTTP(sw, r)
		if r.URL.Path == contracts.NodePollPath && sw.status == 200 && r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
			authenticatedOK.Add(1)
		}
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	root, stop := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(root, listener) }()
	defer func() {
		stop()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	endpoint := "https://" + listener.Addr().String()
	credentials, err := mtls.NewNodeCredentials()
	if err != nil {
		t.Fatal(err)
	}
	client, err := node.NewClient(endpoint, "asservat-connector-nodes", roots, credentials.GetClientCertificate)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdle()
	response, err := client.Enroll(root, contracts.NodeEnrollRequest{Token: "synthetic.node.token", CSR: credentials.CSR(), BootID: testNodeBoot, Epoch: testNodeEpoch})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = credentials.Install(response.Certificate, time.Now()); err != nil {
		t.Fatal(err)
	}
	client.CloseIdle()
	budget, _ := collector.NewBudget(collector.Ceilings{RingBytes: 1 << 20, FrozenBytes: 16 << 20, UploadBytesPerSecond: 32 << 20, UploadBurstBytes: 64 << 20}, time.Now())
	facts := collector.Facts{KernelRelease: "6.8.0", Kernel: collector.KernelVersion{Major: 6, Minor: 8}, BTF: collector.Supported, CgroupV2: collector.Supported, BPF: collector.Supported, TCX: collector.Supported, TC: collector.Supported, DebugFS: collector.Unsupported, TraceFS: collector.Unsupported, BPFFS: collector.Supported, HostProcesses: collector.Supported, Runtime: collector.RuntimeContainerd, Engine: collector.Engine{Linked: true, Initialized: true, Version: "v0.57.0"}}
	report := collector.Report{Sequence: 1, ObservedAt: time.Now().UTC(), Facts: facts, Mechanisms: collector.Assess(facts), Budget: budget.Usage(time.Now())}
	if err = client.Status(root, testNodeEpoch, report); err != nil {
		t.Fatal(err)
	}
	leaf, err := credentials.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(leaf.PrivateKey)
	if err != nil {
		t.Fatal("synthetic fixture key serialization unavailable")
	}
	input := struct {
		Endpoint, ServerName, Roots, Certificate, Key, Epoch string
		After                                                uint64
	}{endpoint, "asservat-connector-nodes", rootPEM, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: response.Certificate})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})), testNodeEpoch, 0}
	clear(key)
	packet, _ := nodePermitWork(time.Now())
	permit := packet.Packet.Observation
	packet.Packet.Observation = nil
	legacy, err := server.Channel.EnqueuePacket("node-uid", *packet.Packet, time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, binary := range []nodeVersionBinary{manifest.Old, manifest.New} {
		result := runNodeVersionHelper(t, root, binary, input)
		if !result.Accepted || result.Unavailable || result.WorkCount != 1 || !result.PacketValid || result.Observed {
			t.Fatal("actual version legacy positive failed", binary.Head, result)
		}
	}
	input.After = legacy.Sequence
	view, ok := server.Channel.NodeByName("worker-1")
	if !ok {
		t.Fatal("authenticated source missing")
	}
	source := targets.PacketSourceObservation{PodUID: packet.Packet.PodUID, NodeUID: view.Identity.NodeUID, BootID: view.Identity.BootID, CollectorPodUID: view.Identity.PodUID, CollectorEpoch: view.Identity.Epoch, ObservedAt: time.Now().UTC(), FreshUntil: time.Now().Add(5 * time.Second)}
	permit.Binding.NodeUID, permit.Binding.BootID, permit.Binding.CollectorPodUID, permit.Binding.CollectorEpoch = source.NodeUID, source.BootID, source.CollectorPodUID, source.CollectorEpoch
	packet.Packet.Observation = permit
	if _, err = server.Channel.EnqueuePacketExpected(root, source, *packet.Packet, permit.StartBy); err != nil {
		t.Fatal(err)
	}
	old := runNodeVersionHelper(t, root, manifest.Old, input)
	if old.Accepted || !old.Unavailable || old.WorkCount != 0 || old.PacketValid || old.Observed {
		t.Fatal("actual old client silently accepted observed packet", old)
	}
	current := runNodeVersionHelper(t, root, manifest.New, input)
	if !current.Accepted || current.Unavailable || current.WorkCount != 1 || !current.PacketValid || !current.Observed {
		t.Fatal("actual new client dropped the emitted permit", current)
	}
	if authenticatedOK.Load() != 4 {
		t.Fatal("version refusal did not follow four authenticated HTTP200 polls", authenticatedOK.Load())
	}
	t.Logf("actual versions old=%s new=%s: legacy positives2, emitted permit old refusal/new positive; authenticatedHTTP200=4; helper source=%s old binary=%s new binary=%s", manifest.Old.Head, manifest.New.Head, manifest.HelperSourceSHA, manifest.Old.SHA256, manifest.New.SHA256)
}
func hexSHA(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func runNodeVersionHelper(t *testing.T, parent context.Context, binary nodeVersionBinary, input any) nodeVersionResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	data, err := json.Marshal(input)
	if err != nil || len(data) > 64<<10 {
		t.Fatal("bounded child input unavailable")
	}
	cmd := exec.CommandContext(ctx, binary.Path, "-test.run=^TestActualNodeVersionClientHelper$")
	cmd.Env = append(os.Environ(), "ASSERVAT_NODE_VERSION_HELPER=1")
	cmd.ExtraFiles = []*os.File{reader}
	var output nodeHelperOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if cmd.Start() != nil {
		t.Fatal("actual helper could not start")
	}
	reader.Close()
	_, writeErr := writer.Write(data)
	clear(data)
	writer.Close()
	waitErr := cmd.Wait()
	if writeErr != nil || waitErr != nil {
		t.Fatal("actual helper failed; output deliberately closed")
	}
	var result nodeVersionResult
	found := false
	for _, line := range strings.Split(output.String(), "\n") {
		if strings.HasPrefix(line, "NODE_POLL_HELPER ") {
			if found || json.Unmarshal([]byte(strings.TrimPrefix(line, "NODE_POLL_HELPER ")), &result) != nil {
				t.Fatal("closed helper result invalid")
			}
			found = true
		} else if line != "" && line != "PASS" {
			t.Fatal("unexpected helper output suppressed")
		}
	}
	if !found {
		t.Fatal("actual helper result missing")
	}
	return result
}
