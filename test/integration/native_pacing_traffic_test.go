package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

const nativeTrafficRecords = 65536
const nativeTrafficRecordBytes = 64
const nativeTrafficPayload = nativeTrafficRecords * nativeTrafficRecordBytes
const nativeTrafficBatches = 16
const nativeTrafficRecordsPerBatch = nativeTrafficRecords / nativeTrafficBatches
const nativeTrafficInterval = 500 * time.Millisecond
const nativeTrafficPhase = 8500 * time.Millisecond

// The child owns exactly these eight receipt fields. Parent wall time,
// receipt validity and derived client timing are never accepted from JSON.
type nativeTrafficReceipt struct {
	Batches, Records, Bytes int64
	Elapsed                 time.Duration
	Failure                 string
	LastStatus              int
	LastBodyBytes           int64
	LastAcknowledged        bool
}

type nativeTrafficResult struct {
	Batches, Records, Bytes int64
	Elapsed                 time.Duration
	Failure                 string
	LastStatus              int
	LastBodyBytes           int64
	LastAcknowledged        bool
	ClientElapsed           time.Duration
	ReceiptValid            bool
}

// A measured small artifact never qualifies the near-full-window experiment.
// The 64 KiB tolerance covers final format blocks without increasing the cap.
func nativePacingRequireNearFullRecording(size int64) error {
	if size < artifact.RecordingNativeLimit-nativePacingWindow || size > artifact.RecordingNativeLimit {
		return fmt.Errorf("near-full qualification requires %d..%d measured native bytes; got %d", artifact.RecordingNativeLimit-nativePacingWindow, artifact.RecordingNativeLimit, size)
	}
	return nil
}

func TestNativePacingMeasuredSizeGate(t *testing.T) {
	for _, size := range []int64{4096, artifact.RecordingNativeLimit - nativePacingWindow - 1, artifact.RecordingNativeLimit + 1} {
		if nativePacingRequireNearFullRecording(size) == nil {
			t.Fatal("tiny or oversized artifact relabeled as near-full", size)
		}
	}
	if err := nativePacingRequireNearFullRecording(artifact.RecordingNativeLimit - nativePacingWindow); err != nil {
		t.Fatal(err)
	}
}

// This binary was built CGO_ENABLED=0 by the existing fixture runner, copied
// before collection, and hash-checked on each exact owned regional Kind node.
type nativeTrafficHelper struct {
	Cluster, SHA256 string
	Nodes           []string
}

func (h nativeTrafficHelper) validForNode(node string) bool {
	digest, err := hex.DecodeString(h.SHA256)
	if h.Cluster == "" || err != nil || len(digest) != 32 || len(h.Nodes) < 1 || len(h.Nodes) > 2 || !slices.Contains(h.Nodes, node) {
		return false
	}
	for i, current := range h.Nodes {
		if !strings.HasPrefix(current, h.Cluster+"-") || slices.Contains(h.Nodes[:i], current) {
			return false
		}
	}
	return true
}

type nativeTrafficOutput struct{ bytes.Buffer }

func (b *nativeTrafficOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 2048 {
		return 0, errors.New("traffic receipt exceeds bound")
	}
	return b.Buffer.Write(p)
}

func nativePacingNodeTraffic(ctx context.Context, helper nativeTrafficHelper, node, podIP string) (out nativeTrafficResult, err error) {
	started := time.Now()
	defer func() { out.Elapsed = time.Since(started) }()
	ip := net.ParseIP(podIP)
	if ctx == nil || ctx.Err() != nil || !helper.validForNode(node) || ip == nil || !ip.IsPrivate() || ip.IsLoopback() {
		return out, errors.New("exact owned traffic target unavailable")
	}
	phase, cancel := context.WithTimeout(ctx, nativeTrafficPhase)
	defer cancel()
	deadline, _ := phase.Deadline()
	command := exec.CommandContext(phase, "docker", "exec", "-i", node, "/asservat-fixture-traffic", "traffic-client", ip.String(), deadline.UTC().Format(time.RFC3339Nano))
	input, err := command.StdinPipe()
	if err != nil {
		return out, err
	}
	defer input.Close()
	var output nativeTrafficOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	// EOF reaches the helper's cancellation reader. A failed join is a failed
	// experiment; no detached helper is accepted as a successful traffic phase.
	command.Cancel = func() error { return input.Close() }
	command.WaitDelay = 250 * time.Millisecond
	if err = command.Start(); err != nil {
		return out, errors.New("owned traffic process unavailable")
	}
	stop := context.AfterFunc(phase, func() { _ = input.Close() })
	processErr := command.Wait()
	stop()
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	decoder.DisallowUnknownFields()
	var receipt nativeTrafficReceipt
	if err = decoder.Decode(&receipt); err != nil {
		out.Failure = "receipt"
		return out, errors.New("owned traffic receipt unavailable")
	}
	if receipt.Batches < 0 || receipt.Batches > nativeTrafficBatches || receipt.Records != receipt.Batches*nativeTrafficRecordsPerBatch || receipt.Bytes < 0 || receipt.Bytes > nativeTrafficPayload+1 || receipt.LastBodyBytes < 0 || receipt.LastBodyBytes > nativeTrafficRecordsPerBatch*nativeTrafficRecordBytes+1 || receipt.Elapsed < 0 || !slices.Contains([]string{"", "deadline", "request", "acknowledgement"}, receipt.Failure) {
		out.Failure = "receipt_shape"
		return out, errors.New("owned traffic receipt exceeds finite shape")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		out.Failure = "receipt_extra"
		return out, errors.New("owned traffic receipt has extra output")
	}
	out = nativeTrafficResult{Batches: receipt.Batches, Records: receipt.Records, Bytes: receipt.Bytes,
		Failure: receipt.Failure, LastStatus: receipt.LastStatus, LastBodyBytes: receipt.LastBodyBytes,
		LastAcknowledged: receipt.LastAcknowledged, ClientElapsed: receipt.Elapsed, ReceiptValid: true}
	if processErr != nil && out.Failure == "" {
		out.Failure = "process"
	}
	if processErr != nil || out.Failure != "" || out.Batches != nativeTrafficBatches || out.Records != nativeTrafficRecords || out.Bytes != nativeTrafficPayload || !out.LastAcknowledged || out.LastStatus != http.StatusOK || out.LastBodyBytes != nativeTrafficRecordsPerBatch*nativeTrafficRecordBytes || phase.Err() != nil {
		return out, errors.New("owned traffic phase incomplete")
	}
	return out, nil
}

func TestNativePacingNodeTrafficCancellationClosesInputAndJoins(t *testing.T) {
	work := t.TempDir()
	marker := filepath.Join(work, "joined")
	// A synthetic command observes EOF, writes its closed receipt and exits.
	// It performs no Docker operation or network request.
	script := "#!/bin/sh\n/bin/cat >/dev/null\nprintf joined > \"$ASSERVAT_TRAFFIC_JOIN_MARKER\"\nprintf '%s\\n' '{\"Failure\":\"deadline\"}'\nexit 1\n"
	if err := os.WriteFile(filepath.Join(work, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", work)
	t.Setenv("ASSERVAT_TRAFFIC_JOIN_MARKER", marker)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	result, err := nativePacingNodeTraffic(ctx, nativeTrafficHelper{Cluster: "owned", SHA256: strings.Repeat("1", 64), Nodes: []string{"owned-worker"}}, "owned-worker", "10.0.0.2")
	if err == nil || result.Failure != "deadline" || result.Elapsed > time.Second {
		t.Fatal("cancelled command accepted or did not join", result, err)
	}
	if b, e := os.ReadFile(marker); e != nil || string(b) != "joined" {
		t.Fatal("EOF did not complete original process", e)
	}
}

func TestNativePacingNodeTrafficRefusesForeignOrLoopbackTarget(t *testing.T) {
	helper := nativeTrafficHelper{Cluster: "owned", SHA256: strings.Repeat("1", 64), Nodes: []string{"owned-worker"}}
	for _, target := range []struct{ node, ip string }{{"foreign-worker", "10.0.0.2"}, {"owned-worker", "127.0.0.1"}, {"owned-worker", "example.invalid"}, {"owned-worker", "8.8.8.8"}} {
		if _, err := nativePacingNodeTraffic(t.Context(), helper, target.node, target.ip); err == nil {
			t.Fatal("unowned traffic destination admitted", target)
		}
	}
}

func TestNativePacingNodeTrafficRequiresClosedCompleteReceipt(t *testing.T) {
	work := t.TempDir()
	response := filepath.Join(work, "receipt")
	if err := os.WriteFile(filepath.Join(work, "docker"), []byte("#!/bin/sh\n/bin/cat \"$ASSERVAT_TRAFFIC_RESPONSE\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", work)
	t.Setenv("ASSERVAT_TRAFFIC_RESPONSE", response)
	complete := `{"Batches":16,"Records":65536,"Bytes":4194304,"Elapsed":7500000000,"LastStatus":200,"LastBodyBytes":262144,"LastAcknowledged":true}`
	for _, tc := range []struct {
		name, receipt string
		valid         bool
	}{
		{"complete", complete, true},
		{"partial", `{"Batches":7,"Records":28672,"Bytes":1863232,"Failure":"deadline"}`, false},
		{"missing acknowledgement", strings.Replace(complete, `"LastAcknowledged":true`, `"LastAcknowledged":false`, 1), false},
		{"extra JSON", complete + `{}`, false},
		{"unknown field", strings.TrimSuffix(complete, "}") + `,"unknown":1}`, false},
		{"parent receipt validity", strings.TrimSuffix(complete, "}") + `,"ReceiptValid":true}`, false},
		{"parent client elapsed", strings.TrimSuffix(complete, "}") + `,"ClientElapsed":77}`, false},
		{"decode failure after injected parent fields", strings.TrimSuffix(complete, "}") + `,"ReceiptValid":true,"ClientElapsed":77,"unknown":1}`, false},
		{"unbounded output", strings.Repeat("x", 2049), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(response, []byte(tc.receipt), 0600); err != nil {
				t.Fatal(err)
			}
			result, err := nativePacingNodeTraffic(t.Context(), nativeTrafficHelper{Cluster: "owned", SHA256: strings.Repeat("1", 64), Nodes: []string{"owned-worker"}}, "owned-worker", "10.0.0.2")
			if (err == nil) != tc.valid {
				t.Fatal("synthetic process receipt wrongly accepted/refused", result, err)
			}
			if tc.valid && !result.ReceiptValid {
				t.Fatal("complete synthetic receipt not marked valid")
			}
			if strings.Contains(tc.name, "parent") && (result.ReceiptValid || result.ClientElapsed != 0) {
				t.Fatal("invalid child receipt changed parent-owned fields", result)
			}
			if tc.name == "partial" && (result.Batches != 7 || result.Records != 28672 || result.Bytes != 1863232 || !result.ReceiptValid || result.Failure != "deadline") {
				t.Fatal("valid partial diagnostics lost", result)
			}
		})
	}
}

func TestNativePacingTrafficDescriptorRefusesBeforeBootstrap(t *testing.T) {
	good := nativeTrafficHelper{Cluster: "owned", SHA256: strings.Repeat("1", 64), Nodes: []string{"owned-control-plane"}}
	if !good.validForNode("owned-control-plane") {
		t.Fatal("owned descriptor refused")
	}
	for _, bad := range []nativeTrafficHelper{{}, {Cluster: "owned", SHA256: strings.Repeat("z", 64), Nodes: good.Nodes}, {Cluster: "other", SHA256: good.SHA256, Nodes: good.Nodes}, {Cluster: "owned", SHA256: good.SHA256, Nodes: []string{"owned-control-plane", "owned-control-plane"}}} {
		if bad.validForNode("owned-control-plane") {
			t.Fatal("missing/foreign/invalid descriptor passed early preflight")
		}
	}
}

func TestNativePacingMissingDescriptorStopsActualBootstrapEntry(t *testing.T) {
	// The actual entry must refuse this otherwise parseable descriptor before
	// touching deliberately unusable provider/API inputs. No services are used.
	path := filepath.Join(t.TempDir(), "fixture.json")
	raw := `{"WorkerImage":"synthetic","NativeProviders":{"Postgres":"unusable"},"Clusters":[{},{}]}`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestInitialBootstrapChainWithRealServices$", "-test.timeout=5s")
	command.Env = append(os.Environ(), "ASSERVAT_CONTEXT_FIXTURES="+path, "ASSERVAT_INITIAL_BOOTSTRAP_CHAIN_NATIVE=1", "ASSERVAT_INSTALLER_CONTINUATION=1", "ASSERVAT_JOURNEY_FOCUS=native-paced")
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "native traffic helper descriptor unavailable before bootstrap") {
		t.Fatal("actual bootstrap entry did not refuse missing helper first", err, string(output))
	}
}
