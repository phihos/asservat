package objectstore

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/packets"
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type rawSummaryProbeInput struct {
	Shape                             string
	Packets, Unclassified, Aggregates int64
	NativeSHA256                      string
	NativeBytes                       int64
	Files                             map[string]string
}
type rawSummaryProbeFixture struct {
	BinarySHA256 string
	Inputs       []rawSummaryProbeInput
}

// Explicit producer and consumer processes reuse the encrypted fixture and
// actual receiver/outer reader. A caller may put the consumer in a cgroup; this
// test never creates one or infers containment from RSS/configuration.
func TestRawPacketSummaryEncryptedProcess(t *testing.T) {
	if dir := os.Getenv("ASSERVAT_RAW_PACKET_SUMMARY_GENERATE"); dir != "" {
		rawSummaryProbeGenerate(t, dir)
		return
	}
	dir := os.Getenv("ASSERVAT_RAW_PACKET_SUMMARY_FIXTURE")
	if dir == "" {
		t.Skip("explicit prepared raw-summary resource component")
	}
	shape, mode := os.Getenv("ASSERVAT_RAW_PACKET_SUMMARY_SHAPE"), os.Getenv("ASSERVAT_RAW_PACKET_SUMMARY_MODE")
	if mode != "complete" && mode != "cancel" && mode != "source-error" {
		t.Fatal("explicit complete/cancel/source-error mode required")
	}
	var fixture rawSummaryProbeFixture
	comparisonProbeLoad(t, filepath.Join(dir, "probe.json"), &fixture)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binarySHA, _ := comparisonProbeDigest(t, executable)
	if fixture.BinarySHA256 != binarySHA {
		t.Fatal("producer/consumer binary differs")
	}
	var input *rawSummaryProbeInput
	for i := range fixture.Inputs {
		if fixture.Inputs[i].Shape == shape {
			input = &fixture.Inputs[i]
		}
	}
	if input == nil {
		t.Fatal("unknown prepared shape")
	}
	for file, want := range input.Files {
		got, _ := comparisonProbeDigest(t, filepath.Join(dir, shape, file))
		if got != want {
			t.Fatal("immutable prepared fixture changed", file)
		}
	}
	var f profileEncryptedFixture
	comparisonProbeLoad(t, filepath.Join(dir, shape, "fixture.json"), &f)
	// Use the actual production projection conversation bound, not a new timeout.
	until := time.Now().Add(value.NativeConversationWindow(value.NativeProjection))
	ctx, cancel := context.WithDeadline(t.Context(), until)
	defer cancel()
	var before, after syscall.Rusage
	if err = syscall.Getrusage(syscall.RUSAGE_SELF, &before); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	result, readErr, roles, joined, cancelJoin := rawSummaryProbeRead(t, ctx, cancel, filepath.Join(dir, shape), f, mode)
	if err = syscall.Getrusage(syscall.RUSAGE_SELF, &after); err != nil {
		t.Fatal(err)
	}
	valid := readErr == nil && result.Valid(f.Scope)
	expected := valid && result.PacketSummary.Packets == input.Packets && result.PacketSummary.UnclassifiedPackets != nil && *result.PacketSummary.UnclassifiedPackets == input.Unclassified && int64(result.PacketSummary.ConversationsTotal) == input.Aggregates
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	report := map[string]any{"format": "raw-packet-summary-resource-component/v1", "shape": shape, "mode": mode, "binary_sha256": binarySHA, "input": input, "go_version": runtime.Version(), "gomaxprocs": runtime.GOMAXPROCS(0), "gogc": os.Getenv("GOGC"), "gomemlimit": os.Getenv("GOMEMLIMIT"), "operation_elapsed_ns": time.Since(started).Nanoseconds(), "operation_user_cpu_ns": comparisonProbeCPU(after.Utime) - comparisonProbeCPU(before.Utime), "operation_system_cpu_ns": comparisonProbeCPU(after.Stime) - comparisonProbeCPU(before.Stime), "process_peak_rss_kib": after.Maxrss, "heap_inuse": memory.HeapInuse, "command_until": until, "conversation_bound_ns": value.NativeConversationWindow(value.NativeProjection).Nanoseconds(), "synthetic_unwraps": roles, "receiver_joined": joined, "cancel_join_ns": cancelJoin, "result_valid": valid, "expected_counts_match": expected, "read_failed": readErr != nil, "scope": "Actual approved receiver, NativeContextReader, installed parser, framed authentication and local TLS range/key RPC; synthetic current source/key authority. Provider servers share measured consumer process. No SQL, real KMS, native command/owner/public transport, worker bootstrap/enrollment or installed maximum-input claim. Cgroup enforcement/counters require independent external runner/probe evidence."}
	if path := os.Getenv("ASSERVAT_RAW_PACKET_SUMMARY_REPORT"); path != "" {
		comparisonProbeWrite(t, path, report)
	}
	if !joined || roles < 1 || roles > 3 || mode == "complete" && roles != 3 {
		t.Fatal("resource component failed exact role/join contract", roles, joined)
	}
	if mode == "complete" && !expected || mode != "complete" && (readErr == nil || result.PacketSummary != nil) {
		t.Fatal("resource component result/refusal contract", mode)
	}
	result.Clear()
}

func rawSummaryProbeGenerate(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binarySHA, _ := comparisonProbeDigest(t, executable)
	fixture := rawSummaryProbeFixture{BinarySHA256: binarySHA}
	for _, shape := range []string{"payload", "aggregates", "tiny-prefix"} {
		folder := filepath.Join(dir, shape)
		if err = os.MkdirAll(folder, 0700); err != nil {
			t.Fatal(err)
		}
		keyScope := value.KeyScope{InstallationID: testProjectionScope().RootID, Purpose: "artifact", KeyID: "synthetic"}
		sealer := comparisonRemoteFixtureSealer{scope: keyScope}
		f := packetEncryptedFixtureSource(t, folder, "complete", true, sealer)
		if shape == "tiny-prefix" {
			f.Source.Expectation.Recording.Snaplen = 1
		}
		native, input := rawSummaryProbeNative(t, shape, f.Source.Expectation.TriggeredAt)
		if err = os.WriteFile(filepath.Join(folder, "native.pcapng"), native, 0600); err != nil {
			t.Fatal(err)
		}
		f.Source.Copies = prepareEncryptedProjectionSource(t, folder, bytes.NewReader(native), f.Source.Expectation, false, sealer)
		f.Scope.Version = evidence.ContextCopiesDigest(f.Source.Copies)
		comparisonProbeWrite(t, filepath.Join(folder, "fixture.json"), f)
		input.NativeSHA256, input.NativeBytes = comparisonProbeDigest(t, filepath.Join(folder, "native.pcapng"))
		input.Files = map[string]string{}
		for _, name := range []string{"native.pcapng", "data", "index", "manifest", "commit", "fixture.json"} {
			input.Files[name], _ = comparisonProbeDigest(t, filepath.Join(folder, name))
		}
		fixture.Inputs = append(fixture.Inputs, input)
		clear(native)
	}
	comparisonProbeWrite(t, filepath.Join(dir, "probe.json"), fixture)
}

func rawSummaryProbeNative(t *testing.T, shape string, at time.Time) ([]byte, rawSummaryProbeInput) {
	t.Helper()
	input := rawSummaryProbeInput{Shape: shape}
	var out bytes.Buffer
	snap := 1500
	if shape == "tiny-prefix" {
		snap = 1
	}
	writer, err := pcapgo.NewNgWriterInterface(&out, pcapgo.NgInterface{LinkType: layers.LinkTypeEthernet, SnapLength: uint32(snap), TimestampResolution: 9}, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err = writer.Flush(); err != nil {
		t.Fatal(err)
	}
	random := rand.New(rand.NewPCG(5, 7))
	frame := make([]byte, 1500)
	copy(frame, []byte{0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 6, 8, 0, 0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2})
	binary.BigEndian.PutUint16(frame[34:], 40000)
	binary.BigEndian.PutUint16(frame[36:], 80)
	frame[46] = 5 << 4
	add := func(data []byte) {
		wire := len(data)
		if shape == "tiny-prefix" {
			wire = 1500
		}
		if err := writer.WritePacket(gopacket.CaptureInfo{Timestamp: at.Add(time.Duration(input.Packets) * time.Microsecond), CaptureLength: len(data), Length: wire}, data); err != nil {
			t.Fatal(err)
		}
		input.Packets++
		if err := writer.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	if shape == "aggregates" {
		for i := range query.PacketSummaryMaxAggregates {
			binary.BigEndian.PutUint16(frame[34:], uint16(i))
			binary.BigEndian.PutUint16(frame[16:], 40)
			add(frame[:54])
		}
		input.Aggregates = query.PacketSummaryMaxAggregates
	}
	if shape != "payload" && shape != "aggregates" && shape != "tiny-prefix" {
		t.Fatal("unknown shape")
	}
	for out.Len()+1532+1024 < int(artifact.RecordingNativeLimit) {
		if shape == "tiny-prefix" {
			frame[0] = byte(random.Uint32())
			add(frame[:1])
			input.Unclassified++
		} else {
			for i := 54; i < len(frame); i++ {
				frame[i] = byte(random.Uint32())
			}
			binary.BigEndian.PutUint16(frame[16:], 1486)
			add(frame)
			if input.Aggregates == 0 {
				input.Aggregates = 1
			}
		}
	}
	if err = writer.WriteInterfaceStats(0, pcapgo.NgInterfaceStatistics{LastUpdate: at.Add(time.Second), PacketsReceived: uint64(input.Packets), PacketsDropped: 0}); err != nil {
		t.Fatal(err)
	}
	if err = writer.Flush(); err != nil {
		t.Fatal(err)
	}
	// Finite ignored ISB comments fill the exact byte bound without new records.
	for out.Len() < int(artifact.RecordingNativeLimit) {
		size := min(256<<10, int(artifact.RecordingNativeLimit)-out.Len())
		if size < 40 {
			t.Fatal("native padding geometry", size)
		}
		body := make([]byte, 24)
		binary.LittleEndian.PutUint16(body[12:], 5)
		binary.LittleEndian.PutUint16(body[14:], 8)
		remaining := size - 40
		for remaining > 0 {
			n := min(65532, remaining-4)
			option := make([]byte, 4+n)
			binary.LittleEndian.PutUint16(option, 1)
			binary.LittleEndian.PutUint16(option[2:], uint16(n))
			body = append(body, option...)
			remaining -= 4 + n
		}
		body = append(body, 0, 0, 0, 0)
		block := make([]byte, len(body)+12)
		binary.LittleEndian.PutUint32(block, 5)
		binary.LittleEndian.PutUint32(block[4:], uint32(len(block)))
		copy(block[8:], body)
		binary.LittleEndian.PutUint32(block[len(block)-4:], uint32(len(block)))
		out.Write(block)
	}
	if out.Len() != int(artifact.RecordingNativeLimit) {
		t.Fatal("native maximum size")
	}
	count, err := packets.CheckRaw(bytes.NewReader(out.Bytes()), packets.RawLimits{Snaplen: snap})
	if err != nil || int64(count) != input.Packets {
		t.Fatal("canonical producer shape", err)
	}
	return out.Bytes(), input
}

func rawSummaryProbeRead(t *testing.T, ctx context.Context, cancel context.CancelFunc, dir string, f profileEncryptedFixture, mode string) (query.ProjectionResult, error, int, bool, int64) {
	t.Helper()
	return savedPacketProbeRead(t, ctx, cancel, dir, f, mode, func(r *NativeContextReader) { r.ServePacketSummaries(packets.SummarizePCAPNG) })
}

// Both process probes retain the identical receiver/key/source/join apparatus.
func savedPacketProbeRead(t *testing.T, ctx context.Context, cancel context.CancelFunc, dir string, f profileEncryptedFixture, mode string, serve func(*NativeContextReader)) (query.ProjectionResult, error, int, bool, int64) {
	t.Helper()
	verifier, _, entered, unblock := profileEncryptedVerifier(t, dir, f, mode == "cancel")
	defer unblock()
	if mode == "source-error" {
		client, ok := verifier.store.store.client.Options().HTTPClient.(*http.Client)
		if !ok {
			t.Fatal("actual fixture HTTP client unavailable")
		}
		client.Transport = rawSummaryProbeFailTransport{client.Transport}
	}

	var mu sync.Mutex
	roles := map[string]bool{}
	requests := 0
	keyServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, err := contracts.DecodeKeyRequest(r.Body)
		if err != nil || request.Operation != "unwrap" || request.AuthorityID != f.Scope.RootID || request.Sealed == nil {
			w.WriteHeader(400)
			return
		}
		info, err := authapp.DescribeKeyRequest(value.KeyRequest{Scope: value.KeyScope{InstallationID: request.Scope.InstallationID, Purpose: request.Scope.Purpose, KeyID: request.Scope.KeyID}, AuthorityID: request.AuthorityID, Operation: request.Operation, Binding: request.Binding, Sealed: artifact.SealedKey{Reference: request.Sealed.Reference, Ciphertext: request.Sealed.Ciphertext}})
		if err != nil {
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		requests++
		used := roles[string(request.Binding)]
		roles[string(request.Binding)] = true
		mu.Unlock()
		if used {
			w.WriteHeader(403)
			return
		}
		key, err := base64.StdEncoding.DecodeString(request.Sealed.Ciphertext)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		defer clear(key)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(contracts.KeyServiceResponse{Format: contracts.KeyServiceFormat, Operation: "unwrap", Output: key, RequestSHA256: hex.EncodeToString(info.RequestDigest[:]), ValidUntil: time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)})
	}))
	defer keyServer.Close()
	client := keyServer.Client()
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{keyServer.TLS.Certificates[0]}
	defer client.CloseIdleConnections()
	reader, err := NewNativeContextReader(verifier.store, value.KeyScope{InstallationID: f.Scope.RootID, Purpose: "artifact", KeyID: "synthetic"}, keyServer.URL, client)
	if err != nil {
		t.Fatal(err)
	}
	serve(reader)
	now := time.Now().UTC()
	until, _ := ctx.Deadline()
	s := f.Scope
	revision := identity.Revision{UID: s.RootID, Generation: 1, Digest: artifact.Digest{1}}
	path := artifact.DownloadPath{ID: s.RootID, TargetClusterID: s.ClusterID, StoreID: f.Source.Expectation.Registration.StoreID, StorageRegion: "fixture", AcquisitionClusterID: s.RootID, AcquisitionRegion: "fixture", ConnectorClusterID: s.RootID, ConnectorRegion: "fixture", HubClusterID: s.RootID, HubRegion: "fixture", WorkerConfiguration: revision, HubConfiguration: revision}
	proof := artifact.DownloadProcessingProof{RootID: s.RootID, Epoch: s.RootID, CaptureID: s.CaptureID, Location: f.Source.Expectation.Registration.Location, Sequence: 1, StateDigest: artifact.Digest{1}, ObservedAt: now, ValidUntil: until}
	operation := value.NativeOperation{Path: path, Processing: proof, Reference: value.NativeReference{InstallationID: s.RootID, QueryID: s.RootID, WorkerID: s.RootID, OperationID: s.RootID, Fence: 1}, Kind: value.NativeProjection, HubPodUID: s.RootID, HubProcessEpoch: s.RootID, WorkerPodUID: s.RootID, WorkerPublicKey: artifact.Digest{1}, SourceVersion: s.Version, ParentID: s.RootID, Generation: 1, StartedAt: now, Until: until}
	worker := value.WorkerCredentialTarget{InstallationID: s.RootID, QueryID: s.RootID, WorkerID: s.RootID, PodUID: s.RootID, CreatedAt: now, RunUntil: now.Add(time.Minute)}
	receiver, err := evidence.NewRegionalApprovedResult(ctx, worker, reader, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result query.ProjectionResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := receiver.ReadApproved(ctx, operation, f.Source, s)
		done <- outcome{result, err}
	}()
	var canceledAt time.Time
	if mode == "cancel" {
		select {
		case <-entered:
			canceledAt = time.Now()
			cancel()
			unblock()
		case <-ctx.Done():
			t.Fatal("cancel shape never reached data")
		}
	}
	got := <-done
	mu.Lock()
	beforeReplay := requests
	mu.Unlock()
	if _, replayErr := receiver.ReadApproved(ctx, operation, f.Source, s); replayErr == nil {
		t.Fatal("spent resource-probe batch replayed")
	}
	mu.Lock()
	replayed := requests != beforeReplay
	mu.Unlock()
	if replayed {
		t.Fatal("spent resource-probe batch requested another key")
	}
	receiver.Close()
	joined := receiver.Wait(context.Background()) == nil
	var cancelJoin int64
	if !canceledAt.IsZero() {
		cancelJoin = time.Since(canceledAt).Nanoseconds()
	}
	mu.Lock()
	count := len(roles)
	mu.Unlock()
	if mode == "cancel" && !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("cancel not retained")
	}
	return got.result, got.err, count, joined, cancelJoin
}

// Fault injection changes only the consumer transport, never prepared files.
type rawSummaryProbeFailTransport struct{ inner http.RoundTripper }

func (t rawSummaryProbeFailTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, "/data") {
		return nil, errors.New("synthetic data transport failure")
	}
	return t.inner.RoundTrip(r)
}
func (t rawSummaryProbeFailTransport) CloseIdleConnections() {
	if c, ok := t.inner.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}
