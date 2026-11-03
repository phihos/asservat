package integration

import (
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/privacy"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/google/pprof/profile"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/diagnostics"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/domain/artifact"
)

// qualifyProfileArtifacts is the ADR-284 component qualification on real
// S3: synthetic pprof and execution-trace artifacts of this test process
// (runtime/pprof, runtime/trace) are stored through the producer, fully
// verified with the publisher's stream checks, and read back byte-identical
// through the native source; a gzip-valid but corrupted profile is stored
// by the producer and refused by verification; where the Go toolchain is
// installed, `go tool pprof -top` opens the downloaded file offline. Keys
// are synthetic; SQL publication and download authority for profiles are
// increment 3 and not composed here.
func qualifyProfileArtifacts(t *testing.T, ctx context.Context, store *objectstore.Store, admin *pgxpool.Pool, ledger *postgres.Ledger) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(raw)
	clear(raw)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	keys := authorityTestKeys{aead}
	expectation := func(p artifact.GoProfileAcquisition) artifact.ContextExpectation {
		now := time.Now().UTC().Truncate(time.Microsecond)
		t0 := now.Add(-20 * time.Second)
		digest := artifact.Digest(sha256.Sum256([]byte("synthetic go profile")))
		e := artifact.ContextExpectation{
			Profile: &p, NativeType: p.NativeType(), ExecutionClass: artifact.ContextAPIExecution,
			Registration: artifact.Registration{Location: artifact.Location{ClusterID: custodyID(), ArtifactID: custodyID(), AttemptID: custodyID()}, StoreID: custodyID(), AllocationID: custodyID(), PoolRevision: 1, AllocationRevision: 1, NativeLimit: artifact.RemoteNativeLimit,
				AnchorAt: t0, WriteUntil: now.Add(10 * time.Minute), ExpiresAt: t0.Add(1800 * time.Second), DeleteBy: t0.Add(2400 * time.Second)},
			CaseID: custodyID(), OccurrenceID: custodyID(), PodUID: "synthetic-pod-uid", Namespace: "synthetic", NamespaceUID: "synthetic-namespace-uid", WorkloadUID: "synthetic-workload-uid",
			CollectorVersion: "synthetic-test", CollectorImageDigest: digest, RecipeDigest: digest, PlanDigest: digest, CaptureUID: custodyID(), ActionID: "a0123456789abcdef01234567", DataClass: "raw", PurposeRef: "synthetic-test",
			Audience:            []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://identity.example.invalid", SubjectID: "synthetic-team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding-uid", AssignmentID: custodyID(), BasisDigest: digest}},
			RequestedAgeSeconds: 1800, MaximumAgeSeconds: 7200, DeletionBudgetSeconds: 600, RetentionRules: []artifact.RetentionRule{{UID: "retention-uid", Generation: 1, Digest: digest}}, TriggeredAt: t0,
		}
		if err := e.Validate(); err != nil {
			t.Fatal("synthetic expectation", err)
		}
		return e
	}
	store1 := func(t *testing.T, e artifact.ContextExpectation, body []byte) (*objectstore.ContextVerifier, artifact.Copies, error) {
		t.Helper()
		bound, err := store.ForCustody(e.Registration.StoreID)
		if err != nil {
			t.Fatal(err)
		}
		var journal privacy.StreamingJournal = unusedStreamingJournal{}
		writer := ""
		var plan artifact.StreamingPlan
		if e.Registration.NativeLimit > artifact.FrameBytes {
			plan = artifact.StreamingPlan{Registration: e.Registration, WriterEpoch: custodyID()}
			root := custodyID()
			reserved, objects := e.Registration.ReservedBytes()+plan.TemporaryBytes(), int64(5+plan.PartLimit())
			valid := time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)
			if _, err = admin.Exec(ctx, "INSERT INTO custody_pool(id,store_id,revision,valid_until,byte_limit,object_limit) VALUES($1,$2,1,$3,$4,$5)", root, e.Registration.StoreID, valid, reserved, objects); err != nil {
				t.Fatal(err)
			}
			if err = ledger.ProvisionAllocation(ctx, capacity.StorageAllocation{ID: e.Registration.AllocationID, PoolID: root, ScopeID: custodyID(), ServiceClass: "evidence", PoolRevision: 1, Revision: 1, Bytes: reserved, Objects: objects, ValidUntil: valid}); err != nil {
				t.Fatal(err)
			}
			if _, err = ledger.RegisterStreaming(ctx, plan); err != nil {
				t.Fatal(err)
			}
			journal, writer = ledger, plan.WriterEpoch
		}
		producer, err := objectstore.NewArtifactProducer(bound, keys, journal, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := producer.Prepare(ctx, e, writer)
		if err != nil {
			t.Fatal("prepare", err)
		}
		started := e.TriggeredAt.Add(time.Second)
		copies, err := prepared.Store(ctx, bytes.NewReader(body), started, started.Add(time.Second))
		if err != nil {
			return nil, copies, err
		}
		if writer != "" {
			if err = ledger.StoreCopies(ctx, e.Registration, copies); err != nil {
				t.Fatal(err)
			}
			state, err := ledger.ReadStreaming(ctx, plan)
			if err != nil || state.Receipt == nil {
				t.Fatal("stream journal", err)
			}
			if err = privacy.ReleaseStreaming(ctx, plan, state, ledger, objectstore.StreamingObjects{Store: store}); err != nil {
				t.Fatal("temporary stream release", err)
			}
		}
		verifier, err := objectstore.NewContextVerifier(bound, keys)
		if err != nil {
			t.Fatal(err)
		}
		// The publisher's registration (internal/bootstrap/publisher.go).
		verifier.WithStreamCheck(artifact.PprofArtifact, func(artifact.ContextExpectation) objectstore.StreamCheck { return diagnostics.NewPprofCheck() })
		verifier.WithStreamCheck(artifact.GoTraceArtifact, func(artifact.ContextExpectation) objectstore.StreamCheck { return diagnostics.NewGoTraceCheck() })
		return verifier, copies, nil
	}
	readBack := func(t *testing.T, v *objectstore.ContextVerifier, e artifact.ContextExpectation, c artifact.Copies) ([]byte, artifact.NativeDownloadMetadata) {
		t.Helper()
		window, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		s, err := v.OpenNative(window, e, c, time.Now().Add(10*time.Second))
		if err != nil {
			t.Fatal("open native", err)
		}
		defer s.Close()
		m := s.Metadata()
		var out []byte
		for at := int64(0); at < m.Size; {
			n := min(artifact.DeliveryBytes, m.Size-at)
			b, _, err := s.ReadNext(window, at, n)
			if err != nil || int64(len(b)) != n {
				t.Fatal("read", at, err)
			}
			out = append(out, b...)
			at += n
		}
		return out, m
	}

	// 1. A heap profile as net/http/pprof serves it (debug=0).
	runtime.GC()
	var heap bytes.Buffer
	if err = pprof.Lookup("heap").WriteTo(&heap, 0); err != nil {
		t.Fatal(err)
	}
	e := expectation(artifact.GoProfileAcquisition{SourceRef: "synthetic-pprof", EndpointDigest: artifact.Digest{1}, Type: "heap", Mode: "snapshot"})
	v, copies, err := store1(t, e, heap.Bytes())
	if err != nil {
		t.Fatal("store pprof", err)
	}
	if _, err = v.VerifyContext(ctx, e, copies); err != nil {
		t.Fatal("pprof verification", err)
	}
	got, m := readBack(t, v, e, copies)
	if !bytes.Equal(got, heap.Bytes()) || m.Format != artifact.PprofFormat || m.Filename != "artifact-"+e.Registration.Location.ArtifactID+".pb.gz" || m.SHA256 != sha256.Sum256(heap.Bytes()) {
		t.Fatalf("pprof native bytes differ: %d/%d %+v", len(got), heap.Len(), m)
	}
	tool := "not run (no go toolchain)"
	if goBin, lookErr := exec.LookPath("go"); lookErr == nil {
		local := filepath.Join(t.TempDir(), m.Filename)
		if err = os.WriteFile(local, got, 0o600); err != nil {
			t.Fatal(err)
		}
		// Offline: no symbolization, no network.
		out, runErr := exec.CommandContext(ctx, goBin, "tool", "pprof", "-symbolize=none", "-top", local).CombinedOutput()
		if runErr != nil || !bytes.Contains(out, []byte("flat")) {
			t.Fatal("go tool pprof could not read the stored profile", runErr, string(out))
		}
		tool = "go tool pprof -top read it"
	}

	// 2. A gzip-valid profile with invalid contents: the producer stores it
	// (it does not parse), the publisher check refuses it.
	var bad bytes.Buffer
	w := gzip.NewWriter(&bad)
	_, _ = w.Write([]byte{0x12, 0x02, 0x08, 0x07, 0x22, 0x02, 0x08, 0x00}) // sample -> absent location
	_ = w.Close()
	e = expectation(artifact.GoProfileAcquisition{SourceRef: "synthetic-pprof", EndpointDigest: artifact.Digest{2}, Type: "cpu", Mode: "interval", DurationMillis: 10_000})
	v, copies, err = store1(t, e, bad.Bytes())
	if err != nil {
		t.Fatal("producer refused a gzip-valid stream", err)
	}
	if _, err = v.VerifyContext(ctx, e, copies); !errors.Is(err, artifact.ErrIntegrity) {
		t.Fatal("corrupted pprof verified", err)
	}
	// A stream that is not gzip never leaves the producer.
	e = expectation(artifact.GoProfileAcquisition{SourceRef: "synthetic-pprof", EndpointDigest: artifact.Digest{3}, Type: "cpu", Mode: "interval", DurationMillis: 10_000})
	if _, _, err = store1(t, e, []byte("<html>pprof disabled</html>")); err == nil {
		t.Fatal("producer stored a non-gzip pprof response")
	}

	// 3. An execution trace of this process.
	var tr bytes.Buffer
	if err = trace.Start(&tr); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	trace.Stop()
	e = expectation(artifact.GoProfileAcquisition{SourceRef: "synthetic-trace", EndpointDigest: artifact.Digest{4}, Type: "runtimeTrace", Mode: "interval", DurationMillis: 1000})
	v, copies, err = store1(t, e, tr.Bytes())
	if err != nil {
		t.Fatal("store trace", err)
	}
	if _, err = v.VerifyContext(ctx, e, copies); err != nil {
		t.Fatal("trace verification", err)
	}
	got, m = readBack(t, v, e, copies)
	if !bytes.Equal(got, tr.Bytes()) || m.Format != artifact.GoTraceFormat || m.Filename != "artifact-"+e.Registration.Location.ArtifactID+".trace" {
		t.Fatal("trace native bytes differ", len(got), tr.Len())
	}
	// A truncated trace with a valid header is refused by the publisher.
	e = expectation(artifact.GoProfileAcquisition{SourceRef: "synthetic-trace", EndpointDigest: artifact.Digest{5}, Type: "runtimeTrace", Mode: "interval", DurationMillis: 1000})
	if v, copies, err = store1(t, e, tr.Bytes()[:tr.Len()/2]); err != nil {
		t.Fatal("store truncated trace", err)
	}
	if _, err = v.VerifyContext(ctx, e, copies); !errors.Is(err, artifact.ErrIntegrity) {
		t.Fatal("truncated trace verified", err)
	}
	// A valid pprof larger than one storage frame exercises the real SQL
	// multipart journal and S3 decoder. The large synthetic symbol is raw data;
	// never print it. This is component evidence, not installed raw authority.
	t.Run("multi-frame pprof", func(t *testing.T) {
		encoded := multiFramePprofFixture(t)
		large := expectation(artifact.GoProfileAcquisition{SourceRef: "synthetic-large", EndpointDigest: artifact.Digest{6}, Type: "heap", Mode: "snapshot"})
		large.Registration.NativeLimit = 16 << 20
		verifier, copies, err := store1(t, large, encoded.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = verifier.VerifyContext(ctx, large, copies); err != nil {
			t.Fatal("large profile verification", err)
		}
		got, metadata := readBack(t, verifier, large, copies)
		source := evidence.NativeContextSource{Expectation: large, Copies: copies}
		if !source.Valid(evidence.ContextCopiesDigest(copies)) || !evidence.ValidNativeSourceMetadata(source, metadata) || !bytes.Equal(got, encoded.Bytes()) || metadata.SHA256 != sha256.Sum256(got) {
			t.Fatal("multi-frame profile bytes/metadata")
		}
		path := filepath.Join(t.TempDir(), metadata.Filename)
		if err = os.WriteFile(path, got, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, "go", "tool", "pprof", "-symbolize=none", "-top", "-nodecount=1", path)
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if err = cmd.Run(); err != nil {
			t.Fatal("local pprof opening", err)
		}
		t.Logf("multi-frame pprof stored with real SQL multipart journal, verified and downloaded: %d native bytes; local pprof opened", len(got))
	})

	t.Logf("ADR-284 profiles on real S3: %d-byte heap pprof and %d-byte execution trace stored, verified and read back byte-identical; %s; gzip-valid corrupted pprof and truncated trace refused by verification; non-gzip pprof refused by the producer", heap.Len(), tr.Len(), tool)
}

func multiFramePprofFixture(t *testing.T) *bytes.Buffer {
	t.Helper()

	name := make([]byte, 12<<20)
	if _, err := rand.Read(name); err != nil {
		t.Fatal(err)
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	for i := range name {
		name[i] = alphabet[name[i]&63]
	}
	fn := &profile.Function{ID: 1, Name: string(name)}
	loc := &profile.Location{ID: 1, Line: []profile.Line{{Function: fn}}}
	p := &profile.Profile{PeriodType: &profile.ValueType{Type: "space", Unit: "bytes"}, Period: 1, SampleType: []*profile.ValueType{{Type: "samples", Unit: "count"}}, Function: []*profile.Function{fn}, Location: []*profile.Location{loc}, Sample: []*profile.Sample{{Location: []*profile.Location{loc}, Value: []int64{1}}}}
	var encoded bytes.Buffer
	if err := p.Write(&encoded); err != nil {
		t.Fatal(err)
	}
	if encoded.Len() <= int(artifact.FrameBytes) {
		t.Fatal("fixture did not cross storage frame")
	}
	if err := diagnostics.CheckPprof(bytes.NewReader(encoded.Bytes())); err != nil {
		t.Fatal("generated fixture rejected", err)
	}
	return &encoded
}

func TestMultiFramePprofFixture(t *testing.T) {
	encoded := multiFramePprofFixture(t)
	if encoded.Len() <= int(artifact.FrameBytes) {
		t.Fatal("fixture is not multi-frame")
	}
}
