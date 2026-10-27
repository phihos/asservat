package integration

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
)

// qualifyRemoteNativeWindow is the ADR-248 component qualification of the
// regional worker's framed source on real S3: a synthetic PCAPNG save within
// the installed download bound (one 8 MiB frame) is stored and fully
// verified, opened once like a response window (OpenNative with the exact
// expectation) and read back as sequential 1 MiB delivery chunks, whole and
// resumed from inside a chunk. Its manifest facts equal the hub's
// expectation-derived metadata. Keys are synthetic; the worker, hub and SQL
// download ledger are not composed here.
func qualifyRemoteNativeWindow(t *testing.T, ctx context.Context, store *objectstore.Store) {
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
	now := time.Now().UTC().Truncate(time.Microsecond)
	t0 := now.Add(-20 * time.Second)
	started, completed := t0.Add(-30*time.Second), t0.Add(10*time.Second)
	digest := artifact.Digest(sha256.Sum256([]byte("synthetic remote native window")))
	e := artifact.ContextExpectation{
		NativeType: artifact.PCAPNGArtifact,
		Lifecycle:  &artifact.OngoingLifecycle{TriggerKind: "policy", SourceSessionID: custodyID(), SourceStartedAt: now.Add(-2 * time.Minute), SnapshotID: custodyID(), RequestedBefore: 30 * time.Second, After: 10 * time.Second, HistoryCoverage: "full", GapReasons: []string{}, WindowCoverage: "full"},
		Registration: artifact.Registration{Location: artifact.Location{ClusterID: custodyID(), ArtifactID: custodyID(), AttemptID: custodyID()}, StoreID: custodyID(), AllocationID: custodyID(), PoolRevision: 1, AllocationRevision: 1, NativeLimit: artifact.RemoteNativeLimit,
			AnchorAt: started, WriteUntil: now.Add(10 * time.Minute), ExpiresAt: started.Add(1800 * time.Second), DeleteBy: started.Add(2400 * time.Second)},
		CaseID: custodyID(), OccurrenceID: custodyID(), NodeUID: "synthetic-node-uid", NodeBootID: custodyID(), PodUID: "synthetic-pod-uid", Namespace: "synthetic", NamespaceUID: "synthetic-namespace-uid", WorkloadUID: "synthetic-workload-uid",
		CollectorVersion: "synthetic-test", CollectorImageDigest: digest, RecipeDigest: digest, PlanDigest: digest, CaptureUID: custodyID(), ActionID: "a0123456789abcdef01234567", DataClass: "metadata", PurposeRef: "synthetic-test",
		Audience:            []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://identity.example.invalid", SubjectID: "synthetic-team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding-uid", AssignmentID: custodyID(), BasisDigest: digest}},
		RequestedAgeSeconds: 1800, MaximumAgeSeconds: 7200, DeletionBudgetSeconds: 600, RetentionRules: []artifact.RetentionRule{{UID: "retention-uid", Generation: 1, Digest: digest}}, TriggeredAt: t0,
	}
	if err = e.Validate(); err != nil {
		t.Fatal("synthetic expectation", err)
	}
	path := filepath.Join(t.TempDir(), "synthetic.pcapng")
	size, sum := writeSyntheticPCAPNG(t, path, artifact.RemoteNativeLimit)
	body, err := os.ReadFile(path)
	if err != nil || int64(len(body)) != size || size <= 7*artifact.DeliveryBytes {
		t.Fatal("synthetic pcapng", err, size)
	}
	bound, err := store.ForCustody(e.Registration.StoreID)
	if err != nil {
		t.Fatal(err)
	}
	// One frame: the producer writes small objects and never uses the journal.
	producer, err := objectstore.NewArtifactProducer(bound, keys, unusedStreamingJournal{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := producer.Prepare(ctx, e, "")
	if err != nil {
		t.Fatal("prepare", err)
	}
	copies, err := prepared.Store(ctx, bytes.NewReader(body), started, completed)
	if err != nil {
		t.Fatal("store", err)
	}
	verifier, err := objectstore.NewContextVerifier(bound, keys)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifier.VerifyContext(ctx, e, copies); err != nil {
		t.Fatal("full verification", err)
	}
	source := evidence.NativeContextSource{Expectation: e, Copies: copies}
	if !source.Valid(evidence.ContextCopiesDigest(copies)) {
		t.Fatal("stored pcapng is not a downloadable native source")
	}
	read := func(from int64) ([]byte, int) {
		t.Helper()
		window, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		s, err := verifier.OpenNative(window, e, copies, time.Now().Add(5*time.Second))
		if err != nil {
			t.Fatal("open window", err)
		}
		defer s.Close()
		m := s.Metadata()
		if !evidence.ValidNativeSourceMetadata(source, m) || m.Size != size || m.SHA256 != sum || m.Filename != "artifact-"+e.Registration.Location.ArtifactID+".pcapng" || m.Format != artifact.PCAPNGFormat {
			t.Fatalf("manifest metadata differs from the hub expectation: %+v", m)
		}
		var out []byte
		chunks := 0
		for at := from; at < size; {
			n := min(artifact.DeliveryBytes, size-at)
			b, final, err := s.ReadNext(window, at, n)
			if err != nil || int64(len(b)) != n || at+n == size && !final {
				t.Fatal("chunk", at, err, final)
			}
			out = append(out, b...)
			clear(b)
			at += n
			chunks++
		}
		return out, chunks
	}
	whole, chunks := read(0)
	if !bytes.Equal(whole, body) || sha256.Sum256(whole) != sum || chunks != int((size+artifact.DeliveryBytes-1)/artifact.DeliveryBytes) {
		t.Fatal("whole window differs", len(whole), chunks)
	}
	from := int64(3*artifact.DeliveryBytes + 777)
	rest, _ := read(from)
	if !bytes.Equal(rest, body[from:]) {
		t.Fatal("resumed window differs", len(rest))
	}
	t.Logf("ADR-248 remote native window: %d-byte synthetic PCAPNG stored as one frame, verified, read as %d delivery chunks and resumed at %d on real S3", size, chunks, from)
}

// unusedStreamingJournal panics if a one-frame store ever needed the journal.
type unusedStreamingJournal struct{ privacy.StreamingJournal }
