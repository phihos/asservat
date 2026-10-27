package integration

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	mathrand "math/rand/v2"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/objectstore/manifest"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/browser"
	"github.com/jackc/pgx/v5/pgxpool"
)

// nativeArtifactBytes is the synthetic recording size (about 200 MiB) of the
// ADR-244 qualification: four 64 MiB accounting windows, 25 frames, 26 parts.
const nativeArtifactBytes = 200 << 20

// writeSyntheticPCAPNG writes a deterministic synthetic PCAPNG (one section,
// one Ethernet interface with a 128-byte snapshot length and 96-byte
// pseudo-random "header" records; no real traffic) of at most size bytes.
func writeSyntheticPCAPNG(t *testing.T, path string, size int64) (int64, artifact.Digest) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	w := bufio.NewWriterSize(io.MultiWriter(f, h), 1<<20)
	le := binary.LittleEndian
	shb := make([]byte, 28)
	le.PutUint32(shb, 0x0A0D0D0A)
	le.PutUint32(shb[4:], 28)
	le.PutUint32(shb[8:], 0x1A2B3C4D)
	le.PutUint16(shb[12:], 1)
	le.PutUint64(shb[16:], ^uint64(0)) // section length unspecified
	le.PutUint32(shb[24:], 28)
	idb := make([]byte, 20)
	le.PutUint32(idb, 1)
	le.PutUint32(idb[4:], 20)
	le.PutUint16(idb[8:], 1) // LINKTYPE_ETHERNET
	le.PutUint32(idb[12:], 128)
	le.PutUint32(idb[16:], 20)
	written := int64(len(shb) + len(idb))
	w.Write(shb)
	w.Write(idb)
	random := mathrand.NewChaCha8([32]byte{2, 4, 4})
	epb := make([]byte, 128)
	ts := uint64(1_800_000_000_000_000)
	for written+int64(len(epb)) <= size {
		le.PutUint32(epb, 6)
		le.PutUint32(epb[4:], 128)
		le.PutUint32(epb[8:], 0)
		le.PutUint32(epb[12:], uint32(ts>>32))
		le.PutUint32(epb[16:], uint32(ts))
		le.PutUint32(epb[20:], 96)
		le.PutUint32(epb[24:], 1500)
		_, _ = random.Read(epb[28:124])
		le.PutUint32(epb[124:], 128)
		if _, err = w.Write(epb); err != nil {
			t.Fatal(err)
		}
		written += int64(len(epb))
		ts += 10
	}
	if err = w.Flush(); err != nil {
		t.Fatal(err)
	}
	return written, artifact.Digest(h.Sum(nil))
}

// nativeDownloadLedger keeps one synthetic download session in memory and
// applies the real domain transitions (BeginResponse, BeginWindow, Lease,
// RecordWindow, AcknowledgeWindow). It stands in for the SQL session/window
// ledger, which qualifyDownloadResponses covers on real PostgreSQL; its
// identity and authority are synthetic test facts, never production access.
type nativeDownloadLedger struct {
	mu        sync.Mutex
	s         artifact.DownloadSession
	r         artifact.DownloadResponse
	w         artifact.DownloadWindow
	authority artifact.DownloadAuthority
	actor     identity.Identity
	windows   int
	store     string // window audit store
}

func newNativeDownloadLedger(e artifact.ContextExpectation, c artifact.Copies, auditStore string) *nativeDownloadLedger {
	now := time.Now().UTC()
	principal := identity.Principal{Issuer: "https://identity.example.invalid", Subject: "synthetic-developer", ClientID: "console", Kind: identity.Human}
	scope := artifact.DownloadScope{RootID: custodyID(), ArtifactID: e.Registration.Location.ArtifactID, CaptureID: e.CaptureUID, ClusterID: e.Registration.Location.ClusterID, NamespaceUID: e.NamespaceUID, WorkloadUID: e.WorkloadUID, PodUID: e.PodUID, Version: evidence.ContextCopiesDigest(c), Principal: principal}
	revision := identity.Revision{UID: "synthetic-policy", Generation: 1, Digest: [32]byte{9}}
	return &nativeDownloadLedger{
		s:         artifact.DownloadSession{ID: custodyID(), AllocationID: custodyID(), Scope: scope, RequestDigest: artifact.Digest{7}, State: artifact.DownloadReady, CreatedAt: now, Deadline: now.Add(30 * time.Minute), OutputLimit: 1 << 30, ReadLimit: 4 << 30, RequestLimit: 8, Requests: 1},
		authority: artifact.DownloadAuthority{Scope: scope, PermissionEpoch: custodyID(), PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: revision, AccessUntil: e.Registration.ExpiresAt, DeleteBy: e.Registration.DeleteBy},
		actor:     identity.Identity{Principal: principal, Policy: revision, Scopes: []string{"evidence:read", "evidence:download"}},
		store:     auditStore,
	}
}

type nativeTestBatch struct{ l *nativeDownloadLedger }

func (b nativeTestBatch) ResolveIdentity(context.Context) (identity.Identity, error) {
	i := b.l.actor
	i.VerifiedAt = time.Now()
	i.ValidUntil = i.VerifiedAt.Add(5 * time.Second)
	return i, nil
}
func (nativeTestBatch) Close() {}

func (l *nativeDownloadLedger) BeginBatch(context.Context) (identities.IdentityBatch, error) {
	return nativeTestBatch{l}, nil
}
func (l *nativeDownloadLedger) Close() {}
func (l *nativeDownloadLedger) CheckDownloadCurrent(ctx context.Context, b identities.CurrentIdentity, s artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	i, err := b.ResolveIdentity(ctx)
	if err != nil || s != l.authority.Scope {
		return artifact.DownloadAuthority{}, artifact.ErrDownloadUnavailable
	}
	a := l.authority
	a.CheckedAt, a.ValidUntil = time.Now(), i.ValidUntil
	return a, nil
}
func (l *nativeDownloadLedger) ReserveDownload(context.Context, evidence.DownloadReservation) (artifact.DownloadSession, error) {
	return artifact.DownloadSession{}, artifact.ErrDownloadUnavailable
}
func (l *nativeDownloadLedger) LookupDownload(_ context.Context, id string, p identity.Principal) (artifact.DownloadSession, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if id != l.s.ID || p != l.s.Scope.Principal {
		return artifact.DownloadSession{}, artifact.ErrDownloadUnavailable
	}
	return l.s, nil
}
func (l *nativeDownloadLedger) BeginDownloadBatch(context.Context, string, artifact.DownloadAuthority, artifact.DownloadBatch) (audit.DownloadIntent, error) {
	return audit.DownloadIntent{}, artifact.ErrDownloadUnavailable
}
func (l *nativeDownloadLedger) PermitDownloadBatch(context.Context, string, artifact.DownloadAuthority, string, int64) error {
	return artifact.ErrDownloadUnavailable
}
func (l *nativeDownloadLedger) PermitDownloadMetadata(context.Context, string, artifact.DownloadAuthority, string, int64) error {
	return artifact.ErrDownloadUnavailable
}
func (l *nativeDownloadLedger) FinishDownloadBatch(context.Context, string, string, int64, int64, bool, bool) (audit.DownloadOutcome, error) {
	return audit.DownloadOutcome{}, artifact.ErrDownloadUnavailable
}
func (l *nativeDownloadLedger) CancelDownload(context.Context, string, identity.Principal) (artifact.DownloadSession, error) {
	return artifact.DownloadSession{}, artifact.ErrDownloadUnavailable
}
func (l *nativeDownloadLedger) BeginDownloadResponse(_ context.Context, _ string, a artifact.DownloadAuthority, r artifact.DownloadResponse) (artifact.DownloadResponse, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var err error
	l.s, l.r, err = l.s.BeginResponse(a, r, time.Now())
	return l.r, err
}
func (l *nativeDownloadLedger) BeginDownloadWindow(_ context.Context, _, _, _, id string, a artifact.DownloadAuthority) (audit.DownloadWindowIntent, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var err error
	l.s, l.r, l.w, err = l.r.BeginWindow(l.s, a, id, l.store, l.s.Deadline.Add(time.Minute), time.Now())
	l.windows++
	return audit.DownloadWindowIntent{Response: l.r, Window: l.w}, err
}
func (l *nativeDownloadLedger) LeaseDownloadResponse(_ context.Context, _, _, _, _ string, a artifact.DownloadAuthority) (artifact.DownloadDeliveryLease, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var lease artifact.DownloadDeliveryLease
	var err error
	l.r, lease, err = l.r.Lease(l.s, l.w, a, l.r.OwnerID, time.Now())
	return lease, err
}
func (l *nativeDownloadLedger) FinishDownloadWindow(_ context.Context, i audit.DownloadWindowIntent, o artifact.DownloadWindowOutcome) (audit.DownloadWindowAuditOutcome, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var err error
	if l.s, l.r, l.w, err = l.r.RecordWindow(l.s, l.w, o, time.Now()); err != nil {
		return audit.DownloadWindowAuditOutcome{}, err
	}
	return audit.DownloadWindowAuditOutcome{Intent: i, Outcome: *l.w.Outcome}, nil
}
func (l *nativeDownloadLedger) CloseDownloadResponse(context.Context, string, string, string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.r.Closed = true
	return nil
}
func (l *nativeDownloadLedger) AcknowledgeDownloadWindowIntent(_ context.Context, i audit.DownloadWindowIntent, result audit.DownloadWindowWriteResult) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !result.Receipt.ValidDownloadWindow(i, "intent") {
		return artifact.ErrIntegrity
	}
	l.w.IntentAcknowledged = true
	return nil
}
func (l *nativeDownloadLedger) AcknowledgeDownloadWindowOutcome(_ context.Context, _ audit.DownloadWindowAuditOutcome, _ audit.DownloadWindowWriteResult) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var err error
	l.s, l.r, l.w, err = l.r.AcknowledgeWindow(l.s, l.w, time.Now())
	return err
}
func (l *nativeDownloadLedger) state() (artifact.DownloadState, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.s.State, l.windows
}

// qualifyNativeArtifacts is the ADR-244 component qualification on real
// PostgreSQL (streaming custody journal, charges, StoreCopies) and real S3
// (multipart data, small index/manifest/commit, encrypted window audit):
// a synthetic ~200 MiB PCAPNG ongoing save is stored, fully verified against
// its independent manifest provenance and downloaded natively over TLS, whole
// and interrupted plus resumed with Range/If-Match. Keys, identity, authority
// and the session ledger are synthetic; this is not an installed download.
func qualifyNativeArtifacts(t *testing.T, ctx context.Context, admin *pgxpool.Pool, ledger *postgres.Ledger, store *objectstore.Store, charge func(*testing.T, string) (int64, int64)) {
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
	storeID, root, allocation := custodyID(), custodyID(), custodyID()
	digest := artifact.Digest(sha256.Sum256([]byte("synthetic native artifact")))
	e := artifact.ContextExpectation{
		NativeType: artifact.PCAPNGArtifact,
		Lifecycle:  &artifact.OngoingLifecycle{TriggerKind: "policy", SourceSessionID: custodyID(), SourceStartedAt: now.Add(-2 * time.Minute), SnapshotID: custodyID(), RequestedBefore: 30 * time.Second, After: 10 * time.Second, HistoryCoverage: "full", GapReasons: []string{}, WindowCoverage: "full"},
		Registration: artifact.Registration{Location: artifact.Location{ClusterID: custodyID(), ArtifactID: custodyID(), AttemptID: custodyID()}, StoreID: storeID, AllocationID: allocation, PoolRevision: 1, AllocationRevision: 1, NativeLimit: artifact.StreamingNativeLimit,
			AnchorAt: started, WriteUntil: now.Add(10 * time.Minute), ExpiresAt: started.Add(1800 * time.Second), DeleteBy: started.Add(2400 * time.Second)},
		CaseID: custodyID(), OccurrenceID: custodyID(), NodeUID: "synthetic-node-uid", NodeBootID: custodyID(), PodUID: "synthetic-pod-uid", Namespace: "synthetic", NamespaceUID: "synthetic-namespace-uid", WorkloadUID: "synthetic-workload-uid",
		CollectorVersion: "synthetic-test", CollectorImageDigest: digest, RecipeDigest: digest, PlanDigest: digest, CaptureUID: custodyID(), ActionID: "a0123456789abcdef01234567", DataClass: "metadata", PurposeRef: "synthetic-test",
		Audience:            []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://identity.example.invalid", SubjectID: "synthetic-team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: "binding-uid", AssignmentID: custodyID(), BasisDigest: digest}},
		RequestedAgeSeconds: 1800, MaximumAgeSeconds: 7200, DeletionBudgetSeconds: 600, RetentionRules: []artifact.RetentionRule{{UID: "retention-uid", Generation: 1, Digest: digest}}, TriggeredAt: t0,
	}
	if err = e.Validate(); err != nil {
		t.Fatal("synthetic expectation", err)
	}
	plan := artifact.StreamingPlan{Registration: e.Registration, WriterEpoch: custodyID()}
	bytesPer, objectsPer := plan.Registration.ReservedBytes()+plan.TemporaryBytes(), int64(4+1+plan.PartLimit())
	if plan.PartLimit() != artifact.StreamingMaxParts {
		t.Fatal("256 MiB plan part count", plan.PartLimit())
	}
	valid := now.Add(time.Hour)
	if _, err = admin.Exec(ctx, "INSERT INTO custody_pool(id,store_id,revision,valid_until,byte_limit,object_limit) VALUES($1,$2,1,$3,$4,$5)", root, storeID, valid, 2*bytesPer, 2*objectsPer); err != nil { // two attempts
		t.Fatal(err)
	}
	if err = ledger.ProvisionAllocation(ctx, capacity.StorageAllocation{ID: allocation, PoolID: root, ScopeID: custodyID(), ServiceClass: "evidence", PoolRevision: 1, Revision: 1, Bytes: bytesPer, Objects: objectsPer, ValidUntil: valid}); err != nil {
		t.Fatal(err)
	}
	// Migration 00097: the 256 MiB attempt and its 34 temporary objects fit.
	if _, err = ledger.RegisterStreaming(ctx, plan); err != nil {
		t.Fatal("256 MiB streaming registration", err)
	}
	if b, o := charge(t, allocation); b != bytesPer || o != objectsPer {
		t.Fatal("final and temporary obligations", b, o, bytesPer, objectsPer)
	}
	path := filepath.Join(t.TempDir(), "synthetic.pcapng")
	size, sum := writeSyntheticPCAPNG(t, path, nativeArtifactBytes)
	bound, err := store.ForCustody(storeID)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := objectstore.NewArtifactProducer(bound, keys, ledger, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := producer.Prepare(ctx, e, plan.WriterEpoch)
	if err != nil {
		t.Fatal("prepare", err)
	}
	src, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	begin := time.Now()
	copies, err := prepared.Store(ctx, src, started, completed)
	src.Close()
	if err != nil {
		t.Fatal("store", err)
	}
	stored := time.Since(begin)
	if err = ledger.StoreCopies(ctx, e.Registration, copies); err != nil {
		t.Fatal("stored_unpublished", err)
	}
	state, err := ledger.ReadStreaming(ctx, plan)
	if err != nil || state.Receipt == nil || len(state.Parts) != int((copies[0].Bytes+artifact.StreamingPartBytes-1)/artifact.StreamingPartBytes) {
		t.Fatal("journal", err, len(state.Parts))
	}
	if err = privacy.ReleaseStreaming(ctx, plan, state, ledger, objectstore.StreamingObjects{Store: store}); err != nil {
		t.Fatal("temporary release", err)
	}
	if b, o := charge(t, allocation); b != plan.Registration.ReservedBytes() || o != 4 {
		t.Fatal("temporary obligation not released", b, o)
	}

	verifier, err := objectstore.NewContextVerifier(bound, keys)
	if err != nil {
		t.Fatal(err)
	}
	begin = time.Now()
	if err = verifier.VerifyContext(ctx, e, copies); err != nil {
		t.Fatal("full verification", err)
	}
	verified := time.Since(begin)
	// The manifest provenance must equal the independent expectation exactly.
	for name, change := range map[string]func(*artifact.ContextExpectation){
		"snapshot":        func(x *artifact.ContextExpectation) { x.Lifecycle.SnapshotID = custodyID() },
		"source session":  func(x *artifact.ContextExpectation) { x.Lifecycle.SourceSessionID = custodyID() },
		"window coverage": func(x *artifact.ContextExpectation) { x.Lifecycle.WindowCoverage = "partial" },
		"source stopped":  func(x *artifact.ContextExpectation) { x.Lifecycle.SourceStoppedAt = completed },
		"onTrigger":       func(x *artifact.ContextExpectation) { x.Lifecycle = nil; x.TriggeredAt = started },
		"syscall type":    func(x *artifact.ContextExpectation) { x.NativeType = artifact.SyscallRecordsArtifact },
		"http as pcap": func(x *artifact.ContextExpectation) {
			x.NativeType = artifact.HTTPHeadersArtifact
			x.Registration.NativeLimit = artifact.HTTPHeadersNativeLimit
		},
	} {
		x := e
		x.Lifecycle = e.Lifecycle.Clone()
		change(&x)
		if x.Validate() != nil {
			t.Fatal("mutated expectation invalid before verification", name)
		}
		if err = verifier.VerifyContext(ctx, x, copies); err == nil {
			t.Fatal("verification accepted a changed expectation", name)
		}
	}

	// Native download through the windowed transfer and the real HTTP sink.
	audits, err := objectstore.NewDownloadWindowAuditObjects(store, storeID, keys, keys)
	if err != nil {
		t.Fatal(err)
	}
	var current *nativeDownloadLedger
	done := make(chan error, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := current
		source, err := verifier.OpenNative(r.Context(), e, copies, time.Now().Add(time.Hour))
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			done <- err
			return
		}
		transfer := evidence.DownloadResponseTransfer{Sessions: l, Responses: l, Authority: l, Objects: audits, Audit: l, Now: time.Now, NewID: custodyID}
		sinks := &nativeTestSinks{HTTPDownloadResponseFactory: browser.HTTPDownloadResponseFactory{Writer: w, Request: r}}
		err = transfer.Transfer(r.Context(), l, evidence.DownloadResponseRequest{SessionID: l.s.ID, ResponseID: custodyID(), OwnerID: custodyID(), HardUntil: time.Now().Add(10 * time.Minute)}, source, sinks)
		if err != nil && !sinks.opened {
			w.WriteHeader(browser.DownloadConditionStatus(err))
		}
		var fixed interface{ FixedStep() string }
		if errors.As(err, &fixed) {
			err = fmt.Errorf("stage %s: %w", fixed.FixedStep(), err)
		}
		done <- err
	}))
	defer server.Close()
	client := server.Client()
	client.Transport.(*http.Transport).DisableCompression = true
	get := func(header http.Header) *http.Response {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/content", nil)
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range header {
			req.Header[k] = v
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	wait := func() error {
		t.Helper()
		select {
		case err := <-done:
			return err
		case <-time.After(2 * time.Minute):
			t.Fatal("download handler did not finish")
		}
		return nil
	}
	filename := "artifact-" + e.Registration.Location.ArtifactID + ".pcapng"
	etag := evidence.NativeETag(evidence.ContextCopiesDigest(copies))
	checkHeaders := func(resp *http.Response, status int, length int64) {
		t.Helper()
		_, params, _ := mime.ParseMediaType(resp.Header.Get("Content-Disposition"))
		if resp.StatusCode != status || resp.ContentLength != length || resp.Header.Get("Content-Type") != "application/octet-stream" || params["filename"] != filename || resp.Header.Get("ETag") != etag || resp.Header.Get("Accept-Ranges") != "bytes" || resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Content-Encoding") != "" {
			t.Fatal("native response headers", resp.StatusCode, resp.ContentLength, resp.Header)
		}
	}

	// 1. Whole file: four windows, whole-file hash verified before the last bytes.
	current = newNativeDownloadLedger(e, copies, storeID)
	begin = time.Now()
	resp := get(nil)
	checkHeaders(resp, http.StatusOK, size)
	h := sha256.New()
	n, err := io.Copy(h, resp.Body)
	resp.Body.Close()
	if err != nil || n != size || artifact.Digest(h.Sum(nil)) != sum {
		t.Fatal("whole native file", n, err, "server:", wait())
	}
	if err = wait(); err != nil {
		t.Fatal("whole transfer", err)
	}
	whole := time.Since(begin)
	if s, windows := current.state(); s != artifact.DownloadCompleted || windows != 4 {
		t.Fatal("whole-file session", s, windows)
	}

	// 2. Interrupted after 70 MiB (inside window 2), resumed with Range and the
	// strong If-Match ETag; the assembled local file matches the full hash.
	current = newNativeDownloadLedger(e, copies, storeID)
	local := filepath.Join(t.TempDir(), filename)
	out, err := os.Create(local)
	if err != nil {
		t.Fatal(err)
	}
	resp = get(nil)
	checkHeaders(resp, http.StatusOK, size)
	partial, err := io.CopyN(out, resp.Body, 70<<20)
	resp.Body.Close()
	if err != nil || partial != 70<<20 {
		t.Fatal("partial read", partial, err)
	}
	if err = wait(); err == nil {
		t.Fatal("interrupted transfer reported success")
	}
	if s, _ := current.state(); s == artifact.DownloadCompleted {
		t.Fatal("interrupted session completed")
	}
	resp = get(http.Header{"Range": {"bytes=" + strconv.FormatInt(partial, 10) + "-"}, "If-Match": {etag}})
	checkHeaders(resp, http.StatusPartialContent, size-partial)
	if resp.Header.Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", partial, size-1, size) {
		t.Fatal("content range", resp.Header.Get("Content-Range"))
	}
	rest, err := io.Copy(out, resp.Body)
	resp.Body.Close()
	if err != nil || rest != size-partial {
		t.Fatal("resumed range", rest, err)
	}
	if err = wait(); err != nil {
		t.Fatal("resumed transfer", err)
	}
	if err = out.Close(); err != nil {
		t.Fatal(err)
	}
	if got := fileSHA256(t, local); got != sum {
		t.Fatal("resumed file hash", hex.EncodeToString(got[:]))
	}
	// The assembled file is structurally valid PCAPNG (same check as storage).
	contracts, err := manifest.New()
	if err != nil {
		t.Fatal(err)
	}
	check, err := contracts.NativeCheck(e, manifest.ContextManifest{StartedAt: started, CompletedAt: completed})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(local)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1<<20)
	for {
		k, readErr := f.Read(buf)
		if k > 0 {
			if err = check.Write(buf[:k]); err != nil {
				t.Fatal("downloaded PCAPNG structure", err)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
	}
	f.Close()
	if err = check.Close(); err != nil {
		t.Fatal("downloaded PCAPNG end", err)
	}
	// Where Wireshark's CLI is installed, it must open the downloaded file
	// (an offline read; nothing is captured).
	if tshark, lookErr := exec.LookPath("tshark"); lookErr == nil {
		if output, runErr := exec.CommandContext(ctx, tshark, "-n", "-r", local, "-c", "10").CombinedOutput(); runErr != nil {
			t.Fatal("tshark could not read the downloaded PCAPNG", runErr, string(output))
		}
		t.Log("tshark -r read the downloaded PCAPNG")
	} else {
		t.Log("tshark not installed: structural PCAPNG check only")
	}

	// 3. Conditional refusals before any byte: changed version, unsatisfiable range.
	current = newNativeDownloadLedger(e, copies, storeID)
	resp = get(http.Header{"Range": {"bytes=100-"}, "If-Match": {`"v1-0000"`}})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusPreconditionFailed || len(body) != 0 {
		t.Fatal("If-Match mismatch", resp.StatusCode, len(body))
	}
	if err = wait(); err == nil {
		t.Fatal("refused precondition reported success")
	}
	resp = get(http.Header{"Range": {"bytes=" + strconv.FormatInt(size, 10) + "-"}})
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Fatal("unsatisfiable range", resp.StatusCode)
	}
	_ = wait()
	// 4. If-Range with another version falls back to a full, fully charged 200.
	resp = get(http.Header{"Range": {"bytes=100-"}, "If-Range": {`"v1-0000"`}})
	checkHeaders(resp, http.StatusOK, size)
	resp.Body.Close()
	_ = wait()
	if _, ok := artifact.NativeTypeForFormat(artifact.PCAPNGFormat); !ok {
		t.Fatal("format registry")
	}

	// 5. The ADR-166 path at its new ceiling: a worst-case incompressible
	// 256 MiB attempt fills all 33 parts, completes create-only, is reread in
	// full and releases its temporary charge exactly.
	maxPlan := artifact.StreamingPlan{Registration: e.Registration, WriterEpoch: custodyID()}
	maxPlan.Registration.Location = artifact.Location{ClusterID: custodyID(), ArtifactID: custodyID(), AttemptID: custodyID()}
	maxAllocation := custodyID()
	maxPlan.Registration.AllocationID = maxAllocation
	if err = ledger.ProvisionAllocation(ctx, capacity.StorageAllocation{ID: maxAllocation, PoolID: root, ScopeID: custodyID(), ServiceClass: "evidence", PoolRevision: 1, Revision: 1, Bytes: bytesPer, Objects: objectsPer, ValidUntil: valid}); err != nil {
		t.Fatal(err)
	}
	if _, err = ledger.RegisterStreaming(ctx, maxPlan); err != nil {
		t.Fatal(err)
	}
	writer, err := privacy.NewStreamingWriter(ctx, maxPlan, ledger, objectstore.StreamingObjects{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	random := mathrand.NewChaCha8([32]byte{2, 5, 6})
	chunk := make([]byte, 3<<20) // unrelated to the part size
	for left := maxPlan.TemporaryBytes(); left > 0; {
		k := min(int64(len(chunk)), left)
		_, _ = random.Read(chunk[:k])
		if err = writer.Write(ctx, chunk[:k]); err != nil {
			t.Fatal("worst-case write", err)
		}
		left -= k
	}
	if _, err = writer.Finish(ctx); err != nil {
		t.Fatal("worst-case completion", err)
	}
	maxState, err := ledger.ReadStreaming(ctx, maxPlan)
	if err != nil || maxState.Receipt == nil || len(maxState.Parts) != artifact.StreamingMaxParts || maxState.CompleteBytes != maxPlan.TemporaryBytes() {
		t.Fatal("33-part journal", err, len(maxState.Parts))
	}
	if err = privacy.ReleaseStreaming(ctx, maxPlan, maxState, ledger, objectstore.StreamingObjects{Store: store}); err != nil {
		t.Fatal("worst-case release", err)
	}
	if b, o := charge(t, maxAllocation); b != maxPlan.Registration.ReservedBytes() || o != 4 {
		t.Fatal("worst-case temporary obligation", b, o)
	}
	t.Logf("ADR-244 native artifact: %d-byte synthetic PCAPNG in %d parts; store %s, full verification %s, whole native download %s (4 windows), interrupted at %d bytes and resumed with Range/If-Match to the identical SHA-256; If-Match/416/If-Range conditions; worst-case 256 MiB attempt in %d parts on real PostgreSQL/S3", size, len(state.Parts), stored.Round(time.Millisecond), verified.Round(time.Millisecond), whole.Round(time.Millisecond), partial, len(maxState.Parts))
}

// nativeTestSinks records whether the response sink was opened, so a refusal
// before any header can still answer with its conditional status.
type nativeTestSinks struct {
	browser.HTTPDownloadResponseFactory
	opened bool
}

func (s *nativeTestSinks) OpenDownloadResponse(ctx context.Context, m artifact.NativeDownloadMetadata, r artifact.DownloadResponse) (evidence.DownloadResponseSink, error) {
	s.opened = true
	return s.HTTPDownloadResponseFactory.OpenDownloadResponse(ctx, m, r)
}

func fileSHA256(t *testing.T, path string) artifact.Digest {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var h hash.Hash = sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return artifact.Digest(h.Sum(nil))
}
