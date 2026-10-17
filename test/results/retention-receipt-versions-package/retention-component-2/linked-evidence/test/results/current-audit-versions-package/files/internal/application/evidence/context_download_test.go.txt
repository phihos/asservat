package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"
)

type downloadWorkerFixture struct {
	s                 artifact.DownloadSession
	a                 artifact.DownloadAuthority
	now               time.Time
	i                 audit.DownloadIntent
	o                 audit.DownloadOutcome
	body, delivered   []byte
	failure           string
	calls             []string
	gateCalls, denyAt int
	shortenAt         int
	sentUntil         time.Time
	sentMetadata      DownloadMetadata
	nativeBacking     []byte
}

func (f *downloadWorkerFixture) step(name string) error {
	f.calls = append(f.calls, name)
	if f.failure == name {
		return artifact.ErrDownloadUnavailable
	}
	return nil
}
func (f *downloadWorkerFixture) CheckDownload(_ context.Context, _ string, scope artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	f.gateCalls++
	if f.shortenAt > 0 && f.gateCalls >= f.shortenAt {
		f.a.AccessUntil = f.now.Add(2 * time.Second)
		f.a.ValidUntil = f.a.AccessUntil
		f.a.DeleteBy = f.now.Add(30 * time.Second)
	}
	err := f.step("authority")
	if scope != f.a.Scope || f.gateCalls == f.denyAt {
		err = artifact.ErrDownloadExpired
	}
	return f.a, err
}
func (f *downloadWorkerFixture) ReserveDownload(context.Context, DownloadReservation) (artifact.DownloadSession, error) {
	panic("not used")
}
func (f *downloadWorkerFixture) LookupDownload(context.Context, string, identity.Principal) (artifact.DownloadSession, error) {
	return f.s, nil
}
func (f *downloadWorkerFixture) CancelDownload(context.Context, string, identity.Principal) (artifact.DownloadSession, error) {
	panic("not used")
}
func (f *downloadWorkerFixture) BeginDownloadBatch(_ context.Context, id string, a artifact.DownloadAuthority, b artifact.DownloadBatch) (audit.DownloadIntent, error) {
	if err := f.step("begin"); err != nil {
		return audit.DownloadIntent{}, err
	}
	s, err := f.s.Start(a, b, f.now)
	if err != nil {
		return audit.DownloadIntent{}, err
	}
	f.s = s
	f.i = audit.DownloadIntent{SessionID: id, Batch: *s.Active}
	return f.i, nil
}
func (f *downloadWorkerFixture) PermitDownloadBatch(_ context.Context, _ string, a artifact.DownloadAuthority, id string, g int64) error {
	if err := f.step("permit"); err != nil {
		return err
	}
	return f.s.Permit(a, id, g, f.now)
}
func (f *downloadWorkerFixture) PermitDownloadMetadata(context.Context, string, artifact.DownloadAuthority, string, int64) error {
	return f.step("metadata-permit")
}
func (f *downloadWorkerFixture) FinishDownloadBatch(_ context.Context, _ string, b string, g, n int64, success, full bool) (audit.DownloadOutcome, error) {
	if err := f.step("finish"); err != nil {
		return audit.DownloadOutcome{}, err
	}
	before := f.s.State
	s, err := f.s.Finish(b, g, n, success, full, f.now)
	if err != nil {
		return audit.DownloadOutcome{}, err
	}
	f.s = s
	f.s.State = before
	f.o = audit.DownloadOutcome{Intent: f.i, EmittedBytes: n, Success: success, FullFile: full, RecordedAt: f.now}
	return f.o, nil
}
func (f *downloadWorkerFixture) receipt(phase string) audit.Receipt {
	return audit.Receipt{Key: audit.DownloadAuditKey(f.s.Scope.RootID, f.s.ID, f.i.Batch.ID, phase), Version: "synthetic-original-version", ETag: "synthetic", Bytes: 128, SHA256: artifact.Digest{8}}
}
func (f *downloadWorkerFixture) WriteDownloadIntent(context.Context, audit.DownloadIntent) (audit.Receipt, error) {
	return f.receipt("intent"), f.step("intent")
}
func (f *downloadWorkerFixture) WriteDownloadOutcome(context.Context, audit.DownloadOutcome) (audit.Receipt, error) {
	return f.receipt("outcome"), f.step("outcome")
}
func (f *downloadWorkerFixture) AcknowledgeDownloadIntent(context.Context, audit.DownloadIntent, audit.Receipt) error {
	if err := f.step("intent-ack"); err != nil {
		return err
	}
	f.s.Active.AuditAcknowledged = true
	return nil
}
func (f *downloadWorkerFixture) AcknowledgeDownloadOutcome(context.Context, audit.DownloadOutcome, audit.Receipt) error {
	if err := f.step("outcome-ack"); err != nil {
		return err
	}
	if f.o.Success {
		if f.o.Intent.Batch.Purpose == artifact.DownloadMetadata {
			f.s.State = artifact.DownloadReady
		} else if f.o.FullFile {
			f.s.State = artifact.DownloadCompleted
		} else {
			f.s.State = artifact.DownloadInterrupted
		}
	}
	return nil
}
func (f *downloadWorkerFixture) ReadContext(context.Context, artifact.ContextExpectation, artifact.Copies, time.Time) ([]byte, error) {
	if err := f.step("native"); err != nil {
		return nil, err
	}
	f.nativeBacking = bytes.Clone(f.body)
	return f.nativeBacking, nil
}
func (f *downloadWorkerFixture) Send(ctx context.Context, m DownloadMetadata, s DownloadSelection, b []byte) (int64, error) {
	if err := f.step("send"); err != nil {
		f.delivered = bytes.Clone(b[:1])
		return 1, err
	}
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if m.SHA256 != sha256.Sum256(f.body) || s.Length != int64(len(b)) {
		return 0, artifact.ErrIntegrity
	}
	f.sentUntil, _ = ctx.Deadline()
	f.sentMetadata = m
	f.delivered = bytes.Clone(b)
	return int64(len(b)), nil
}
func downloadWorkerTest(t *testing.T) (*downloadWorkerFixture, ContextDownloadWorker, ContextDownloadRequest) {
	p, _ := publicationTest(t)
	id := p.e.CaptureUID
	scope := artifact.DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: p.e.NamespaceUID, WorkloadUID: p.e.WorkloadUID, PodUID: p.e.PodUID, Version: ContextCopiesDigest(p.copies), Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}}
	f := &downloadWorkerFixture{now: p.now, body: []byte("synthetic approved native context")}
	f.a = artifact.DownloadAuthority{Scope: scope, PermissionEpoch: id, PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{3}}, CheckedAt: p.now, ValidUntil: p.now.Add(5 * time.Second), AccessUntil: p.e.Registration.ExpiresAt, DeleteBy: p.e.Registration.DeleteBy}
	f.s = artifact.DownloadSession{ID: id, AllocationID: id, Scope: scope, RequestDigest: artifact.Digest{7}, State: artifact.DownloadPreparing, CreatedAt: p.now, Deadline: p.now.Add(time.Minute), OutputLimit: 8192, ReadLimit: 16 << 20, RequestLimit: 4}
	r := ContextDownloadRequest{SessionID: id, Scope: scope, Expectation: p.e, Copies: p.copies}
	w := ContextDownloadWorker{Sessions: f, AuditAcknowledgements: f, Audit: f, Authority: f, Native: f, Now: func() time.Time { return f.now }, NewID: func() string { return "22222222-2222-4222-8222-222222222222" }}
	return f, w, r
}
func TestContextDownloadComposedOrderAndClearBuffers(t *testing.T) {
	f, w, r := downloadWorkerTest(t)
	m, err := w.Prepare(context.Background(), "synthetic", r)
	if err != nil || m.Size != int64(len(f.body)) || m.SHA256 != sha256.Sum256(f.body) || m.ETag == "" || f.s.State != artifact.DownloadReady {
		t.Fatal(m, err)
	}
	if !slices.Equal(f.calls, []string{"authority", "begin", "intent", "intent-ack", "authority", "permit", "native", "authority", "permit", "finish", "outcome", "outcome-ack", "authority", "metadata-permit"}) {
		t.Fatal(f.calls)
	}
	if !bytes.Equal(f.nativeBacking, make([]byte, len(f.body))) {
		t.Fatal("plaintext kept after metadata")
	}
	f.calls = nil
	if err = w.Transfer(context.Background(), "synthetic", r, DownloadSelection{Length: m.Size}, f); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.delivered, f.body) || f.s.State != artifact.DownloadCompleted || f.s.ChargedRead != 8<<20 || f.s.EmittedBytes != m.Size {
		t.Fatal("wrong transfer outcome")
	}
	if !bytes.Equal(f.nativeBacking, make([]byte, len(f.body))) {
		t.Fatal("plaintext kept after delivery")
	}
}
func TestContextDownloadFailuresNeverBypassAuditOrReauthorizeLate(t *testing.T) {
	for _, stage := range []string{"authority", "begin", "intent", "intent-ack", "permit", "native", "finish", "outcome", "outcome-ack", "metadata-permit"} {
		t.Run(stage, func(t *testing.T) {
			f, w, r := downloadWorkerTest(t)
			f.failure = stage
			m, err := w.Prepare(context.Background(), "synthetic", r)
			if err == nil || m != (DownloadMetadata{}) {
				t.Fatal("failed preparation disclosed metadata", m, err)
			}
			if len(f.delivered) != 0 {
				t.Fatal("metadata emitted file")
			}
			if stage == "intent" || stage == "intent-ack" || stage == "permit" {
				if slices.Contains(f.calls, "native") {
					t.Fatal("read before permit")
				}
			}
			if !bytes.Equal(f.nativeBacking, make([]byte, len(f.nativeBacking))) {
				t.Fatal("failure retained plaintext")
			}
		})
	}
	for _, deniedAt := range []int{2, 3, 4} {
		t.Run("current-decision-loss", func(t *testing.T) {
			f, w, r := downloadWorkerTest(t)
			f.denyAt = deniedAt
			if m, err := w.Prepare(context.Background(), "synthetic", r); err == nil || m != (DownloadMetadata{}) {
				t.Fatal("stale decision")
			}
		})
	}
}
func TestContextDownloadShortAndFailedOutputRemainCharged(t *testing.T) {
	f, w, r := downloadWorkerTest(t)
	f.s.State = artifact.DownloadReady
	f.failure = "send"
	if err := w.Transfer(context.Background(), "synthetic", r, DownloadSelection{Length: int64(len(f.body))}, f); err == nil {
		t.Fatal("failed send succeeded")
	}
	if f.s.ChargedOutput != int64(len(f.body)) || f.s.EmittedBytes != 1 || f.o.Success {
		t.Fatal("short send refunded/claimed completion")
	}
	f, w, r = downloadWorkerTest(t)
	f.s.State = artifact.DownloadReady
	f.denyAt = 3
	if err := w.Transfer(context.Background(), "synthetic", r, DownloadSelection{Length: int64(len(f.body))}, f); !errors.Is(err, artifact.ErrDownloadExpired) || len(f.delivered) != 0 {
		t.Fatal("authority lost after native read", err)
	}
	f, w, r = downloadWorkerTest(t)
	f.s.State = artifact.DownloadReady
	if err := w.Transfer(context.Background(), "synthetic", r, DownloadSelection{Offset: 2, Length: 3, Partial: true}, f); err != nil || string(f.delivered) != string(f.body[2:5]) || f.s.State != artifact.DownloadInterrupted {
		t.Fatal("partial response", err)
	}
}

func TestDownloadUsesShortenedMetadataAndIODeadline(t *testing.T) {
	f, w, r := downloadWorkerTest(t)
	f.shortenAt = 3
	m, err := w.Prepare(context.Background(), "synthetic", r)
	if err != nil || !m.ReadUntil.Equal(f.now.Add(2*time.Second)) || !m.DeleteBy.Equal(f.now.Add(30*time.Second)) {
		t.Fatal("stale privacy notice", m, err)
	}
	f, w, r = downloadWorkerTest(t)
	f.s.State = artifact.DownloadReady
	f.shortenAt = 3
	if err = w.Transfer(context.Background(), "synthetic", r, DownloadSelection{Length: int64(len(f.body))}, f); err != nil {
		t.Fatal(err)
	}
	if !f.sentUntil.Equal(f.now.Add(2*time.Second)) || f.sentMetadata.ReadUntil != f.a.AccessUntil || f.sentMetadata.DeleteBy != f.a.DeleteBy {
		t.Fatal("old effect lease survived stricter cutoff")
	}
	f, w, r = downloadWorkerTest(t)
	f.a.DeleteBy = time.Time{}
	if _, err = w.Prepare(context.Background(), "synthetic", r); err == nil {
		t.Fatal("missing deletion deadline allowed disclosure")
	}
}
