package artifact

import (
	"asservat.local/asservat/internal/domain/identity"
	"errors"
	"testing"
	"time"
)

func downloadFixture() (DownloadSession, DownloadAuthority, time.Time) {
	now := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	id := "10000000-0000-4000-8000-000000000001"
	scope := DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod", Version: Digest{1}, Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "console", Kind: identity.Human}}
	a := DownloadAuthority{Scope: scope, PermissionEpoch: id, PermissionSequence: 1, ProjectionDigest: Digest{2}, DecisionDigest: Digest{3}, IdentityRevision: identity.Revision{UID: "policy", Generation: 1, Digest: Digest{4}}, CheckedAt: now, ValidUntil: now.Add(5 * time.Second), AccessUntil: now.Add(time.Hour)}
	s := DownloadSession{ID: id, AllocationID: id, Scope: scope, RequestDigest: Digest{5}, State: DownloadPreparing, CreatedAt: now, Deadline: now.Add(30 * time.Minute), OutputLimit: 8192, ReadLimit: 8 << 20, RequestLimit: 4}
	return s, a, now
}
func TestDownloadCannotDiscloseBeforeAuditedPreparation(t *testing.T) {
	s, a, n := downloadFixture()
	b := DownloadBatch{ID: s.ID, Purpose: DownloadContent, OutputBytes: 4096, ReadBytes: 2 << 20}
	if _, err := s.Start(a, b, n); !errors.Is(err, ErrDownloadConflict) {
		t.Fatal(err)
	}
	b.Purpose = DownloadMetadata
	b.OutputBytes = 0
	s, err := s.Start(a, b, n)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Permit(a, b.ID, 1, n); err == nil {
		t.Fatal("unaudited metadata permitted")
	}
	if _, err = s.Finish(b.ID, 1, 0, true, false, n); err == nil {
		t.Fatal("unaudited readiness")
	}
	s.Active.AuditAcknowledged = true
	if err = s.Permit(a, b.ID, 1, n); err != nil {
		t.Fatal(err)
	}
	s, err = s.Finish(b.ID, 1, 0, true, false, n)
	if err != nil || s.State != DownloadReady {
		t.Fatal(s.State, err)
	}
	if s.ChargedRead != 2<<20 || s.Requests != 1 {
		t.Fatal("preparation not charged")
	}
	b.Purpose = DownloadContent
	b.OutputBytes = 4096
	s, err = s.Start(a, b, n)
	if err != nil {
		t.Fatal(err)
	}
	s.Active.AuditAcknowledged = true
	if err = s.Permit(a, b.ID, 2, n); err != nil {
		t.Fatal(err)
	}
	s, err = s.Finish(b.ID, 2, 4096, true, true, n)
	if err != nil || s.State != DownloadCompleted || s.EmittedBytes != 4096 {
		t.Fatal(s, err)
	}
	if _, err = s.Start(a, b, n); err == nil {
		t.Fatal("completed session restarted")
	}
}
func TestDownloadLostRepliesCancellationAndScope(t *testing.T) {
	s, a, n := downloadFixture()
	s.State = DownloadReady
	b := DownloadBatch{ID: s.ID, Purpose: DownloadContent, OutputBytes: 4096, ReadBytes: 2 << 20}
	s, err := s.Start(a, b, n)
	if err != nil {
		t.Fatal(err)
	}
	s.Active.AuditAcknowledged = true
	if _, err = s.Start(a, b, n); err == nil {
		t.Fatal("simultaneous batch")
	}
	for _, mutate := range []func(*DownloadAuthority){
		func(a *DownloadAuthority) { a.Scope.Principal.Subject = "other" },
		func(a *DownloadAuthority) { a.Scope.Principal.ClientID = "agent" },
		func(a *DownloadAuthority) { a.Scope.Version = Digest{9} },
		func(a *DownloadAuthority) { a.Scope.ArtifactID = "10000000-0000-4000-8000-000000000002" },
		func(a *DownloadAuthority) { a.ValidUntil = n },
	} {
		bad := a
		mutate(&bad)
		if s.Permit(bad, b.ID, 1, n) == nil {
			t.Fatal("changed authority permitted")
		}
	}
	n = n.Add(6 * time.Second)
	a.CheckedAt = n
	a.ValidUntil = n.Add(5 * time.Second)
	if s.Permit(a, b.ID, 1, n) == nil {
		t.Fatal("renewed expired batch")
	}
	b.ID = "10000000-0000-4000-8000-000000000002"
	s, err = s.Start(a, b, n)
	if err != nil || s.ChargedOutput != 8192 {
		t.Fatal(s, err)
	}
	s.Active.AuditAcknowledged = true
	s, err = s.Cancel()
	if err != nil {
		t.Fatal(err)
	}
	if s.Permit(a, b.ID, 2, n) == nil {
		t.Fatal("cancelled output permitted")
	}
	s, err = s.Finish(b.ID, 2, 1024, false, false, n)
	if err != nil || s.State != DownloadCancelled || s.EmittedBytes != 1024 || s.ChargedOutput != 8192 {
		t.Fatal(s, err)
	}
}
func TestDownloadBudgetAndPartialOutcomes(t *testing.T) {
	s, a, n := downloadFixture()
	s.State = DownloadReady
	s.OutputLimit = 4096
	b := DownloadBatch{ID: s.ID, Purpose: DownloadContent, Offset: 1, OutputBytes: 4096, ReadBytes: 2 << 20}
	s, err := s.Start(a, b, n)
	if err != nil {
		t.Fatal(err)
	}
	s.Active.AuditAcknowledged = true
	if _, err = s.Finish(b.ID, 1, 4095, true, false, n); err == nil {
		t.Fatal("short success")
	}
	s, err = s.Finish(b.ID, 1, 4096, true, false, n)
	if err != nil || s.State != DownloadInterrupted {
		t.Fatal(s.State, err)
	}
	if _, err = s.Start(a, b, n); !errors.Is(err, ErrDownloadCapacity) {
		t.Fatal("refund after partial response", err)
	}
	s, a, n = downloadFixture()
	s.State = DownloadReady
	b.OutputBytes = DeliveryBytes + 1
	if _, err = s.Start(a, b, n); err == nil {
		t.Fatal("unbounded batch")
	}
	b.OutputBytes = 1
	s.ReadLimit = 1
	if _, err = s.Start(a, b, n); !errors.Is(err, ErrDownloadCapacity) {
		t.Fatal(err)
	}
	s.ReadLimit = 8 << 20
	s.Requests = s.RequestLimit
	if _, err = s.Start(a, b, n); !errors.Is(err, ErrDownloadCapacity) {
		t.Fatal(err)
	}
	s.Requests = 0
	s.Deadline = n.Add(time.Second)
	s, err = s.Start(a, b, n)
	if err != nil {
		t.Fatal(err)
	}
	s.Active.AuditAcknowledged = true
	if s.Permit(a, b.ID, 1, n.Add(time.Second)) == nil {
		t.Fatal("expired deadline")
	}
	s, err = s.Finish(b.ID, 1, 1, true, false, n.Add(time.Second))
	if err != nil || s.State != DownloadExpired {
		t.Fatal(s.State, err)
	}
}

func TestDownloadStatusObservationDoesNotExtendTransferAuthority(t *testing.T) {
	session, authority, now := downloadFixture()
	session.Deadline = now.Add(time.Second)
	now = now.Add(2 * time.Second)
	authority.CheckedAt = now
	authority.ValidUntil = now.Add(5 * time.Second)
	session.State = DownloadCompleted
	observation := DownloadObservation{Session: session, ObservedAt: now, ValidUntil: authority.ValidUntil}
	if !observation.Valid(now) {
		t.Fatal("fresh authorized terminal status was tied to expired transfer deadline")
	}
	for _, purpose := range []DownloadPurpose{DownloadMetadata, DownloadContent} {
		batch := DownloadBatch{ID: session.ID, Purpose: purpose, ReadBytes: 4096}
		if purpose == DownloadContent {
			batch.OutputBytes = 16
		}
		if _, err := session.Start(authority, batch, now); err == nil {
			t.Fatal("status extended effect authority", purpose)
		}
	}
	observation.ValidUntil = now
	if observation.Valid(now) {
		t.Fatal("stale status observation accepted")
	}
}

func TestDownloadObservedExpiryPreservesTerminalOutcomeAndAccounting(t *testing.T) {
	for _, state := range []DownloadState{DownloadPreparing, DownloadReady, DownloadStreaming, DownloadInterrupted, DownloadCompleted, DownloadCancelled, DownloadExpired, DownloadDenied, DownloadFailed} {
		session, _, now := downloadFixture()
		session.State = state
		before := session
		expected := state
		if !state.Terminal() {
			expected = DownloadExpired
		}
		if got := session.ObservedState(session.Deadline); got != expected {
			t.Fatal(state, got)
		}
		if got := session.ObservedState(now); got != state {
			t.Fatal("premature expiry", state, got)
		}
		if session != before {
			t.Fatal("observation mutated session")
		}
	}
}
