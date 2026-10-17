package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
)

var _ ContextDownloadUseCase = evidence.ContextDownloadCoordinator{}

const downloadID = "00000000-0000-4000-8000-000000000090"

type downloadProjectionFixture struct {
	view            evidence.ContextDownloadView
	err             error
	prepares, reads int
	after           func()
}

func (f *downloadProjectionFixture) PrepareContextDownload(context.Context, identities.CurrentIdentity, string, string) (evidence.ContextDownloadView, error) {
	f.prepares++
	if f.after != nil {
		f.after()
	}
	return f.view, f.err
}
func (f *downloadProjectionFixture) GetContextDownload(context.Context, identities.CurrentIdentity, string) (evidence.ContextDownloadView, error) {
	f.reads++
	if f.after != nil {
		f.after()
	}
	return f.view, f.err
}
func downloadProjection(t *testing.T) (*ContextDownloadOperations, *downloadProjectionFixture, *contextOperationFixture) {
	t.Helper()
	_, current := operationFixture(t, false)
	current.i.Scopes = []string{"evidence:read", "evidence:download"}
	now := time.Now().UTC()
	current.i.VerifiedAt = now
	current.i.ValidUntil = now.Add(5 * time.Second)
	f := &downloadProjectionFixture{view: evidence.ContextDownloadView{Session: artifact.DownloadSession{ID: downloadID, AllocationID: caseID, Scope: artifact.DownloadScope{RootID: caseID, ArtifactID: artifactID, CaptureID: caseID, ClusterID: caseID, NamespaceUID: "private-namespace", WorkloadUID: "private-workload", PodUID: "private-pod", Version: artifact.Digest{1}, Principal: current.i.Principal}, RequestDigest: artifact.Digest{2}, State: artifact.DownloadReady, CreatedAt: now.Add(-time.Minute), Deadline: now.Add(time.Minute), OutputLimit: 4096, ReadLimit: 65536, RequestLimit: 4}, Metadata: &artifact.NativeDownloadMetadata{Filename: "pod-status.json", Format: "application/json", ETag: `"native-version"`, Coverage: "One complete bounded pod-status snapshot.", Size: 42, SHA256: artifact.Digest{3}, ReadUntil: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}, ValidUntil: now.Add(time.Second), AccessUntil: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour)}}
	s, e := NewContextDownloadOperations(ContextDownloadOperationsConfig{PublicOrigin: "https://console.invalid", Now: func() time.Time { return now }, NewID: func() string { return caseID }}, f)
	if e != nil {
		t.Fatal(e)
	}
	return s, f, current
}
func TestDownloadProjectionUsesOnlyPreparedNativeGroup(t *testing.T) {
	s, f, current := downloadProjection(t)
	out, e := s.Call(t.Context(), current, "get_artifact_download", []byte(`{"download_id":"`+downloadID+`"}`))
	if e != nil || f.prepares != 0 || f.reads != 1 || !out.ValidUntil.Equal(f.view.ValidUntil) {
		t.Fatalf("status: %s %v", out.Body, e)
	}
	var wire struct{ Data ContextDownloadData }
	if json.Unmarshal(out.Body, &wire) != nil || wire.Data.Filename != "pod-status.json" || wire.Data.SHA256 != hash(f.view.Metadata.SHA256) || wire.Data.ContentPath != "/api/v1/downloads/"+downloadID+"/content" || wire.Data.ContinuePreparation {
		t.Fatal("wrong native projection", string(out.Body))
	}
	for _, private := range []string{"private-namespace", "private-workload", "private-pod", "Principal", "RequestDigest", "allocation_id", "ReadLimit"} {
		if strings.Contains(string(out.Body), private) {
			t.Fatal("private control field escaped", private)
		}
	}
}
func TestDownloadTerminalStatusNeedsNoNativeMetadataAfterTransferExpiry(t *testing.T) {
	s, f, c := downloadProjection(t)
	f.view.Session.State = artifact.DownloadCompleted
	f.view.Session.Deadline = c.i.VerifiedAt.Add(-time.Second)
	f.view.Metadata = nil
	out, e := s.Call(t.Context(), c, "get_artifact_download", []byte(`{"download_id":"`+downloadID+`"}`))
	if e != nil || strings.Contains(string(out.Body), "sha256") || strings.Contains(string(out.Body), "content_path") || !strings.Contains(string(out.Body), `"state":"Completed"`) {
		t.Fatal(string(out.Body), e)
	}
}
func TestDownloadInvalidRawOrAmbiguousInputNeverDispatches(t *testing.T) {
	for _, bad := range []string{`{"artifact_id":"` + artifactID + `","idempotency_key":"key","grant_id":"` + caseID + `"}`, `{"artifact_id":"` + artifactID + `","artifact_id":"` + caseID + `","idempotency_key":"key"}`, `{"artifact_id":"` + artifactID + `","idempotency_key":""}`} {
		s, f, c := downloadProjection(t)
		if _, e := s.Call(t.Context(), c, "prepare_artifact_download", []byte(bad)); !errors.Is(e, contracts.ErrInvestigationWire) || f.prepares != 0 {
			t.Fatal("raw/ambiguous request dispatched", e)
		}
	}
}
func TestDownloadPreparationAttachmentAndContinuationArePOSTOnly(t *testing.T) {
	s, f, c := downloadProjection(t)
	f.view.Session.State = artifact.DownloadPreparing
	f.view.Metadata = nil
	f.view.ContinuePreparation = true
	calls := 0
	attachmentUntil := c.i.VerifiedAt.Add(500 * time.Millisecond)
	call := OperationCall{requestID: caseID, downloadAttachment: func(ctx context.Context, id string) (time.Time, error) {
		calls++
		if id != downloadID || ctx.Err() != nil {
			t.Fatal("wrong binding")
		}
		return attachmentUntil, nil
	}}
	out, e := s.CallWithContext(t.Context(), c, call, "prepare_artifact_download", []byte(`{"artifact_id":"`+artifactID+`","idempotency_key":"key"}`))
	if e != nil || calls != 1 || !out.ValidUntil.Equal(attachmentUntil) || !strings.Contains(string(out.Body), `"continue_preparation":true`) {
		t.Fatal(string(out.Body), e, calls)
	}
	f.view.ContinuePreparation = false
	out, e = s.CallWithContext(t.Context(), c, call, "get_artifact_download", []byte(`{"download_id":"`+downloadID+`"}`))
	if e != nil || calls != 1 || strings.Contains(string(out.Body), "continue_preparation") {
		t.Fatal("status acquired an owner or continued work", e)
	}
	f.view.Session.State = artifact.DownloadCompleted
	if _, e = s.CallWithContext(t.Context(), c, call, "prepare_artifact_download", []byte(`{"artifact_id":"`+artifactID+`","idempotency_key":"key"}`)); e != nil || calls != 1 {
		t.Fatal("terminal replay acquired owner", e)
	}
}
func TestDownloadResponseDeniesChangedIdentityAndExpiredAttachment(t *testing.T) {
	s, f, c := downloadProjection(t)
	f.after = func() { c.i.Scopes = []string{"evidence:read"} }
	if _, e := s.Call(t.Context(), c, "get_artifact_download", []byte(`{"download_id":"`+downloadID+`"}`)); e == nil {
		t.Fatal("lost download scope disclosed metadata")
	}
	s, _, c = downloadProjection(t)
	call := OperationCall{requestID: caseID, downloadAttachment: func(context.Context, string) (time.Time, error) { return c.i.VerifiedAt, nil }}
	if out, e := s.CallWithContext(t.Context(), c, call, "prepare_artifact_download", []byte(`{"artifact_id":"`+artifactID+`","idempotency_key":"key"}`)); e == nil || len(out.Body) > 0 {
		t.Fatal("expired attachment disclosed metadata")
	}
}
func TestDownloadErrorsDoNotDiscloseNativeOrExistenceDetails(t *testing.T) {
	s, f, c := downloadProjection(t)
	f.err = errors.New("private backend SQL error")
	out, e := s.Call(t.Context(), c, "get_artifact_download", []byte(`{"download_id":"`+downloadID+`"}`))
	if e != nil || strings.Contains(string(out.Body), downloadID) || strings.Contains(string(out.Body), "SQL") || strings.Contains(string(out.Body), "filename") {
		t.Fatal(string(out.Body), e)
	}
}

type stopProjectionFixture struct {
	out   artifact.DownloadStopReceipt
	calls int
}

func (f *stopProjectionFixture) CancelContextDownload(context.Context, identities.CurrentIdentity, string, string, string) (artifact.DownloadStopReceipt, error) {
	f.calls++
	return f.out, nil
}
func TestDownloadStopUsesPrepaidLaneWithoutReadScopeOrNormalAuditCapacity(t *testing.T) {
	audited, current, gate := auditedFixture(t)
	current.i.Scopes = []string{"openid"}
	downloads, _, _ := downloadProjection(t)
	downloads.config.Now = audited.config.Now
	stop := &stopProjectionFixture{out: artifact.DownloadStopReceipt{DownloadID: downloadID, RequestID: caseID, State: "AlreadyTerminal", AuditState: "pending", ObservedAt: current.i.VerifiedAt, ValidUntil: current.i.ValidUntil}}
	downloads.stop = stop
	combined, e := NewInvestigationOperations(audited.inner.(*InvestigationOperations).captures, nil, downloads)
	if e != nil {
		t.Fatal(e)
	}
	audited.inner = combined
	audited.stopSlots = make(chan struct{}, 4)
	audited.lanes["normal"] <- struct{}{}
	gate.beginFail = true
	out, e := audited.Call(t.Context(), current, "cancel_artifact_download", []byte(`{"download_id":"`+downloadID+`","idempotency_key":"same-key"}`))
	if e != nil || stop.calls != 1 || len(gate.intents) != 0 || len(gate.outcomes) != 0 || !strings.Contains(string(out.Body), `"state":"AlreadyTerminal"`) {
		t.Fatal(string(out.Body), e)
	}
	for _, field := range []string{"artifact_id", "filename", "sha256", "expires_at", "Completed"} {
		if strings.Contains(string(out.Body), field) {
			t.Fatal("hidden metadata escaped stop", field)
		}
	}
}
func TestDownloadStopMalformedInputCannotUsePrepaidLane(t *testing.T) {
	audited, current, gate := auditedFixture(t)
	downloads, _, _ := downloadProjection(t)
	stop := &stopProjectionFixture{}
	downloads.stop = stop
	combined, e := NewInvestigationOperations(audited.inner.(*InvestigationOperations).captures, nil, downloads)
	if e != nil {
		t.Fatal(e)
	}
	audited.inner = combined
	audited.stopSlots = make(chan struct{}, 4)
	_, e = audited.Call(t.Context(), current, "cancel_artifact_download", []byte(`{"download_id":"`+downloadID+`","idempotency_key":"key","actor":"foreign"}`))
	if !errors.Is(e, contracts.ErrInvestigationWire) || stop.calls != 0 || len(gate.intents) != 1 || gate.intents[0].Name != "invalid_operation" {
		t.Fatal("invalid input reached protected stop", e)
	}
}
