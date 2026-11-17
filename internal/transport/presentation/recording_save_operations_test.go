package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

type recordingOperationFixture struct {
	page                    app.RecordingPage
	result                  app.ContextPreviewResult
	listCalls, previewCalls int
	request                 app.RecordingSavePreviewRequest
	target                  targets.WorkloadRequest
	limit                   int
	after                   func()
	err                     error
}

func (f *recordingOperationFixture) List(_ context.Context, _ identities.CurrentIdentity, target targets.WorkloadRequest, _ string, _ string, limit int) (app.RecordingPage, error) {
	f.listCalls++
	f.target = target
	f.limit = limit
	if f.after != nil {
		f.after()
	}
	return f.page, f.err
}
func (f *recordingOperationFixture) Select(ctx context.Context, current identities.CurrentIdentity, target targets.WorkloadRequest, ids []string) (app.RecordingPage, error) {
	return f.List(ctx, current, target, "", "", len(ids))
}
func (f *recordingOperationFixture) Preview(_ context.Context, _ identities.CurrentIdentity, in app.RecordingSavePreviewRequest) (app.ContextPreviewResult, error) {
	f.previewCalls++
	f.request = in
	if in.Before > 0 {
		f.result.RecordingSave.Before = in.Before
		f.result.Preview.Intent.Snapshot.Request.Before = in.Before
	}
	if f.after != nil {
		f.after()
	}
	return f.result, f.err
}
func recordingOperationTestFixture(t *testing.T) (*AuditedOperations, *RecordingSaveOperations, *contextOperationFixture, *recordingOperationFixture, *presentationAuditGate) {
	t.Helper()
	audited, actor, gate := auditedFixture(t)
	now := audited.config.Now()
	row := app.RecordingRow{Handle: "opaque-recording-handle", PolicyName: "policy-a", PolicyUID: "policy-a", PodUID: "pod-a", PodName: "api-a", ActionID: "packets", Kind: "packetCapture", State: "Unknown", History: "Unknown", MaximumBefore: 90 * time.Second, IncidentPodCap: 3}
	f := &recordingOperationFixture{page: app.RecordingPage{Rows: []app.RecordingRow{row}, Cursor: "opaque-next", ExpiresAt: now.Add(time.Minute), ValidUntil: now.Add(2 * time.Second)}}
	assessment := assessmentFixture()
	assessment.GeneratedAt = now
	assessment.ValidUntil = now.Add(5 * time.Second)
	f.result = app.ContextPreviewResult{RecordingSave: &app.RecordingSavePreviewMetadata{Selected: []app.RecordingRow{row}, Before: time.Minute, IncidentPodCap: 3}, Assessment: assessment, ValidUntil: now.Add(2 * time.Second), Preview: value.ContextPreview{ID: "00000000-0000-4000-8000-000000000020", CaptureID: "00000000-0000-4000-8000-000000000030", ScopeDigest: assessment.PlanDigest, SelectionUntil: now.Add(time.Minute), Deadline: now.Add(time.Hour), Intent: value.ContextIntent{Snapshot: &planning.SourceSnapshotContext{Request: artifact.SourceSnapshotRequest{Before: time.Minute}}}}}
	operations, err := NewRecordingSaveOperations(RecordingSaveOperationsConfig{PublicOrigin: audited.PublicOrigin(), Now: audited.config.Now, NewID: audited.config.NewID}, f)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := NewInvestigationRecordingSaveOperations(audited.inner.(*InvestigationOperations), operations)
	if err != nil {
		t.Fatal(err)
	}
	// list_recordings without live viewing lists save rows only.
	list, err := NewLiveOperations(LiveOperationsConfig{PublicOrigin: audited.PublicOrigin(), Recordings: f, Clusters: NewClusterNames(map[string]string{"local": "00000000-0000-4000-8000-000000000001"}), Now: audited.config.Now})
	if err != nil {
		t.Fatal(err)
	}
	if combined, err = NewInvestigationLiveOperations(combined, list); err != nil {
		t.Fatal(err)
	}
	audited.inner = combined
	return audited, operations, actor, f, gate
}
func TestRecordingSaveOperationsUseExistingAuditAndPassiveNamedTarget(t *testing.T) {
	audited, _, actor, f, gate := recordingOperationTestFixture(t)
	reply, err := audited.Call(t.Context(), actor, "list_recordings", []byte(`{`+liveWireTarget+`}`))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Status     string
		Data       recordingListPage
		NextCursor *string `json:"next_cursor"`
	}
	if json.Unmarshal(reply.Body, &out) != nil || out.Status != "ok" || len(out.Data.Recordings) != 1 || out.Data.CaptureEnabled || out.Data.Recordings[0].History != "Unknown" || out.Data.Recordings[0].MaximumBefore != "90s" || out.Data.Recordings[0].IncidentPodCap != 3 || out.Data.Recordings[0].SaveVia != "recordingSave" || out.NextCursor == nil || f.limit != 16 || f.target.Name != "api" {
		t.Fatal("lost bounded passive inventory", string(reply.Body))
	}
	if len(gate.events) != 1 || gate.events[0].Operation != "list_recordings" || !reply.ValidUntil.Equal(f.page.ValidUntil) || actor.requests != 0 {
		t.Fatal("lost original audit/freshness or acquired work", gate, reply.ValidUntil)
	}
	gate.fail = true
	if reply, err = audited.Call(t.Context(), actor, "list_recordings", []byte(`{`+liveWireTarget+`}`)); err == nil || len(reply.Body) != 0 {
		t.Fatal("inventory escaped without its audit row", err)
	}
}
func TestRecordingSavePreviewIsTypedAndKeepsMutationDisabled(t *testing.T) {
	audited, _, actor, f, gate := recordingOperationTestFixture(t)
	reply, err := audited.Call(t.Context(), actor, "preview_recording_save", []byte(`{"recording_handles":["opaque-recording-handle"],"before":"30s"}`))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Status string
		Data   RecordingSavePreviewData
	}
	if json.Unmarshal(reply.Body, &out) != nil || out.Status != "ok" || out.Data.Operation != "recordingSave" || out.Data.CaptureEnabled || out.Data.IncidentPodCap != 3 || len(out.Data.Selected) != 1 || out.Data.Windows[0].Before != "30s" || out.Data.Windows[0].After != "0s" || len(out.Data.Blockers) != 1 || out.Data.Blockers[0] != "CollectionDisabled" || f.request.Before != 30*time.Second {
		t.Fatal("preview became ordinary capture or invented coverage", string(reply.Body))
	}
	if len(out.Data.PlanDigest) != 64 || len(gate.events) != 1 || actor.requests != 0 {
		t.Fatal("preview lost its plan digest or started acquisition", out.Data)
	}
	for _, bad := range []string{`{"recording_handles":["opaque-recording-handle"],"after":"1s"}`, `{"recording_handles":["opaque-recording-handle"],"source_id":"forged"}`, `{"recording_handles":["opaque-recording-handle","opaque-recording-handle"]}`, `{"Recording_Handles":["opaque-recording-handle"]}`} {
		if _, err = audited.Call(t.Context(), actor, "preview_recording_save", []byte(bad)); err == nil || f.previewCalls != 1 {
			t.Fatal("unsupported input reached source use case", bad, err, f.previewCalls)
		}
	}
}
func TestRecordingSaveMetadataRechecksIdentityAndDoesNotLeakProviderErrors(t *testing.T) {
	audited, _, actor, f, _ := recordingOperationTestFixture(t)
	f.after = func() { actor.revoke = true }
	if _, err := audited.Call(t.Context(), actor, "list_recordings", json.RawMessage(`{`+liveWireTarget+`}`)); err == nil {
		t.Fatal("revoked identity disclosed inventory")
	}
	audited, _, actor, f, _ = recordingOperationTestFixture(t)
	f.err = errors.New("private SQL source and credential detail")
	reply, err := audited.Call(t.Context(), actor, "list_recordings", json.RawMessage(`{`+liveWireTarget+`}`))
	if err != nil || strings.Contains(string(reply.Body), "private SQL") || !strings.Contains(string(reply.Body), `"status":"error"`) {
		t.Fatal(err, string(reply.Body))
	}
	reply, err = audited.Call(t.Context(), actor, "list_recordings", json.RawMessage(`{"target_ref":{"cluster":"elsewhere","namespace":"payments","kind":"Deployment","name":"api"}}`))
	if err != nil || !strings.Contains(string(reply.Body), `"code":"UnknownCluster"`) {
		t.Fatal("unknown cluster name is not a domain error", err, string(reply.Body))
	}
}
func TestRecordingSaveToolsRequireExplicitComposition(t *testing.T) {
	base, _ := operationFixture(t, false)
	for _, name := range []string{"list_recordings", "preview_recording_save"} {
		if _, ok := base.Tool(name); ok {
			t.Fatal("schema registration enabled source service")
		}
	}
	audited, _, _, _, _ := recordingOperationTestFixture(t)
	for _, name := range []string{"list_recordings", "preview_recording_save"} {
		if _, ok := audited.Tool(name); !ok {
			t.Fatal("explicitly composed passive route missing", name)
		}
	}
}

func TestRecordingInventoryBoundsWholePage(t *testing.T) {
	audited, _, actor, f, _ := recordingOperationTestFixture(t)
	row := f.page.Rows[0]
	row.Handle = strings.Repeat("h", 146)
	row.PolicyUID = strings.Repeat("u", 64)
	row.PolicyName = strings.Repeat("n", 253)
	row.PodUID = strings.Repeat("p", 128)
	row.PodName = strings.Repeat("n", 253)
	row.ActionID = strings.Repeat("a", 128)
	f.page.Rows = make([]app.RecordingRow, 16)
	for i := range f.page.Rows {
		f.page.Rows[i] = row
		f.page.Rows[i].Handle = fmt.Sprintf("%02d", i) + row.Handle[2:]
	}
	reply, err := audited.Call(t.Context(), actor, "list_recordings", []byte(`{`+liveWireTarget+`,"limit":100}`))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Status     string
		Data       recordingListPage
		NextCursor *string `json:"next_cursor"`
	}
	if f.limit != 16 || len(reply.Body) > 24<<10 || json.Unmarshal(reply.Body, &envelope) != nil || len(envelope.Data.Recordings) != 16 || envelope.NextCursor == nil {
		t.Fatal("unbounded page", f.limit, len(reply.Body))
	}
	t.Logf("16 maximum ASCII rows: %d bytes", len(reply.Body))
}

type cancellationOperationFixture struct {
	decision value.Cancellation
	err      error
	request  value.CancellationRequest
	calls    int
}

func (f *cancellationOperationFixture) Cancel(_ context.Context, _ identities.CurrentIdentity, in value.CancellationRequest) (value.Cancellation, error) {
	f.calls++
	f.request = in
	return f.decision, f.err
}
func TestRecordingCancellationReportsDurableRequestWithoutClaimingJoin(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		audited, ops, actor, _, gate := recordingOperationTestFixture(t)
		now := ops.config.Now()
		f := &cancellationOperationFixture{decision: value.Cancellation{CaptureID: "00000000-0000-4000-8000-000000000030", Phase: "Running", ApplicationStopUnknown: uncertain, Revision: 4, Requested: true, ObservedAt: now, ValidUntil: now.Add(time.Second)}, err: errors.New("private transport failure")}
		ops.cancellations = f
		// Acquisition remains disabled; restrictive cancellation uses the existing audit lane.
		base, err := NewInvestigationOperations(audited.inner.(*InvestigationOperations).captures, nil)
		if err != nil {
			t.Fatal(err)
		}
		combined, err := NewInvestigationRecordingSaveOperations(base, ops)
		if err != nil {
			t.Fatal(err)
		}
		audited.inner = combined
		reply, err := audited.Call(t.Context(), actor, "cancel_capture", []byte(`{"capture_id":"00000000-0000-4000-8000-000000000030","expected_revision":3,"idempotency_key":"cancel-once"}`))
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Status   string
			Data     RecordingCancellationData
			Warnings []string
		}
		if json.Unmarshal(reply.Body, &envelope) != nil || envelope.Status != "ok" || envelope.Data.Phase != "Running" || !envelope.Data.Requested || envelope.Data.Revision != 4 || len(envelope.Warnings) != 1+btoi(uncertain) {
			t.Fatal(string(reply.Body))
		}
		if f.calls != 1 || f.request.ExpectedRevision != 3 || f.request.IdempotencyKey != "cancel-once" || len(gate.events) != 1 || gate.events[0].Effect != "accepted" || strings.Contains(string(reply.Body), "private transport") {
			t.Fatal("lost durable request audit", f.request, gate.events, string(reply.Body))
		}
		if uncertain && !strings.Contains(strings.Join(envelope.Warnings, " "), "does not confirm that the application stopped profiling") {
			t.Fatal(string(reply.Body))
		}
	}
}
func btoi(v bool) int {
	if v {
		return 1
	}
	return 0
}

func TestRecordingCancellationRespectsOrdinaryCompositionGate(t *testing.T) {
	audited, ops, actor, _, _ := recordingOperationTestFixture(t)
	ops.cancellations = &cancellationOperationFixture{}
	base := audited.inner.(*InvestigationOperations).captures
	closed := *base
	closed.config.CollectionEnabled = false
	aggregate, err := NewInvestigationOperations(&closed, nil)
	if err != nil {
		t.Fatal(err)
	}
	composed, err := NewInvestigationRecordingSaveOperations(aggregate, ops)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := composed.Tool("cancel_capture"); ok {
		t.Fatal("ordinary disabled gate advertised cancellation")
	}
	if _, err = composed.Call(t.Context(), actor, "cancel_capture", []byte(`{"capture_id":"00000000-0000-4000-8000-000000000030","expected_revision":1,"idempotency_key":"same"}`)); err == nil {
		t.Fatal("disabled cancellation reached service")
	}
	for _, name := range []string{"preview_recording_save"} {
		if _, ok := composed.Tool(name); !ok {
			t.Fatal("passive tool disappeared", name)
		}
	}
}
