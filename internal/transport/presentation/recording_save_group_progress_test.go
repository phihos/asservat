package presentation

import (
	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

type groupedRecordingProgressFixture struct{ progress value.ContextProgress }

func (f groupedRecordingProgressFixture) Get(context.Context, identities.CurrentIdentity, string) (value.ContextProgress, error) {
	return f.progress, nil
}
func TestRecordingSaveCancelledActionHasCanonicalProgress(t *testing.T) {
	base, current := operationFixture(t, true)
	p, err := current.Get(t.Context(), current, "00000000-0000-4000-8000-000000000030")
	if err != nil {
		t.Fatal(err)
	}
	p.Operation = "recordingSave"
	p.ActionID = "traffic"
	p.Phase = "Cancelled"
	p.ActionPhase = "Cancelled"
	p.ReasonCode = "CancellationJoined"
	p.CancellationRequested = true
	ops, err := NewContextOperations(base.config, current, groupedRecordingProgressFixture{p})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := ops.Call(t.Context(), current, "get_capture", json.RawMessage(`{"capture_id":"00000000-0000-4000-8000-000000000030"}`))
	if err != nil {
		t.Fatal("joined cancellation cannot be projected", err)
	}
	var envelope struct{ Data ContextProgressData }
	if json.Unmarshal(reply.Body, &envelope) != nil || envelope.Data.Phase != "Cancelled" || len(envelope.Data.Actions) != 1 || envelope.Data.Actions[0].Phase != "Cancelled" {
		t.Fatal(string(reply.Body))
	}
}

func TestRecordingSaveGroupProgressKeepsEveryChildUnderOneParent(t *testing.T) {
	base, current := operationFixture(t, true)
	p, err := current.Get(t.Context(), current, "00000000-0000-4000-8000-000000000030")
	if err != nil {
		t.Fatal(err)
	}
	p.Operation = "recordingSave"
	p.ActionID = ""
	p.Phase = "Partial"
	p.Actions = []value.ContextActionProgress{
		{InstanceID: "00000000-0000-4000-8000-000000000101", PodUID: "retained-pod-a", PodName: "api-a", ActionID: "traffic", Phase: "Succeeded", ReasonCode: "Published"},
		{InstanceID: "00000000-0000-4000-8000-000000000102", PodUID: "retained-pod-b", PodName: "api-b", ActionID: "traffic", Phase: "Cancelled", ReasonCode: "CancellationJoined"},
	}
	ops, err := NewContextOperations(base.config, current, groupedRecordingProgressFixture{p})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := ops.Call(t.Context(), current, "get_capture", json.RawMessage(`{"capture_id":"00000000-0000-4000-8000-000000000030"}`))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Data struct {
			CaptureID string `json:"capture_id"`
			Actions   []struct {
				ActionID   string `json:"action_id"`
				InstanceID string `json:"action_instance_id"`
				PodUID     string `json:"pod_uid"`
				PodName    string `json:"pod_name"`
				Phase      string `json:"phase"`
			} `json:"actions"`
		}
	}
	if json.Unmarshal(reply.Body, &envelope) != nil || envelope.Data.CaptureID != p.CaptureID || len(envelope.Data.Actions) != 2 {
		t.Fatal("grouped progress dropped child rows", string(reply.Body))
	}
	for i, row := range envelope.Data.Actions {
		want := p.Actions[i]
		if row.ActionID != want.ActionID || row.InstanceID != want.InstanceID || row.PodUID != want.PodUID || row.PodName != want.PodName || row.Phase != want.Phase {
			t.Fatal("child identity or phase was substituted", row, want)
		}
	}
}

func TestRecordingSaveGroupedPreviewKeepsPerSourceWindowsWithoutParentArtifact(t *testing.T) {
	_, ops, current, f, _ := recordingOperationTestFixture(t)
	first := f.result.RecordingSave.Selected[0]
	second := first
	second.Handle = "other-opaque-handle"
	second.PodUID = "retained-pod-b"
	second.PodName = "api-b"
	f.result.Preview.Intent.Snapshot = nil
	f.result.Preview.Group = &value.RecordingSaveGroupPreview{Children: []value.RecordingSaveGroupChild{
		{Reference: value.RecordingReference{PodUID: first.PodUID, ActionID: first.ActionID}, Request: artifact.SourceSnapshotRequest{Before: 20 * time.Second}},
		{Reference: value.RecordingReference{PodUID: second.PodUID, ActionID: second.ActionID}, Request: artifact.SourceSnapshotRequest{Before: 10 * time.Second}},
	}}
	f.result.RecordingSave.Selected = []app.RecordingRow{first, second}
	f.result.RecordingSave.Assessments = []app.RecordingSaveActionAssessment{{ActionID: first.ActionID, PodUID: first.PodUID, Assessment: f.result.Assessment}, {ActionID: second.ActionID, PodUID: second.PodUID, Assessment: f.result.Assessment}}
	f.result.Assessment.OutputLimit *= 2
	f.result.RecordingSave.Before = 0
	f.result.RecordingSave.Windows = []app.RecordingSaveWindow{{Handle: first.Handle, Before: 20 * time.Second}, {Handle: second.Handle, Before: 10 * time.Second}}
	handles := []string{first.Handle, second.Handle}
	reply, err := ops.Call(t.Context(), current, "preview_recording_save", json.RawMessage(`{"recording_handles":["`+first.Handle+`","`+second.Handle+`"]}`))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct{ Data RecordingSavePreviewData }
	if json.Unmarshal(reply.Body, &envelope) != nil || envelope.Data.CaptureID != f.result.Preview.CaptureID || len(envelope.Data.Selected) != 2 || len(envelope.Data.Windows) != 2 || envelope.Data.Windows[0].Before != "20s" || envelope.Data.Windows[1].Before != "10s" {
		t.Fatal("grouped preview collapsed windows or parent", string(reply.Body))
	}
	f.result.RecordingSave.Windows[1].Before = 11 * time.Second
	if _, _, err := recordingPreviewSelection(f.result, handles); err == nil {
		t.Fatal("preview changed one child reviewed window")
	}
	f.result.RecordingSave.Windows = f.result.RecordingSave.Windows[:1]
	if _, _, err := recordingPreviewSelection(f.result, handles); err == nil {
		t.Fatal("preview silently dropped missing child window")
	}
}
func TestRecordingSaveGroupProgressRejectsSubstitutedOrDuplicateInstances(t *testing.T) {
	original := value.ContextActionProgress{InstanceID: "00000000-0000-4000-8000-000000000101", PodUID: "pod-a", PodName: "api-a", ActionID: "traffic", Phase: "Running"}
	parent := "00000000-0000-4000-8000-000000000030"
	for _, kind := range []string{"duplicate", "parent", "missing pod", "ordinary"} {
		p := value.ContextProgress{CaptureID: parent, Operation: "recordingSave", Actions: []value.ContextActionProgress{original}}
		switch kind {
		case "duplicate":
			p.Actions = append(p.Actions, original)
		case "parent":
			p.Actions[0].InstanceID = parent
		case "missing pod":
			p.Actions[0].PodName = ""
		case "ordinary":
			p.Operation = "collect"
		}
		if _, err := recordingProgressActions(p); err == nil {
			t.Fatal("invalid child metadata accepted", kind)
		}
	}
}

type recordingParentCaptureFixture struct{ *contextOperationFixture }

func (f recordingParentCaptureFixture) Request(context.Context, identities.CurrentIdentity, string, string) (value.Accepted, error) {
	return value.Accepted{CaptureID: "00000000-0000-4000-8000-000000000030", MetadataValidUntil: f.metadataUntil, Group: &value.RecordingSaveGroupAccepted{Children: []value.Accepted{{CaptureID: "00000000-0000-4000-8000-000000000101"}, {CaptureID: "00000000-0000-4000-8000-000000000102"}}}}, nil
}
func (f recordingParentCaptureFixture) ResolveContextRequest(ctx context.Context, current identities.CurrentIdentity, p, key string) (value.ContextRequestDisposition, error) {
	a, err := f.Request(ctx, current, p, key)
	return value.ContextRequestDisposition{State: value.RequestAccepted, Accepted: &a, ValidUntil: f.metadataUntil}, err
}
func TestRecordingSaveGroupReceiptExposesOnlyParent(t *testing.T) {
	base, current := operationFixture(t, true)
	service := recordingParentCaptureFixture{current}
	ops, err := NewContextOperations(base.config, service, current)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"request_capture", "resolve_capture_request"} {
		reply, err := ops.Call(t.Context(), current, name, json.RawMessage(wireRequest))
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct{ Data map[string]any }
		if json.Unmarshal(reply.Body, &envelope) != nil || envelope.Data["capture_id"] != "00000000-0000-4000-8000-000000000030" || envelope.Data["operation"] != "recordingSave" {
			t.Fatal("parent receipt became ordinary or selected child", string(reply.Body))
		}
		for _, child := range []string{"00000000-0000-4000-8000-000000000101", "00000000-0000-4000-8000-000000000102"} {
			if strings.Contains(string(reply.Body), child) {
				t.Fatal("child navigation escaped parent receipt", string(reply.Body))
			}
		}
	}
}

func TestRecordingSaveMaximumGroupedProgressFitsExistingEnvelope(t *testing.T) {
	base, current := operationFixture(t, true)
	p, err := current.Get(t.Context(), current, "00000000-0000-4000-8000-000000000030")
	if err != nil {
		t.Fatal(err)
	}
	p.Operation = "recordingSave"
	reason := strings.Repeat("\x00", 512)
	p.Reason, p.ReasonState = &reason, "available"
	p.Actions = make([]value.ContextActionProgress, value.MaxRecordingSaveGroupChildren)
	for i := range p.Actions {
		p.Actions[i] = value.ContextActionProgress{InstanceID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i+101), PodUID: strings.Repeat("u", 128), PodName: strings.Repeat("p", 253), ActionID: strings.Repeat("a", 63), Phase: "Finalizing", ReasonCode: strings.Repeat("R", 64)}
	}
	ops, err := NewContextOperations(base.config, current, groupedRecordingProgressFixture{p})
	if err != nil {
		t.Fatal(err)
	}
	reply, err := ops.Call(t.Context(), current, "get_capture", json.RawMessage(`{"capture_id":"00000000-0000-4000-8000-000000000030"}`))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct{ Data ContextProgressData }
	if json.Unmarshal(reply.Body, &envelope) != nil || len(envelope.Data.Actions) != 16 || envelope.Data.Reason == nil || *envelope.Data.Reason != reason || envelope.Data.ReasonState != "available" || len(reply.Body) > 24<<10 {
		t.Fatal("fullgroup response exceeded unchanged bound", len(reply.Body), err)
	}
	frame, _ := json.Marshal(struct {
		Result any `json:"result"`
	}{struct {
		Content           []map[string]string `json:"content"`
		StructuredContent json.RawMessage     `json:"structuredContent"`
	}{[]map[string]string{{"type": "text", "text": string(reply.Body)}}, reply.Body}})
	if len(frame) > 64<<10 {
		t.Fatal("duplicated MCP shape exceeds unchanged64KiB cap", len(frame))
	}
	t.Logf("16 maximum child rows +512 worst-escaped reason raw=%d duplicated-frame=%d bytes", len(reply.Body), len(frame))
}

func TestRecordingSaveAssessmentUsesActualSourceActionAndRetention(t *testing.T) {
	_, ops, current, f, _ := recordingOperationTestFixture(t)
	reply, err := ops.Call(t.Context(), current, "preview_recording_save", json.RawMessage(`{"recording_handles":["opaque-recording-handle"]}`))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct{ Data RecordingSavePreviewData }
	if json.Unmarshal(reply.Body, &envelope) != nil {
		t.Fatal(string(reply.Body))
	}
	assessment := envelope.Data.Assessment
	if len(assessment.Actions) != 1 || assessment.Actions[0].ActionID != f.result.RecordingSave.Selected[0].ActionID || assessment.Actions[0].Retention.AnchorRule != "firstAcquisitionOrEarlierSource" || assessment.Actions[0].Quantities[0].SourceRef == "builtin-pod-status-v1" {
		t.Fatal("snapshot assessment fabricated podstatus metadata", string(reply.Body))
	}
}

func TestRecordingSaveSixteenSourcePreviewFitsResponseBound(t *testing.T) {
	audited, ops, current, f, gate := recordingOperationTestFixture(t)
	m := f.result.RecordingSave
	prototype := m.Selected[0]
	perSource := f.result.Assessment
	perSource.Retention.PolicyDigests = make([]artifact.Digest, 64)
	for i := range perSource.Retention.PolicyDigests {
		perSource.Retention.PolicyDigests[i] = artifact.Digest{byte(i + 1)}
	}
	perSource.Impact.Explanation = strings.Repeat("e", 256)
	perSource.Impact.Effects = []string{"applicationPause", "applicationCPU", "applicationAllocation", "forcedGC", "nodeCPU", "collectorMemory", "storageIO", "uploadContention", "applicationMutation", "diagnosticInterference"}
	perSource.Exposure.RetainedPossible = []string{"userContent", "credentials", "personalIdentifiers", "networkAddresses", "paths", "profileLabels", "unknownApplicationData"}
	perSource.Exposure.TransientOnly = append([]string(nil), perSource.Exposure.RetainedPossible...)
	m.Selected = nil
	m.Windows = nil
	m.Assessments = nil
	m.Before = 0
	m.IncidentPodCap = 16
	f.result.Preview.Intent.Snapshot = nil
	f.result.Preview.Group = &value.RecordingSaveGroupPreview{}
	handles := []string{}
	for i := 0; i < 16; i++ {
		r := prototype
		r.Handle = strings.Repeat("h", 125) + fmt.Sprintf("%03d", i)
		r.PolicyUID = strings.Repeat("p", 64)
		r.ActionID = strings.Repeat("a", 63)
		r.PodUID = strings.Repeat("u", 125) + fmt.Sprintf("%03d", i)
		r.PodName = strings.Repeat("n", 60) + fmt.Sprintf("%03d", i)
		r.IncidentPodCap = 16
		m.Selected = append(m.Selected, r)
		m.Windows = append(m.Windows, app.RecordingSaveWindow{Handle: r.Handle, Before: 30 * time.Second})
		m.Assessments = append(m.Assessments, app.RecordingSaveActionAssessment{PodUID: r.PodUID, ActionID: r.ActionID, Assessment: perSource})
		f.result.Preview.Group.Children = append(f.result.Preview.Group.Children, value.RecordingSaveGroupChild{Reference: value.RecordingReference{PodUID: r.PodUID, ActionID: r.ActionID}, Request: artifact.SourceSnapshotRequest{Before: 30 * time.Second}})
		handles = append(handles, r.Handle)
	}
	f.result.Assessment.OutputLimit = 16 * perSource.OutputLimit
	assessment, err := recordingSaveAssessment(f.result)
	if err != nil {
		t.Fatal(err)
	}
	rows, windows, err := recordingPreviewSelection(f.result, handles)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(RecordingSavePreviewData{Kind: "recordingSavePreview", Operation: "recordingSave", PreviewID: f.result.Preview.ID, CaptureID: f.result.Preview.CaptureID, ExpiresAt: f.result.Preview.SelectionUntil, ScopeDigest: hash(f.result.Preview.ScopeDigest), Selected: rows, Windows: windows, Assessment: assessment, Blockers: []string{}, NavigationURI: ops.PublicOrigin() + "/captures/new", IncidentPodCap: 16})
	t.Logf("maximum16-source preview (128handle/128PodUID/63PodName/63actionID/64retention refs perchild) data bytes=%d before envelope; configured bounds, not measured collector overhead", len(raw))
	input, _ := json.Marshal(map[string]any{"recording_handles": handles})
	reply, err := ops.Call(t.Context(), current, "preview_recording_save", input)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Status string
		Data   json.RawMessage
	}
	if json.Unmarshal(reply.Body, &envelope) != nil || envelope.Status != "ok" {
		t.Fatal("accepted16-source contract cannot fit current response", len(raw), string(reply.Body))
	}
	auditedReply, auditErr := audited.Call(t.Context(), current, "preview_recording_save", input)
	if auditErr != nil || len(gate.outcomes) != 1 || gate.outcomes[0].OutputBytes != int64(len(auditedReply.Body)) || gate.outcomes[0].Effect != "none" {
		t.Fatal("large preview escaped exact audit/count", auditErr, gate.outcomes)
	}
}
