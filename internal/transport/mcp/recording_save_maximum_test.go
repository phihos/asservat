package mcp

import (
	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	planning "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/transport/presentation"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type maximumRecordingSave struct{ *mcpRecordingFixture }

func (maximumRecordingSave) Preview(_ context.Context, _ identities.CurrentIdentity, in app.RecordingSavePreviewRequest) (app.ContextPreviewResult, error) {
	// Synthetic explanatory metadata exercises the complete legal disclosure
	// shape. No authority, metrics, source or provider operation is supplied.
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := func(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
	assessment := planning.ContextAssessment{ID: id(3001), PlanDigest: artifact.Digest{1}, RulesDigest: artifact.Digest{2}, CapabilityDigest: artifact.Digest{3}, GeneratedAt: now, ValidUntil: now.Add(5 * time.Second), OutputLimit: artifact.RecordingNativeLimit,
		Impact:    planning.AssessmentImpact{Level: "unknown", HasUnknowns: true, Explanation: strings.Repeat("e", 256), Effects: []string{"applicationPause", "applicationCPU", "applicationAllocation", "forcedGC", "nodeCPU", "collectorMemory", "storageIO", "uploadContention", "applicationMutation", "diagnosticInterference"}},
		Exposure:  planning.AssessmentExposure{Classification: "potentialPersonalData", Basis: "conservativeMechanism", UnknownContent: true, RetainedPossible: []string{"userContent", "credentials", "personalIdentifiers", "networkAddresses", "paths", "profileLabels", "unknownApplicationData"}, TransientOnly: []string{"userContent", "credentials", "personalIdentifiers", "networkAddresses", "paths", "profileLabels", "unknownApplicationData"}},
		Retention: planning.AssessmentRetention{AccessAgeSeconds: 3600, DeleteAgeSeconds: 3900, MaximumAgeSeconds: 86400, DeletionBudgetSeconds: 300}}
	for i := 0; i < 64; i++ {
		assessment.Retention.PolicyDigests = append(assessment.Retention.PolicyDigests, artifact.Digest{byte(i + 1)})
	}
	out := app.ContextPreviewResult{Preview: value.ContextPreview{ID: id(2001), CaptureID: id(2002), ScopeDigest: assessment.PlanDigest, CreatedAt: now, SelectionUntil: now.Add(time.Minute), Deadline: now.Add(2 * time.Minute), Group: &value.RecordingSaveGroupPreview{}}, RecordingSave: &app.RecordingSavePreviewMetadata{IncidentPodCap: 16}, Assessment: assessment, ValidUntil: assessment.ValidUntil}
	for i, h := range in.Handles {
		row := app.RecordingRow{Handle: h, PolicyUID: strings.Repeat("p", 64), PodUID: strings.Repeat("u", 125) + fmt.Sprintf("%03d", i), PodName: strings.Repeat("n", 60) + fmt.Sprintf("%03d", i), ActionID: strings.Repeat("a", 63), Kind: "packetCapture", State: "Unknown", History: "Unknown", MaximumBefore: 90 * time.Second, IncidentPodCap: 16}
		out.RecordingSave.Selected = append(out.RecordingSave.Selected, row)
		out.RecordingSave.Windows = append(out.RecordingSave.Windows, app.RecordingSaveWindow{Handle: h, Before: 30 * time.Second})
		out.RecordingSave.Assessments = append(out.RecordingSave.Assessments, app.RecordingSaveActionAssessment{ActionID: row.ActionID, PodUID: row.PodUID, Assessment: assessment})
		out.Preview.Group.Children = append(out.Preview.Group.Children, value.RecordingSaveGroupChild{Reference: value.RecordingReference{PodUID: row.PodUID, ActionID: row.ActionID}, Request: artifact.SourceSnapshotRequest{Before: 30 * time.Second}})
	}
	out.Assessment.OutputLimit = int64(len(in.Handles)) * assessment.OutputLimit
	return out, nil
}

type recordingFrameObserver struct {
	next    http.RoundTripper
	maximum atomic.Int64
}

func (o *recordingFrameObserver) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := o.next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxRecordingSavePreviewResponseBytes+1))
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	for old := o.maximum.Load(); int64(len(body)) > old; old = o.maximum.Load() {
		if o.maximum.CompareAndSwap(old, int64(len(body))) {
			break
		}
	}
	return response, nil
}
func TestMaximumRecordingSaveUsesActualSDKTextAndStructuredFrame(t *testing.T) {
	var handler *Handler
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer server.Close()
	ordinary := &mcpCaptureFixture{}
	base, err := presentation.NewContextOperations(presentation.ContextOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, ordinary, ordinary)
	if err != nil {
		t.Fatal(err)
	}
	aggregate, err := presentation.NewInvestigationOperations(base, nil)
	if err != nil {
		t.Fatal(err)
	}
	saves, err := presentation.NewRecordingSaveOperations(presentation.RecordingSaveOperationsConfig{PublicOrigin: server.URL, Now: time.Now, NewID: func() string { return "00000000-0000-4000-8000-000000000099" }}, maximumRecordingSave{&mcpRecordingFixture{}})
	if err != nil {
		t.Fatal(err)
	}
	composed, err := presentation.NewInvestigationRecordingSaveOperations(aggregate, saves)
	if err != nil {
		t.Fatal(err)
	}
	handler, err = NewContextHandler(Config{PublicOrigin: server.URL, Issuer: "https://id.example.invalid/realm", Version: "test", MaxConcurrent: 4, MaxPerIdentity: 2}, resolverFunc(func(context.Context, string) (identity.Identity, error) {
		i := testIdentity()
		i.Scopes = append(i.Scopes, "evidence:capture")
		return i, nil
	}), composed)
	if err != nil {
		t.Fatal(err)
	}
	handler.Report = func(s string) { t.Log("MCP stage:", s) }
	observer := &recordingFrameObserver{next: bearerTransport{server.Client().Transport}}
	hc := *server.Client()
	hc.Transport = observer
	client := sdk.NewClient(&sdk.Implementation{Name: "bounded-source-preview", Version: "1"}, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: server.URL + Path, HTTPClient: &hc, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	handles := []string{}
	for i := 0; i < 16; i++ {
		handles = append(handles, strings.Repeat("h", 125)+fmt.Sprintf("%03d", i))
	}
	called, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "preview_recording_save", Arguments: map[string]any{"recording_handles": handles}})
	if err != nil || called.IsError || len(called.Content) != 1 || called.StructuredContent == nil {
		t.Fatal("actual maximum SDK call", err, called)
	}
	text, ok := called.Content[0].(*sdk.TextContent)
	if !ok {
		t.Fatal("text compatibility missing")
	}
	var fromText map[string]any
	if json.Unmarshal([]byte(text.Text), &fromText) != nil {
		t.Fatal("invalid canonical text result")
	}
	structured, _ := json.Marshal(called.StructuredContent)
	var fromStructured map[string]any
	if json.Unmarshal(structured, &fromStructured) != nil || !reflect.DeepEqual(fromText, fromStructured) {
		t.Fatal("SDK structured/text results differ")
	}
	if fromText["status"] != "ok" {
		t.Fatal("maximum preview rejected", text.Text)
	}
	data := fromText["data"].(map[string]any)
	actions := data["capture_assessment"].(map[string]any)["actions"].([]any)
	if len(actions) != 16 || len(data["selected_recordings"].([]any)) != 16 || len(data["windows"].([]any)) != 16 {
		t.Fatal("maximum preview lost sources")
	}
	for _, a := range actions {
		row := a.(map[string]any)
		if len(row["recording_handle"].(string)) != 128 || len(row["retention"].(map[string]any)["policyDigests"].([]any)) != 64 {
			t.Fatal("source disclosures were truncated")
		}
	}
	if observer.maximum.Load() > MaxRecordingSavePreviewResponseBytes {
		t.Fatal("SDK frame exceeded dedicated bound")
	}
	t.Logf("actualSDK maximum16-source canonical bytes=%d full duplicated SDK frame=%d; no collector measurement", len(text.Text), observer.maximum.Load())
}
func TestRecordingSaveFrameBudgetDoesNotWidenOtherOperations(t *testing.T) {
	ordinary := newBoundedResponse()
	if _, err := ordinary.Write(make([]byte, MaxResponseBytes+1)); err == nil {
		t.Fatal("ordinary response cap widened")
	}
	preview := newBoundedResponse()
	preview.limit = MaxRecordingSavePreviewResponseBytes
	if _, err := preview.Write(make([]byte, MaxRecordingSavePreviewResponseBytes)); err != nil {
		t.Fatal(err)
	}
	if _, err := preview.Write([]byte{0}); err == nil {
		t.Fatal("one over preview frame cap accepted")
	}
}
