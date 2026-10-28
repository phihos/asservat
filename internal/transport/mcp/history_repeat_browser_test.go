package mcp

// Real HTTPS/browser session/CSRF/audited presentation/C09 composition, reusing
// the storage-response fixture. History storage, source facts, session identity,
// compiler port and effects are synthetic. Settings clone initial real C09
// canonical recipe/filter/profile output; the storage header is constructed,
// so this does not exercise the accepted writer/snapshot builder. No SQL/S3/collector/installed proof.
import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	access "asservat.local/asservat/internal/application/authorization"
	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/browser"
	"asservat.local/asservat/internal/transport/presentation"
)

type repeatBrowserFacts struct {
	*reserveFacts
	app.RestartObserver // Settings does not resolve a workload listing.
	mu                  sync.Mutex
	preview             value.ContextPreview
	settings            value.CaptureSettings
	settingsError       error
}

func (f *repeatBrowserFacts) ResolveWorkload(ctx context.Context, in targets.WorkloadRequest) (targets.PodResolution, error) {
	p, err := f.reserveFacts.ResolveWorkload(ctx, in)
	p.NodeUID, p.NodeBootID, p.Pin.NodeName = "", "", ""
	p.ExecutionClass = artifact.ContextAPIExecution
	return p, err
}
func (f *repeatBrowserFacts) ResolvePod(ctx context.Context, in targets.Request) (targets.PodResolution, error) {
	p, err := f.reserveFacts.ResolvePod(ctx, in)
	p.NodeUID, p.NodeBootID, p.Pin.NodeName = "", "", ""
	p.ExecutionClass = artifact.ContextAPIExecution
	return p, err
}
func (f *repeatBrowserFacts) ContextCapability(ctx context.Context, t authorization.Target) (planning.ContextCapability, error) {
	c, err := f.reserveFacts.ContextCapability(ctx, t)
	c.ExecutionClass = artifact.ContextAPIExecution
	return c, err
}
func (f *repeatBrowserFacts) IdentityPolicy(context.Context, string) (identity.Policy, error) {
	now := time.Now()
	actor := testIdentity()
	return identity.Policy{Revision: actor.Policy, Issuer: actor.Principal.Issuer, ObservedAt: now, FreshUntil: now.Add(5 * time.Second), Clients: []identity.Client{{ID: actor.Principal.ClientID, Kind: identity.Human, ClassQualified: true}}, EligibleGroups: []string{"maintainers"}, GroupsAtIssueQualified: true, GroupMaxAge: time.Minute, RequireRecordingApproval: true}, nil
}
func (f *repeatBrowserFacts) PacketRecorder(context.Context, targets.PodResolution) error { return nil }
func (f *repeatBrowserFacts) ResolvePacketRecorder(ctx context.Context, r targets.Request) (targets.PodResolution, error) {
	return f.ResolvePod(ctx, r)
}
func (f *repeatBrowserFacts) CompileFilter(string) (planning.CompiledFilter, error) {
	return planning.CompiledFilter{LinkType: planning.FilterLinkType, Snaplen: planning.FilterSnaplen, Program: []planning.BPFInstruction{{Code: 6, K: 65535}}}, nil
}
func (f *repeatBrowserFacts) CreateContextPreview(_ context.Context, p value.ContextPreview) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.preview = p.Clone()
	f.stores.Add(1)
	return nil
}
func (f *repeatBrowserFacts) ListCaptureHistory(context.Context, value.HistoryQuery) (value.HistoryPage, error) {
	return value.HistoryPage{}, value.ErrUnavailable
}
func (f *repeatBrowserFacts) ReadCaptureSettings(_ context.Context, q value.SettingsQuery) (value.CaptureSettings, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if q.Identity.Principal != testIdentity().Principal || q.CaptureID != f.settings.CaptureID {
		return value.CaptureSettings{}, value.ErrDenied
	}
	return f.settings, f.settingsError
}

type repeatBrowserSession struct {
	browser.SessionService
	i identity.Identity
}

func (s repeatBrowserSession) Resolve(context.Context, string, bool) (identities.SessionView, error) {
	i := s.i
	i.Scopes = append(i.Scopes, "evidence:capture")
	return identities.SessionView{Identity: i, CSRF: strings.Repeat("C", 43), ExpiresAt: i.ValidUntil}, nil
}
func (repeatBrowserSession) CheckCSRF(_ context.Context, cookie, csrf string) error {
	if cookie != strings.Repeat("A", 43) || csrf != strings.Repeat("C", 43) {
		return identity.ErrDenied
	}
	return nil
}

func TestHistoryEditedRepeatUsesAuditedBrowserHTTP2AndRealC09(t *testing.T) {
	for _, mode := range []string{"sql-microseconds", "submicrosecond-source"} {
		t.Run(mode, func(t *testing.T) { testHistoryEditedRepeatBrowser(t, mode == "submicrosecond-source") })
	}
}
func testHistoryEditedRepeatBrowser(t *testing.T, nanoseconds bool) {
	facts := &repeatBrowserFacts{reserveFacts: &reserveFacts{}}
	var handler *browser.InvestigationHandler
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	service := app.ContextInvestigation{RootID: reserveID(1), InstallationID: reserveID(2), Previews: facts, Replay: facts, Admission: facts, Targets: facts, Eligibility: access.Evaluator{Permissions: facts, Now: time.Now}, Capabilities: facts, Retention: facts, Storage: facts, Refresh: facts, Processing: facts, Recovery: facts, Recorders: facts, Filters: facts, Approvals: facts, Lifetime: time.Minute, Now: time.Now, NewID: func() string { return reserveID(100 + int(facts.ids.Add(1))) }}
	service.ReportPreviewFailure = func(stage string) { t.Log("preview stage", stage) }
	history := app.ContextHistoryService{RootID: reserveID(1), InstallationID: reserveID(2), Reader: facts, Targets: facts, Workloads: facts, Previews: service, Recovery: facts, Now: time.Now}
	ops, err := presentation.NewContextOperationsWithHistory(presentation.ContextOperationsConfig{PublicOrigin: server.URL, CollectionEnabled: true, Now: time.Now, NewID: func() string { return reserveID(500) }}, service, &mcpCaptureFixture{}, history)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := presentation.NewInvestigationOperations(ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := auditapp.NewOperationMAC("audit-v1", bytes.Repeat([]byte{1}, 32), "accounts-v1", bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer mac.Close()
	gate := &reserveAudit{}
	audited, err := presentation.NewHealthyAuditedOperations(presentation.AuditedOperationsConfig{RootID: reserveID(1), Retention: time.Hour, NormalConcurrency: 1, ResolutionConcurrency: 1, PerPrincipalConcurrency: 1, NormalPerSecond: 10, ResolutionPerSecond: 10, Now: time.Now, NewID: func() string { return reserveID(501) }}, combined, gate, gate, mac)
	if err != nil {
		t.Fatal(err)
	}
	handler, err = browser.NewAuditedInvestigationHandler(browser.SessionHandler{Origin: server.URL, Sessions: repeatBrowserSession{i: testIdentity()}}, audited, 4)
	if err != nil {
		t.Fatal(err)
	}
	handler.Report = func(stage string) { t.Log("browser stage", stage) }
	call := func(name string, input map[string]any) map[string]any {
		t.Helper()
		raw, e := json.Marshal(input)
		if e != nil {
			t.Fatal(e)
		}
		req, e := http.NewRequest("POST", server.URL+"/api/v1/operations/"+name, bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", server.URL)
		req.Header.Set("X-CSRF-Token", strings.Repeat("C", 43))
		req.AddCookie(&http.Cookie{Name: browser.SessionCookie, Value: strings.Repeat("A", 43)})
		response, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		body, e := io.ReadAll(io.LimitReader(response.Body, 128<<10))
		if e != nil {
			t.Fatal(e)
		}
		var out map[string]any
		if response.StatusCode != 200 || response.ProtoMajor != 2 || json.Unmarshal(body, &out) != nil {
			t.Fatalf("HTTPS %s route status=%d proto=%d", name, response.StatusCode, response.ProtoMajor)
		}
		return out
	}
	target := map[string]string{"cluster_id": reserveID(4), "namespace": "payments", "kind": "Deployment", "name": "api"}
	composition := map[string]any{"components": []any{map[string]any{"id": "network", "profileRef": map[string]string{"catalog": "builtin", "name": "network-connections", "version": "v1"}, "overrides": []any{map[string]any{"actionID": "sample", "field": "packetFilter", "value": "tcp port 8080"}, map[string]any{"actionID": "sample", "field": "packetAfter", "value": "2s"}, map[string]any{"actionID": "sample", "field": "actionTimeout", "value": "10s"}}}}, "maxTotalBytes": 16 << 20, "maxDuration": "10s"}
	if out := call("preview_capture", map[string]any{"target_ref": target, "profile_composition": composition, "requested_retention_seconds": 600}); out["status"] != "ok" || out["data"].(map[string]any)["approval_required"] != true {
		t.Fatal("original preview", out["data"])
	}
	facts.mu.Lock()
	p := facts.preview.Clone()
	facts.mu.Unlock()
	var scope struct{ Recipe, Filters, ProfileComposition json.RawMessage }
	if err = json.Unmarshal(p.CanonicalScope, &scope); err != nil {
		t.Fatal(err)
	}
	var provenance struct {
		Resolved []struct{ DefinitionDigest string } `json:"resolvedProfiles"`
	}
	if err = json.Unmarshal(scope.ProfileComposition, &provenance); err != nil || len(provenance.Resolved) != 1 {
		t.Fatal("original profile provenance", err)
	}
	image := artifact.Digest{3}
	pins, _ := json.Marshal([]map[string]string{{"role": "collector", "digest": hex.EncodeToString(image[:])}, {"role": "captureProfile", "digest": provenance.Resolved[0].DefinitionDigest}})
	facts.mu.Lock()
	sourceExpiry := time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute)
	if nanoseconds {
		sourceExpiry = sourceExpiry.Add(777 * time.Nanosecond)
	}
	facts.settings = value.CaptureSettings{CaptureID: p.CaptureID, Origin: value.HistoryManual, ClusterID: reserveID(4), NamespaceUID: "ns", WorkloadUID: "deployment", Namespace: "payments", WorkloadKind: "Deployment", WorkloadName: "api", AcceptedAt: p.CreatedAt, ExpiresAt: sourceExpiry, ValidUntil: time.Now().Add(5 * time.Second), SettingsKey: artifact.Digest{8}, ExecutionDigest: p.ScopeDigest, Composition: p.Intent.Composition.Clone(), CompositionJSON: scope.ProfileComposition, RecipeJSON: scope.Recipe, FrozenFilters: scope.Filters, DependencyJSON: pins, RequestedSeconds: 600}
	facts.settings.TargetJSON = []byte(`{"namespace":"payments","workloadRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"api","uid":"deployment"},"maxPods":1,"selection":"allWithinLimit","adoption":"pinUID"}`)
	facts.mu.Unlock()
	if out := call("get_capture_settings", map[string]any{"capture_id": p.CaptureID}); out["status"] != "ok" {
		t.Fatal("settings route", out["data"])
	}
	edits := composition["components"].([]any)[0].(map[string]any)["overrides"].([]any)
	edits[0].(map[string]any)["value"] = "tcp dst port 8080"
	edits[1].(map[string]any)["value"] = "3s"
	repeat := map[string]any{"target_ref": target, "profile_composition": composition, "repeated_from_capture_id": p.CaptureID}
	out := call("preview_capture", repeat)
	if out["status"] != "ok" {
		t.Fatal("edited repeat route", out["data"])
	}
	data := out["data"].(map[string]any)
	deadline, e := time.Parse(time.RFC3339Nano, data["expires_at"].(string))
	if e != nil || deadline.After(sourceExpiry) || deadline.Nanosecond()%1000 != 0 {
		t.Fatal("repeat extended or failed to normalize original bound", e)
	}
	if data["approval_required"] != true || data["repeated_from_capture_id"] != p.CaptureID || data["execution_digest"] == hex.EncodeToString(p.ScopeDigest[:]) {
		t.Fatal("repeat did not create a fresh edited review")
	}
	facts.mu.Lock()
	edited := facts.preview.Clone()
	facts.settingsError = value.ErrSettingsUnavailable
	facts.mu.Unlock()
	if edited.Intent.RepeatedFrom == nil || !edited.Intent.RepeatedFrom.ExpiresAt.Equal(sourceExpiry.UTC().Truncate(time.Microsecond)) || edited.Intent.Composition.Components[0].Edits[0].Text != "tcp dst port 8080" || edited.Intent.Composition.Components[0].Edits[1].Text != "3s" {
		t.Fatal("route lost authored edits")
	}
	out = call("preview_capture", repeat)
	if out["status"] != "error" || out["data"].(map[string]any)["code"] != "ParametersUnavailable" {
		t.Fatal("settings refusal not classified", out["data"])
	}
	facts.mu.Lock()
	facts.settingsError = nil
	facts.settings.ExpiresAt = time.Now().Add(-time.Millisecond)
	facts.mu.Unlock()
	out = call("preview_capture", repeat)
	if out["status"] != "error" {
		t.Fatal("expired source authorized new review")
	}
	if gate.begins.Load() != 5 || gate.finishes.Load() != 5 || facts.admissions.Load() != 0 || facts.stores.Load() != 2 {
		t.Fatal("repeat route audit/effect boundary", gate.begins.Load(), gate.finishes.Load(), facts.stores.Load())
	}
}
