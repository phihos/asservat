package integration

// Component-only synthetic history services, reached through the actual HTTPS
// browser session/CSRF handlers and built React. These confer no SQL, encryption,
// native collection or installed-runtime qualification.
import (
	"context"
	"encoding/json"
	"strings"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/targets"
)

type consoleSyntheticHistory struct{ captures *consoleSyntheticCaptures }

func (h *consoleSyntheticHistory) List(ctx context.Context, current identities.CurrentIdentity, ref targets.WorkloadRequest, _ []value.HistoryOrigin, _ *value.HistoryCursor, _ int) (value.HistoryPage, error) {
	until, err := h.captures.CheckDiagnostic(ctx, current, ref)
	return value.HistoryPage{Target: authorization.WorkloadScope(ref.ClusterID, "synthetic-namespace-uid", "synthetic-workload-uid"), Entries: []value.HistoryEntry{}, ValidUntil: until}, err
}
func (h *consoleSyntheticHistory) Settings(ctx context.Context, current identities.CurrentIdentity, id string) (value.CaptureSettings, error) {
	ref := targets.WorkloadRequest{ClusterID: consoleCaptureID(1), Namespace: "payments", Kind: "Deployment", Name: "api"}
	until, err := h.captures.CheckDiagnostic(ctx, current, ref)
	if err != nil {
		return value.CaptureSettings{}, err
	}
	h.captures.mu.Lock()
	mode := h.captures.historyMode
	h.captures.mu.Unlock()
	if (mode != "history-ready" && mode != "history-large") || id != consoleCaptureID(8) {
		return value.CaptureSettings{}, value.ErrSettingsUnavailable
	}
	args := make([]string, 30)
	for i := range args {
		args[i] = strings.Repeat("a", 4096)
	}
	recipe, _ := json.Marshal(map[string]any{"description": strings.Repeat("<é>&", 200), "actions": []any{map[string]any{"id": "command", "kind": "command", "parameters": map[string]any{"argv": args, "workingDirectory": "/", "adapter": "podsExec"}, "required": true, "impact": "intrusive", "limits": map[string]any{"maxBytes": 4096, "timeout": "5s"}, "executionMode": "onTrigger"}}, "maxTotalBytes": 4096, "maxDuration": "5s"})
	if mode == "history-ready" {
		recipe = nil
	} // Existing supported pod-status snapshot.
	now := time.Now().UTC()
	return value.CaptureSettings{CaptureID: id, Origin: value.HistoryManual, ClusterID: ref.ClusterID, NamespaceUID: "synthetic-namespace-uid", WorkloadUID: "synthetic-workload-uid", Namespace: ref.Namespace, WorkloadKind: ref.Kind, WorkloadName: ref.Name, AcceptedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour), RequestedSeconds: 3600, ValidUntil: until, RecipeJSON: recipe,
		TargetJSON: []byte(`{"adoption":"pinUID","maxPods":1,"namespace":"payments","selection":"allWithinLimit","workloadRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"api","uid":"synthetic-workload-uid"}}`), DependencyJSON: []byte(`[{"role":"collector","digest":"` + strings.Repeat("a", 64) + `"}]`)}, nil
}
func (h *consoleSyntheticHistory) PreviewRepeat(ctx context.Context, current identities.CurrentIdentity, id string, _ *value.ContextSharing) (app.ContextPreviewResult, value.CaptureSettings, error) {
	s, err := h.Settings(ctx, current, id)
	if err != nil {
		return app.ContextPreviewResult{}, s, err
	}
	// The large canonical command projection tests inspection only. This fixture
	// must not silently repeat it as the supported pod-status diagnostic.
	if len(s.RecipeJSON) > 0 {
		return app.ContextPreviewResult{}, s, value.ErrProfileChanged
	}
	p, err := h.captures.Preview(ctx, current, value.ContextIntent{Target: targets.WorkloadRequest{ClusterID: s.ClusterID, Namespace: s.Namespace, Kind: s.WorkloadKind, Name: s.WorkloadName}, Diagnostic: value.ContextDiagnosticName, RequestedSeconds: s.RequestedSeconds})
	p.Preview.Target.PodName = "api-current"
	p.Preview.Target.PodUID = "synthetic-fresh-pod-uid"
	return p, s, err
}
