package integration

// The actual compiler, C20 projection, Go TLS/session/CSRF route and built React
// are composed here. Identity, target, retention and approval persistence are
// synthetic; this fixture performs no capture, SQL, query or native download.
import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	captureapp "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/console"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/browser"
	"asservat.local/asservat/internal/transport/presentation"
)

type consoleArgumentCurrent struct{ sessions *consoleSyntheticSessions }

func (c consoleArgumentCurrent) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	v, err := c.sessions.Resolve(ctx, strings.Repeat("A", 43), false)
	return v.Identity, err
}

type consoleArgumentRequest struct {
	Preview string                     `json:"preview"`
	Key     string                     `json:"key"`
	Access  authorization.ResultAccess `json:"access"`
}

type consoleArgumentCaptures struct {
	*consoleSyntheticCaptures
	mu       sync.Mutex
	profile  planning.CatalogProfile
	previews int
	preview  string
	action   string
	approved bool
	requests []consoleArgumentRequest
}

func newConsoleArgumentCaptures(t *testing.T) *consoleArgumentCaptures {
	t.Helper()
	definition, err := manualArgumentsProfileDefinition()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"name": manualArgumentsProfile, "version": "v1", "definition": definition})
	if err != nil {
		t.Fatal(err)
	}
	return &consoleArgumentCaptures{consoleSyntheticCaptures: &consoleSyntheticCaptures{state: "ready"},
		profile: planning.CatalogProfile{Ref: planning.ProfileRef{Catalog: "namespace", Name: manualArgumentsProfile, Version: "v1"}, SourceClusterID: consoleCaptureID(1), SourceNamespaceUID: consoleCaptureID(2), SourceUID: "synthetic-argument-profile", Document: raw, Enabled: true}}
}

func (s *consoleArgumentCaptures) CaptureProfiles(ctx context.Context, current identities.CurrentIdentity, target targets.WorkloadRequest, catalog string) ([]compiler.ProfileDescription, time.Time, error) {
	until, err := s.CheckDiagnostic(ctx, current, target)
	return compiler.DescribeProfiles(catalog, []planning.CatalogProfile{s.profile}), until, err
}
func (s *consoleArgumentCaptures) CaptureProfile(ctx context.Context, current identities.CurrentIdentity, target targets.WorkloadRequest, ref planning.ProfileRef) (compiler.ProfileDescription, time.Time, error) {
	rows, until, err := s.CaptureProfiles(ctx, current, target, ref.Catalog)
	for _, row := range rows {
		if row.Ref == ref {
			return row, until, err
		}
	}
	return compiler.ProfileDescription{}, until, capture.ErrProfileNotFound
}

func (s *consoleArgumentCaptures) PreviewComposition(ctx context.Context, current identities.CurrentIdentity, intent capture.ContextIntent) (captureapp.RecorderPreviewResult, error) {
	i, err := current.ResolveIdentity(ctx)
	if err != nil || intent.Composition == nil {
		return captureapp.RecorderPreviewResult{}, capture.ErrInvalid
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	target := targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution,
		Request: targets.Request{ClusterID: intent.Target.ClusterID, Namespace: configuration.NamespaceRef{Name: intent.Target.Namespace, UID: consoleCaptureID(2)}, Workload: configuration.WorkloadRef{Kind: intent.Target.Kind, Name: intent.Target.Name, UID: consoleCaptureID(3)}, PodName: "api-a", PodUID: consoleCaptureID(4)},
		Pin:     artifact.PinnedPod{Namespace: intent.Target.Namespace, NamespaceUID: consoleCaptureID(2), Name: "api-a", UID: consoleCaptureID(4), ControllerUID: consoleCaptureID(5)}, PodResourceVersion: "1", WorkloadResourceVersion: "2", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	retention, err := privacy.Resolve(privacy.PolicySet{Target: target.Target(), Revision: identity.Revision{UID: "synthetic-set", Generation: 1, Digest: artifact.Digest{7}}, ObservedAt: now, FreshUntil: now.Add(30 * time.Second), Complete: true, Policies: []privacy.Policy{{Revision: identity.Revision{UID: "synthetic-baseline", Generation: 1, Digest: artifact.Digest{4}}, Baseline: true, PurposeRef: "diagnostics", DefaultSeconds: 3600, MaximumSeconds: 86400, DeletionBudgetSeconds: 300}}}, privacy.Input{Target: target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "syscallTrace", AnchorAt: now}, now)
	if err != nil {
		return captureapp.RecorderPreviewResult{}, err
	}
	composition := intent.Composition.Clone()
	composition.Resolved = []planning.CatalogProfile{s.profile}
	plan, err := compiler.CompileRecorder(planning.RecorderInput{CaptureID: consoleCaptureID(45), Executor: i.Principal, Target: target, Composition: *composition, Retention: retention, Deadline: now.Add(time.Minute), NodeRecorder: true}, installedArgumentsCompiler{}, now)
	if err != nil {
		return captureapp.RecorderPreviewResult{}, err
	}
	assessment, err := compiler.AssessRecorder(plan, consoleCaptureID(46), now)
	if err != nil {
		return captureapp.RecorderPreviewResult{}, err
	}
	s.mu.Lock()
	s.previews++
	s.preview, s.action = consoleCaptureID(50+s.previews), plan.Actions[0].ID
	preview := capture.ContextPreview{ID: s.preview, Intent: intent, Deadline: now.Add(5 * time.Minute), ScopeDigest: plan.ScopeDigest, Target: target.Request}
	s.mu.Unlock()
	s.consoleSyntheticCaptures.mu.Lock()
	s.drafts = map[string]bool{preview.ID: true}
	s.consoleSyntheticCaptures.mu.Unlock()
	return captureapp.RecorderPreviewResult{Preview: preview, Plan: plan, Assessment: assessment, ValidUntil: identity.Earlier(now.Add(5*time.Second), i.ValidUntil), Recordable: true}, nil
}

func cloneConsoleArgumentAccess(a authorization.ResultAccess) authorization.ResultAccess {
	a.ActionIDs, a.Operations, a.ClientIDs = slices.Clone(a.ActionIDs), slices.Clone(a.Operations), slices.Clone(a.ClientIDs)
	return a
}
func (s *consoleArgumentCaptures) RequestWithResultAccess(ctx context.Context, current identities.CurrentIdentity, preview, key string, access *authorization.ResultAccess) (capture.Accepted, error) {
	i, err := current.ResolveIdentity(ctx)
	if err != nil || access == nil {
		return capture.Accepted{}, capture.ErrDenied
	}
	s.mu.Lock()
	if preview != s.preview || !slices.Equal(access.ActionIDs, []string{s.action}) || !slices.Equal(access.ClientIDs, []string{i.Principal.ClientID}) || !slices.Contains(access.Operations, "syscall_query") || len(access.Operations) > 2 || access.MaxArtifacts != 1 || access.MaxBytes < 24576 || access.MaxOperations < 1 || !access.NotAfter.After(time.Now()) {
		s.mu.Unlock()
		return capture.Accepted{}, authorization.ErrGrantScope
	}
	input := consoleArgumentRequest{preview, key, cloneConsoleArgumentAccess(*access)}
	if len(s.requests) > 0 && !reflect.DeepEqual(input, s.requests[0]) {
		s.mu.Unlock()
		return capture.Accepted{}, authorization.ErrGrantScope
	}
	s.requests = append(s.requests, input)
	approved := s.approved
	s.mu.Unlock()
	if !approved {
		return capture.Accepted{}, authorization.ApprovalPendingError{GrantID: consoleCaptureID(41)}
	}
	return s.consoleSyntheticCaptures.Request(ctx, current, preview, key)
}

func consoleArgumentOperations(t *testing.T, origin string, service *consoleArgumentCaptures) *presentation.ContextOperations {
	t.Helper()
	op, err := presentation.NewContextOperationsWithHistory(presentation.ContextOperationsConfig{PublicOrigin: origin, CollectionEnabled: true, Now: time.Now, NewID: func() string { return consoleCaptureID(500) }}, service, service, nil)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

// This is a genuine compiler -> C20 choice producer regression, not a hand-built
// response. It also runs without the browser gate so setup errors stay local.
func TestConsoleSyscallCaptureAuthoringProducer(t *testing.T) {
	service := newConsoleArgumentCaptures(t)
	sessions := &consoleSyntheticSessions{origin: "https://console.invalid", state: "ready", expiresAt: time.Now().Add(time.Minute)}
	in := manualArgumentsCaptureInput(consoleCaptureID(1), "payments", "api", false)
	raw, _ := json.Marshal(in)
	reply, err := consoleArgumentOperations(t, sessions.origin, service).Call(t.Context(), consoleArgumentCurrent{sessions}, "preview_capture", raw)
	var out struct {
		Status string `json:"status"`
		Data   struct {
			Choices []presentation.RecorderResultAccessAction `json:"result_access_actions"`
		} `json:"data"`
	}
	if err != nil || json.Unmarshal(reply.Body, &out) != nil || out.Status != "ok" || len(out.Data.Choices) != 1 || !slices.Equal(out.Data.Choices[0].Operations, []string{"download_artifact", "syscall_query"}) {
		t.Fatal("actual compiled arguments preview lacks its query choice", err, string(reply.Body))
	}
}

func TestConsoleSyscallCaptureAuthoringWithBuiltPackage(t *testing.T) {
	if os.Getenv("ASSERVAT_CONSOLE_BROWSER_TEST") != "1" {
		t.Skip("set ASSERVAT_CONSOLE_BROWSER_TEST=1 after building web/dist")
	}
	for _, mode := range []string{"query", "both"} {
		t.Run(mode, func(t *testing.T) { consoleSyscallCaptureAuthoring(t, mode) })
	}
}
func consoleSyscallCaptureAuthoring(t *testing.T, mode string) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	origin := "https://" + server.Listener.Addr().String()
	static, err := console.New(origin, os.DirFS(filepath.Join(root, "web", "dist")))
	if err != nil {
		t.Fatal(err)
	}
	sessions := &consoleSyntheticSessions{origin: origin, state: "ready", expiresAt: time.Now().Add(5 * time.Minute)}
	sessionHandler := browser.SessionHandler{Origin: origin, Issuer: "https://identity.invalid", Sessions: sessions}
	service := newConsoleArgumentCaptures(t)
	cases, err := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: origin, Now: time.Now, NewID: func() string { return consoleCaptureID(501) }}, &consoleSyntheticCases{state: "ready", expiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	operations, err := presentation.NewInvestigationOperations(consoleArgumentOperations(t, origin, service), cases)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := browser.NewInvestigationHandler(sessionHandler, operations, 4)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/test/argument-approve" {
			if r.Method != "POST" || r.Header.Get("Origin") != origin || len(r.Header.Values("Authorization")) != 0 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			service.mu.Lock()
			service.approved = true
			service.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/test/") {
			sessions.control(w, r)
		} else if r.URL.Path == "/api/v1/session" || strings.HasPrefix(r.URL.Path, "/auth/") {
			sessionHandler.ServeHTTP(w, r)
		} else if strings.HasPrefix(r.URL.Path, "/api/v1/operations/") {
			handler.ServeHTTP(w, r)
		} else {
			static.ServeHTTP(w, r)
		}
	})
	server.StartTLS()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", filepath.Join(root, "web", "scripts", "syscall-capture-authoring-browser.mjs"), origin, mode)
	cmd.Dir = root
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		} else {
			return err
		}
	}
	cmd.WaitDelay = 5 * time.Second
	var output consoleBoundedOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		t.Fatalf("compiled arguments capture authoring: %v\n%s", err, output.String())
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.previews != 1 || len(service.requests) != 2 || !reflect.DeepEqual(service.requests[0], service.requests[1]) {
		t.Fatal("approval resume replaced original preview or result access", service.previews, service.requests)
	}
	want := []string{"syscall_query"}
	if mode == "both" {
		want = []string{"download_artifact", "syscall_query"}
	}
	if !slices.Equal(service.requests[0].Access.Operations, want) || !slices.Equal(service.requests[0].Access.ClientIDs, []string{"console"}) {
		t.Fatal("submitted different current-client operations", service.requests[0].Access)
	}
	t.Logf("%s: real compiler/C20 preview -> built React -> exact current-client result access -> original ApprovalRequired receipt/resume; synthetic authority only\n%s", mode, output.String())
}
