package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	captures "asservat.local/asservat/internal/application/capture"
	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/console"
	"asservat.local/asservat/internal/domain/artifact"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/browser"
	"asservat.local/asservat/internal/transport/presentation"
)

// TestConsoleBrowserWithBuiltPackage uses the actual packaged console and
// browser HTTP/session transport. Its current-identity service and sign-in are
// explicitly synthetic: this is browser/CSP/CSRF/UX evidence, not IdP, SQL,
// protected installation, capture or disclosure qualification.
func TestConsoleBrowserWithBuiltPackage(t *testing.T) {
	if os.Getenv("ASSERVAT_CONSOLE_BROWSER_TEST") != "1" {
		t.Skip("set ASSERVAT_CONSOLE_BROWSER_TEST=1 after building web/dist")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	host, _, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("console fixture must listen exclusively on loopback")
	}
	origin := "https://" + server.Listener.Addr().String()
	static, err := console.New(origin, os.DirFS(filepath.Join(root, "web", "dist")))
	if err != nil {
		t.Fatalf("production console package required: %v", err)
	}
	sessions := &consoleSyntheticSessions{origin: origin, state: "revoked", expiresAt: time.Now().Add(2 * time.Minute)}
	sessionHandler := browser.SessionHandler{Origin: origin, Issuer: "https://identity.invalid", Sessions: sessions}
	// Test-only typed services model a single accepted request and an uncertain
	// reply. Production HTTP, current-identity, CSRF and canonical projection are
	// exercised without claiming SQL/admission/execution qualification.
	captureService := &consoleSyntheticCaptures{state: "ready"}
	operations, err := presentation.NewContextOperationsWithHistory(presentation.ContextOperationsConfig{PublicOrigin: origin, CollectionEnabled: true, Now: time.Now, NewID: func() string { return consoleCaptureID(500) }}, captureService, captureService, &consoleSyntheticHistory{captures: captureService})
	if err != nil {
		t.Fatal(err)
	}
	caseService := &consoleSyntheticCases{state: "ready", expiresAt: time.Now().Add(time.Hour)}
	caseOperations, err := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: origin, Now: time.Now, NewID: func() string { return consoleCaptureID(501) }}, caseService)
	if err != nil {
		t.Fatal(err)
	}
	composed, err := presentation.NewInvestigationOperations(operations, caseOperations)
	if err != nil {
		t.Fatal(err)
	}
	// ADR-232 share operations on the same browser route (synthetic service).
	shareOperations, err := presentation.NewShareOperations(origin, time.Now, func() string { return consoleCaptureID(502) }, &consoleSyntheticShares{})
	if err != nil {
		t.Fatal(err)
	}
	if composed, err = presentation.NewInvestigationShareOperations(composed, shareOperations); err != nil {
		t.Fatal(err)
	}
	grantOperations, managerGrants := newConsoleManagerGrants(t, origin)
	if composed, err = presentation.NewInvestigationGrantOperations(composed, grantOperations); err != nil {
		t.Fatal(err)
	}
	if composed, err = presentation.NewInvestigationPolicyOperations(composed, newConsolePolicyStatus(t, origin, managerGrants)); err != nil {
		t.Fatal(err)
	}
	investigations, err := browser.NewInvestigationHandler(sessionHandler, composed, 4)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/test/capture" || r.URL.Path == "/test/capture-stats" {
			captureService.control(w, r, origin)
			return
		}
		if r.URL.Path == "/test/evidence" || r.URL.Path == "/test/evidence-stats" {
			caseService.control(w, r, origin)
			return
		}
		if r.URL.Path == "/test/policy-grant-stats" {
			managerGrants.stats(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/test/") {
			// These test controls exist only in this _test.go file, on an owned
			// temporary loopback listener. No product route imports this service.
			sessions.control(w, r)
			return
		}
		if r.URL.Path == "/api/v1/session" || strings.HasPrefix(r.URL.Path, "/auth/") {
			sessionHandler.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/operations/") {
			investigations.ServeHTTP(w, r)
			return
		}
		static.ServeHTTP(w, r)
	})
	server.StartTLS()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", filepath.Join(root, "web", "scripts", "browser-test.mjs"), origin)
	cmd.Dir = root
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		// Cancel the browser descendants as well as Node on fixture timeout.
		if e := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); errors.Is(e, syscall.ESRCH) {
			return os.ErrProcessDone
		} else {
			return e
		}
	}
	cmd.WaitDelay = 5 * time.Second
	var output consoleBoundedOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		t.Fatalf("console browser test failed: %v\n%s", err, output.String())
	}
	t.Logf("Synthetic current identity, capture and C16 case data; actual Go TLS/static/session/operations and built React console:\n%s", output.String())
}

type consoleBoundedOutput struct{ bytes.Buffer }

func (o *consoleBoundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := (128 << 10) - o.Len()
	if remaining > 0 {
		_, _ = o.Buffer.Write(p[:min(len(p), remaining)])
	}
	return n, nil
}

type consoleSyntheticSessions struct {
	mu        sync.Mutex
	origin    string
	state     string
	returnTo  string
	expiresAt time.Time
	stats     struct {
		Resolve int `json:"resolve_calls"`
		Refresh int `json:"refresh_calls"`
		CSRF    int `json:"csrf_calls"`
		Logout  int `json:"logout_calls"`
		Login   int `json:"login_calls"`
	}
}

func (s *consoleSyntheticSessions) Begin(_ context.Context, returnTo string) (app.LoginRedirect, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !app.LocalReturnPath(returnTo) {
		return app.LoginRedirect{}, identity.ErrInvalid
	}
	s.returnTo = returnTo
	s.stats.Login++
	return app.LoginRedirect{URL: s.origin + "/test/sign-in", Browser: strings.Repeat("B", 43), State: strings.Repeat("S", 43), ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func (s *consoleSyntheticSessions) Complete(context.Context, string, string, string) (app.LoginResult, error) {
	return app.LoginResult{}, identity.ErrDenied
}

func (s *consoleSyntheticSessions) current(cookie string) bool {
	return cookie == strings.Repeat("A", 43) && s.state != "revoked" && time.Now().Before(s.expiresAt)
}

func (s *consoleSyntheticSessions) Resolve(_ context.Context, cookie string, refresh bool) (app.SessionView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Resolve++
	if refresh {
		s.stats.Refresh++
	}
	if !s.current(cookie) {
		return app.SessionView{}, identity.ErrDenied
	}
	if s.state == "unavailable" {
		return app.SessionView{}, identity.ErrUnavailable
	}
	if s.state == "expired-access" {
		if !refresh {
			return app.SessionView{}, identity.ErrDenied
		}
		s.state = "ready"
	}
	now := time.Now()
	return app.SessionView{Identity: identity.Identity{Principal: identity.Principal{Issuer: "https://identity.invalid", Subject: "synthetic-developer", ClientID: "console", Kind: identity.Human}, Policy: identity.Revision{UID: "synthetic-policy", Generation: 1, Digest: [32]byte{1}}, Scopes: []string{"evidence:read", "evidence:capture", "evidence:share"}, Groups: []string{"maintainers"}, VerifiedAt: now, ValidUntil: identity.Earlier(now.Add(5*time.Second), s.expiresAt)}, CSRF: strings.Repeat("C", 43), ExpiresAt: s.expiresAt}, nil
}

func (s *consoleSyntheticSessions) CSRF(_ context.Context, cookie string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.CSRF++
	if !s.current(cookie) {
		return "", identity.ErrDenied
	}
	if s.state == "csrf-busy-once" {
		s.state = "ready"
		return "", identity.ErrSessionBusy
	}
	return strings.Repeat("C", 43), nil
}

func (s *consoleSyntheticSessions) CheckCSRF(_ context.Context, cookie, csrf string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.current(cookie) || csrf != strings.Repeat("C", 43) {
		return identity.ErrDenied
	}
	if s.state == "logout-check-busy-once" {
		s.state = "ready"
		return identity.ErrSessionBusy
	}
	return nil
}

func (s *consoleSyntheticSessions) End(_ context.Context, cookie string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.current(cookie) {
		return identity.ErrDenied
	}
	s.stats.Logout++
	s.state = "revoked"
	return nil
}

func (s *consoleSyntheticSessions) BackchannelLogout(context.Context, string) error {
	return identity.ErrDenied
}

func (s *consoleSyntheticSessions) control(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "application/json")
	if r.TLS == nil || "https://"+r.Host != s.origin || r.URL.RawQuery != "" {
		w.WriteHeader(400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.URL.Path {
	case "/test/sign-in":
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		s.state, s.expiresAt = "ready", time.Now().Add(2*time.Minute)
		http.SetCookie(w, &http.Cookie{Name: browser.SessionCookie, Value: strings.Repeat("A", 43), Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: s.expiresAt})
		returnTo := s.returnTo
		if returnTo == "" {
			returnTo = "/"
		}
		http.Redirect(w, r, returnTo, http.StatusSeeOther)
	case "/test/state":
		if r.Method != "POST" || r.Header.Get("Origin") != s.origin {
			w.WriteHeader(403)
			return
		}
		var v struct {
			State       string `json:"state"`
			ExpiresInMS *int   `json:"expires_in_ms,omitempty"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&v); err != nil || (v.ExpiresInMS != nil && (*v.ExpiresInMS < 1 || *v.ExpiresInMS > 120000)) {
			w.WriteHeader(400)
			return
		}
		if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
			w.WriteHeader(400)
			return
		}
		switch v.State {
		case "ready", "unavailable", "revoked", "expired-access", "csrf-busy-once", "logout-check-busy-once":
			s.state = v.State
		default:
			w.WriteHeader(400)
			return
		}
		if v.ExpiresInMS != nil {
			s.expiresAt = time.Now().Add(time.Duration(*v.ExpiresInMS) * time.Millisecond)
		}
		w.WriteHeader(204)
	case "/test/stats":
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		_ = json.NewEncoder(w).Encode(s.stats)
	default:
		w.WriteHeader(404)
	}
}

func consoleCaptureID(n int) string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", n)
}

// Synthetic state lives only in this test process. A successful response is
// never evidence that a Kubernetes read, SQL admission or capture occurred.
type consoleSyntheticCaptures struct {
	mu               sync.Mutex
	state            string
	preview, key     string
	lostReply        bool
	lostClosureReply bool
	closed           map[string]bool
	drafts           map[string]bool
	resolutions      []string
	continuations    []string
	requests         []string
	requestedSeconds int64
	previews         int
	historyMode      string
}

func (s *consoleSyntheticCaptures) CheckDiagnostic(ctx context.Context, current app.CurrentIdentity, _ targets.WorkloadRequest) (time.Time, error) {
	started := time.Now()
	i, err := current.ResolveIdentity(ctx)
	if err != nil {
		return time.Time{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == "unavailable" {
		return time.Time{}, capture.ErrUnavailable
	}
	return identity.Earlier(started.Add(5*time.Second), i.ValidUntil), nil
}

func (s *consoleSyntheticCaptures) Preview(ctx context.Context, current app.CurrentIdentity, in capture.ContextIntent) (captures.ContextPreviewResult, error) {
	until, err := s.CheckDiagnostic(ctx, current, in.Target)
	if err != nil {
		return captures.ContextPreviewResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.previews++
	s.requestedSeconds = in.RequestedSeconds
	now := time.Now().UTC()
	seconds := in.RequestedSeconds
	if seconds == 0 {
		seconds = 3600
	}
	if s.drafts == nil {
		s.drafts = make(map[string]bool)
	}
	previewID := consoleCaptureID(172 + s.previews)
	s.drafts[previewID] = true
	p := capture.ContextPreview{ID: previewID, Deadline: now.Add(5 * time.Minute), ScopeDigest: artifact.Digest{1}, Target: targets.Request{ClusterID: in.Target.ClusterID, Namespace: configuration.NamespaceRef{Name: in.Target.Namespace, UID: "synthetic-namespace-uid"}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: in.Target.Name, UID: "synthetic-workload-uid"}, PodName: in.Target.Name + "-a", PodUID: "synthetic-pod-uid"}}
	a := planning.ContextAssessment{ID: consoleCaptureID(174), PlanDigest: p.ScopeDigest, RulesDigest: artifact.Digest{2}, CapabilityDigest: artifact.Digest{3}, GeneratedAt: now, ValidUntil: until, OutputLimit: 4096,
		Impact:    planning.AssessmentImpact{Level: "unknown", HasUnknowns: true, Effects: []string{"collectorMemory", "storageIO", "uploadContention"}, Explanation: "Uses the Kubernetes API and collector. Current load and combined overhead are unmeasured."},
		Exposure:  planning.AssessmentExposure{Classification: "potentialPersonalData", Basis: "conservativeMechanism", RetainedPossible: []string{"personalIdentifiers", "networkAddresses", "paths"}, TransientOnly: []string{"userContent", "credentials", "unknownApplicationData"}, UnknownContent: true},
		Retention: planning.AssessmentRetention{AccessAgeSeconds: seconds, DeleteAgeSeconds: seconds + 300, MaximumAgeSeconds: 86400, DeletionBudgetSeconds: 300, PolicyDigests: []artifact.Digest{{4}}}}
	return captures.ContextPreviewResult{Preview: p, Assessment: a, ValidUntil: until}, nil
}

func (s *consoleSyntheticCaptures) Request(ctx context.Context, current app.CurrentIdentity, preview, key string) (capture.Accepted, error) {
	started := time.Now()
	i, err := current.ResolveIdentity(ctx)
	if err != nil {
		return capture.Accepted{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, key)
	if s.closed[preview] {
		return capture.Accepted{}, capture.ErrConflict
	}
	if !s.drafts[preview] {
		return capture.Accepted{}, capture.ErrUnavailable
	}
	if s.state == "reject-request" || s.state == "lost-closure" {
		return capture.Accepted{}, capture.ErrChanged
	}
	if s.key != "" && (s.preview != preview || s.key != key) {
		return capture.Accepted{}, capture.ErrConflict
	}
	s.preview, s.key = preview, key
	if s.state == "lost-reply-always" || (s.state == "lost-reply" && !s.lostReply) {
		s.lostReply = true
		return capture.Accepted{}, capture.ErrUnavailable
	}
	return capture.Accepted{CaptureID: consoleCaptureID(8), MetadataValidUntil: identity.Earlier(started.Add(5*time.Second), i.ValidUntil)}, nil
}

// This models only explicit same-key continuation of an already accepted
// synthetic receipt. Real execution/keys are never supplied by this fixture.
func (s *consoleSyntheticCaptures) Continue(ctx context.Context, current app.CurrentIdentity, preview, key string) (capture.Accepted, error) {
	started := time.Now()
	i, err := current.ResolveIdentity(ctx)
	if err != nil {
		return capture.Accepted{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	until := identity.Earlier(started.Add(5*time.Second), i.ValidUntil)
	if ctx.Err() != nil || !time.Now().Before(until) || s.state == "unavailable" || s.key == "" || s.key != key || s.preview != preview || s.closed[preview] {
		return capture.Accepted{}, capture.ErrUnavailable
	}
	s.continuations = append(s.continuations, preview+":"+key)
	return capture.Accepted{CaptureID: consoleCaptureID(8), MetadataValidUntil: until}, nil
}

// The fixture models only the accepted-or-closed output contract. Atomic SQL
// admission/closure races and authorization are qualified by separate tests.
func (s *consoleSyntheticCaptures) ResolveContextRequest(ctx context.Context, current app.CurrentIdentity, preview, key string) (capture.ContextRequestDisposition, error) {
	started := time.Now()
	i, err := current.ResolveIdentity(ctx)
	if err != nil {
		return capture.ContextRequestDisposition{}, err
	}
	until := identity.Earlier(started.Add(5*time.Second), i.ValidUntil)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil || !time.Now().Before(until) {
		return capture.ContextRequestDisposition{}, capture.ErrUnavailable
	}
	s.resolutions = append(s.resolutions, preview+":"+key)
	if s.state == "unavailable" || s.state == "resolve-unavailable" || !s.drafts[preview] {
		return capture.ContextRequestDisposition{}, capture.ErrUnavailable
	}
	if s.key != "" && s.preview == preview {
		return capture.ContextRequestDisposition{State: capture.RequestAccepted, Accepted: &capture.Accepted{CaptureID: consoleCaptureID(8), MetadataValidUntil: until}, ValidUntil: until}, nil
	}
	if s.closed == nil {
		s.closed = make(map[string]bool)
	}
	s.closed[preview] = true
	if s.state == "lost-closure" && !s.lostClosureReply {
		s.lostClosureReply = true
		return capture.ContextRequestDisposition{}, capture.ErrUnavailable
	}
	return capture.ContextRequestDisposition{State: capture.RequestClosed, ValidUntil: until}, nil
}

func (s *consoleSyntheticCaptures) Get(ctx context.Context, current app.CurrentIdentity, id string) (capture.ContextProgress, error) {
	started := time.Now()
	i, err := current.ResolveIdentity(ctx)
	if err != nil {
		return capture.ContextProgress{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == "unavailable" || s.key == "" || id != consoleCaptureID(8) {
		return capture.ContextProgress{}, capture.ErrUnavailable
	}
	p := capture.ContextProgress{CaptureID: id, Revision: 1, Phase: "Pending", ActionPhase: "Pending", ReasonCode: "DispatchUnconfirmed", RetryAfterSeconds: 1, ValidUntil: identity.Earlier(started.Add(5*time.Second), i.ValidUntil)}
	if s.historyMode == "history-ready" || s.historyMode == "history-large" {
		p.HistoryState = "available"
	} else if s.historyMode != "" {
		p.HistoryState = "unavailable"
	}
	if s.state == "finalizing" {
		p.Revision, p.Phase, p.ActionPhase, p.ReasonCode = 2, "Finalizing", "Finalizing", "VerificationPending"
	}
	if s.state == "evidence-ready" {
		p.Revision, p.Phase, p.ActionPhase, p.ReasonCode, p.RetryAfterSeconds = 3, "Succeeded", "Succeeded", "", 0
		p.CaseID = consoleCaptureID(80)
	}
	return p, nil
}

func (s *consoleSyntheticCaptures) control(w http.ResponseWriter, r *http.Request, origin string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.TLS == nil || "https://"+r.Host != origin || r.URL.RawQuery != "" {
		w.WriteHeader(400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.URL.Path == "/test/capture-stats" && r.Method == "GET" {
		_ = json.NewEncoder(w).Encode(map[string]any{"request_keys": s.requests, "requested_retention_seconds": s.requestedSeconds, "previews": s.previews, "resolution_pairs": s.resolutions, "continuation_pairs": s.continuations})
		return
	}
	if r.URL.Path != "/test/capture" || r.Method != "POST" || r.Header.Get("Origin") != origin {
		w.WriteHeader(403)
		return
	}
	var input struct {
		State string `json:"state"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	dec.DisallowUnknownFields()
	if dec.Decode(&input) != nil || !errors.Is(dec.Decode(new(any)), io.EOF) {
		w.WriteHeader(400)
		return
	}
	switch input.State {
	case "history-ready", "history-large", "history-unavailable", "history-expired":
		s.historyMode = input.State
	case "ready", "unavailable", "lost-reply", "lost-reply-always", "finalizing", "evidence-ready", "reject-request", "lost-closure", "resolve-unavailable":
		s.state = input.State
	default:
		w.WriteHeader(400)
		return
	}
	w.WriteHeader(204)
}
