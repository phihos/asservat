package integration

import (
	"bytes"
	"context"
	"encoding/json"
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

	app "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/console"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/transport/browser"
	"asservat.local/asservat/internal/transport/presentation"
)

// Controlled service facts only: the actual Go TLS/session/CSRF/rule DTOs and
// built React use the same driver as installed qualification. No SQL/audit or
// protected privacy authority is claimed by this local browser fixture.
func TestConsoleProcessingWithBuiltPackage(t *testing.T) {
	if os.Getenv("ASSERVAT_CONSOLE_BROWSER_TEST") != "1" {
		t.Skip("set ASSERVAT_CONSOLE_BROWSER_TEST=1 after building web/dist")
	}
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
	sessions := &consoleSyntheticSessions{origin: origin, state: "ready", expiresAt: time.Now().Add(3 * time.Minute)}
	session := browser.SessionHandler{Origin: origin, Issuer: "https://identity.invalid", Sessions: sessions}
	facts := &consoleProcessingFacts{}
	changes, err := browser.NewProcessingHandler(session, facts)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := browser.NewProcessingInventoryHandler(session, facts)
	if err != nil {
		t.Fatal(err)
	}
	cases, err := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: origin, Now: time.Now, NewID: func() string { return consoleCaptureID(501) }}, &consoleSyntheticCases{state: "ready", expiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	operations, err := presentation.NewInvestigationOperations(nil, cases)
	if err != nil {
		t.Fatal(err)
	}
	investigations, err := browser.NewInvestigationHandler(session, operations, 4)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == browser.ProcessingChangesPath:
			changes.ServeHTTP(w, r)
		case r.URL.Path == browser.ProcessingRulesPath:
			inventory.ServeHTTP(w, r)
		case r.URL.Path == "/api/v1/session" || strings.HasPrefix(r.URL.Path, "/auth/"):
			session.ServeHTTP(w, r)
		case strings.HasPrefix(r.URL.Path, "/api/v1/operations/"):
			investigations.ServeHTTP(w, r)
		default:
			static.ServeHTTP(w, r)
		}
	})
	server.StartTLS()
	config := map[string]any{"origin": origin, "artifactID": consoleCaptureID(81), "casePath": "/cases/" + consoleCaptureID(80), "cookies": []map[string]any{{"name": browser.SessionCookie, "value": strings.Repeat("A", 43), "url": origin, "secure": true, "httpOnly": true, "sameSite": "Strict"}}}
	private, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	input := append(private, '\n')
	input = append(input, []byte("{\"continue\":true}\n{\"continue\":true}\n")...)
	defer clear(input)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", filepath.Join(root, "web", "scripts", "installed-processing-browser.mjs"))
	cmd.Dir = root
	cmd.Stdin = bytes.NewReader(input)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second
	var output consoleBoundedOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if err = cmd.Run(); err != nil {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		t.Fatalf("controlled processing browser failed: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), `"kind":"complete"`) {
		t.Fatal("processing browser did not complete")
	}
	facts.mu.Lock()
	defer facts.mu.Unlock()
	if len(facts.changes) != 2 || facts.rule.State != "released" || facts.rule.Revision != 2 || facts.changes[0].RequestedArtifactID != consoleCaptureID(81) || facts.changes[0].Scope != (value.ProcessingScope{}) || facts.changes[1].Scope != facts.rule.Scope || facts.changes[1].ExpectedRevision != 1 || facts.changes[0].RequestID == facts.changes[1].RequestID {
		t.Fatal("processing browser changed scope, revision or request identity")
	}
	t.Log("actual compiled React and Go TLS/session/CSRF: case artifact link, explicit restriction, durable inventory reload and exact-revision release; synthetic operator state only")
}

type consoleProcessingFacts struct {
	mu      sync.Mutex
	rule    value.ProcessingInventoryRule
	changes []value.ProcessingChange
}

func (s *consoleProcessingFacts) List(ctx context.Context, current app.CurrentIdentity, q value.ProcessingInventoryQuery) (value.ProcessingInventoryPage, error) {
	if _, err := current.ResolveIdentity(ctx); err != nil {
		return value.ProcessingInventoryPage{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	rules := []value.ProcessingInventoryRule{}
	if s.rule.ID != "" && s.rule.ID > q.After {
		rules = append(rules, s.rule)
	}
	return value.ProcessingInventoryPage{RootID: consoleCaptureID(41), Epoch: consoleCaptureID(42), Initialized: true, Sequence: int64(len(s.changes) + 1), Rules: rules, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}, nil
}
func (s *consoleProcessingFacts) Change(ctx context.Context, current app.CurrentIdentity, c value.ProcessingChange) (value.ProcessingReceipt, error) {
	if _, err := current.ResolveIdentity(ctx); err != nil {
		return value.ProcessingReceipt{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	switch c.Action {
	case "restrict_processing":
		if s.rule.ID != "" || c.ExpectedRevision != 0 || c.RequestedArtifactID != consoleCaptureID(81) {
			return value.ProcessingReceipt{}, value.ErrConflict
		}
		s.rule = value.ProcessingInventoryRule{ID: c.RuleID, State: "restricted", Revision: 1, Scope: value.ProcessingScope{Kind: "artifact", Location: artifact.Location{ClusterID: consoleCaptureID(1), ArtifactID: c.RequestedArtifactID, AttemptID: consoleCaptureID(82)}}, AdministrationUntil: now.Add(time.Hour), RetireBy: now.Add(2 * time.Hour)}
	case "release_processing":
		if c.RuleID != s.rule.ID || c.ExpectedRevision != s.rule.Revision || c.Scope != s.rule.Scope {
			return value.ProcessingReceipt{}, value.ErrConflict
		}
		s.rule.State = "released"
		s.rule.Revision++
	default:
		return value.ProcessingReceipt{}, value.ErrUnavailable
	}
	s.changes = append(s.changes, c)
	return value.ProcessingReceipt{RootID: consoleCaptureID(41), Epoch: consoleCaptureID(42), RequestID: c.RequestID, RuleID: s.rule.ID, OperationID: consoleCaptureID(600 + len(s.changes)), State: s.rule.State, Revision: s.rule.Revision, Sequence: int64(len(s.changes) + 1), ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}, nil
}
