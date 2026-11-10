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
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	app "asservat.local/asservat/internal/application/identity"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/console"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/transport/browser"
	"asservat.local/asservat/internal/transport/presentation"
)

// The compiled React, Go TLS/session/CSRF handlers and audited discovery
// presentation use synthetic privacy authority, lineage and audit effects.
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
	expires := time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)
	facts := &consoleProcessingFacts{expires: expires}
	changes, err := browser.NewProcessingHandler(session, facts)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := browser.NewProcessingInventoryHandler(session, facts)
	if err != nil {
		t.Fatal(err)
	}
	cases, err := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: origin, Now: time.Now, NewID: custodyID}, &consoleSyntheticCases{state: "ready", expiresAt: expires})
	if err != nil {
		t.Fatal(err)
	}
	operations, err := presentation.NewInvestigationOperations(nil, cases)
	if err != nil {
		t.Fatal(err)
	}
	rootID := consoleCaptureID(41)
	discovery, err := presentation.NewProcessingDiscoveryOperations(origin, time.Now, custodyID, privacyapp.ProcessingEvidenceDiscovery{
		RootID: rootID, InstallationID: rootID, Policies: facts, Recovery: facts, Discovery: facts, Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	operations, err = presentation.NewInvestigationProcessingDiscoveryOperations(operations, discovery)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := auditapp.NewOperationMAC("fixture-input", bytes.Repeat([]byte{1}, 32), "fixture-account", bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer mac.Close()
	audited, err := presentation.NewHealthyAuditedOperations(presentation.AuditedOperationsConfig{
		RootID: rootID, Retention: time.Hour, NormalConcurrency: 4, ResolutionConcurrency: 1, PerPrincipalConcurrency: 2,
		NormalPerSecond: 16, ResolutionPerSecond: 1, Now: time.Now, NewID: custodyID,
	}, operations, facts, facts, mac)
	if err != nil {
		t.Fatal(err)
	}
	investigations, err := browser.NewAuditedInvestigationHandler(session, audited, 4)
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
	config := map[string]any{"origin": origin, "artifactID": consoleCaptureID(81), "casePath": "/cases/" + consoleCaptureID(80), "parents": []string{consoleCaptureID(83)}, "cookies": []map[string]any{{"name": browser.SessionCookie, "value": strings.Repeat("A", 43), "url": origin, "secure": true, "httpOnly": true, "sameSite": "Strict"}}}
	private, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	input := append(private, '\n')
	input = append(input, []byte("{\"continue\":true}\n{\"continue\":true}\n{\"continue\":true}\n")...)
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
	out := facts.searchOutcome
	if facts.searchReads != 1 || out.Intent.ID != facts.searchIntent.ID || audit.OperationLane(out.Intent.Name) != "normal" || out.Status != "success" || out.Effect != "none" ||
		!slices.Equal(out.CaseIDs, []string{consoleCaptureID(80)}) || !slices.Equal(out.ArtifactIDs, []string{consoleCaptureID(81)}) || !slices.Equal(out.CaptureIDs, []string{consoleCaptureID(8)}) {
		t.Fatal("discovery did not audit the exact restricted case metadata")
	}
	t.Log("compiled React and Go TLS/session/CSRF covered restriction, audited case search with direct lineage, selection, and exact release using synthetic privacy state")
}

type consoleProcessingFacts struct {
	mu            sync.Mutex
	rule          value.ProcessingInventoryRule
	changes       []value.ProcessingChange
	expires       time.Time
	searchIntent  audit.OperationIntent
	searchOutcome audit.OperationOutcome
	searchReads   int
}

func (s *consoleProcessingFacts) Configured() bool { return s != nil }

func (s *consoleProcessingFacts) Begin(ctx context.Context, intent audit.OperationIntent) error {
	if ctx.Err() != nil || !intent.Valid() {
		return auditapp.ErrUnavailable
	}
	if intent.Name == "search_processing_evidence" {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.searchIntent.ID != "" || s.rule.State != "restricted" {
			return auditapp.ErrUnavailable
		}
		s.searchIntent = intent
	}
	return nil
}

func (s *consoleProcessingFacts) Finish(ctx context.Context, outcome audit.OperationOutcome) error {
	if ctx.Err() != nil || !outcome.Valid() {
		return auditapp.ErrUnavailable
	}
	if outcome.Intent.Name == "search_processing_evidence" {
		s.mu.Lock()
		defer s.mu.Unlock()
		if outcome.Intent.ID != s.searchIntent.ID || s.searchReads != 1 {
			return auditapp.ErrUnavailable
		}
		s.searchOutcome = outcome
	}
	return nil
}

func (s *consoleProcessingFacts) DownloadPolicy(context.Context) (value.DownloadPolicy, error) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return value.DownloadPolicy{RootID: consoleCaptureID(41), InstallationID: consoleCaptureID(41), RecoveryEpoch: consoleCaptureID(42),
		Revision: identity.Revision{UID: "synthetic-privacy-policy", Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2},
		PermittedRegions: []string{}, Paths: []artifact.DownloadPath{}, Clients: []value.DownloadClient{},
		Operators: []value.ProcessingOperator{{Issuer: "https://identity.invalid", ClientID: "console", Kind: "Group", ID: "maintainers"}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}

func (s *consoleProcessingFacts) RecoveryState(context.Context) (artifact.RecoveryProof, error) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return artifact.RecoveryProof{InstallationID: consoleCaptureID(41), IssuerEpoch: consoleCaptureID(42),
		Revision: identity.Revision{UID: "synthetic-recovery", Generation: 1, Digest: artifact.Digest{3}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}

func (s *consoleProcessingFacts) ReadProcessingDiscovery(ctx context.Context, authority value.ProcessingAuthority, query value.ProcessingDiscoveryQuery) (value.ProcessingDiscoveryPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if ctx.Err() != nil || !authority.Valid(now) || s.rule.State != "restricted" || s.searchIntent.ID == "" || s.searchOutcome.Intent.ID != "" || query.CaseID != consoleCaptureID(80) {
		return value.ProcessingDiscoveryPage{}, value.ErrUnavailable
	}
	s.searchReads++
	return value.ProcessingDiscoveryPage{RootID: consoleCaptureID(41), Epoch: consoleCaptureID(42), Sequence: 2,
		ObservedAt: authority.ObservedAt, ValidUntil: authority.ValidUntil, Candidates: []value.ProcessingDiscoveryCandidate{{
			ArtifactID: consoleCaptureID(81), CaptureID: consoleCaptureID(8), CaseID: query.CaseID, ClusterID: consoleCaptureID(1),
			NamespaceUID: "synthetic-namespace-uid", WorkloadUID: "synthetic-workload-uid", PurposeRef: "synthetic-rights-discovery",
			NativeType: "podStatus", DataClass: "metadata", Origin: "derived", AnchorAt: s.expires.Add(-time.Hour),
			ExpiresAt: s.expires, DeleteBy: s.expires.Add(5 * time.Minute), CustodyState: artifact.StoredUnpublished, Parents: []string{consoleCaptureID(83)},
		}}}, nil
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
