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
	root, origin, facts := newConsoleProcessing(t, false)
	runConsoleProcessingBrowser(t, root, origin, "installed-processing-browser.mjs", 3)
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

func TestConsoleWorkloadProcessingWithBuiltPackage(t *testing.T) {
	root, origin, facts := newConsoleProcessing(t, false)
	facts.workloadRestriction = true
	runConsoleProcessingBrowser(t, root, origin, "installed-processing-browser.mjs", 3, true)
	facts.mu.Lock()
	defer facts.mu.Unlock()
	scope := facts.workloadScope()
	if len(facts.changes) != 2 || !facts.changes[0].Scope.Equal(scope) || facts.changes[0].RequestedArtifactID != "" ||
		facts.changes[0].ExpectedRevision != 0 || !facts.changes[1].Scope.Equal(scope) || facts.changes[1].ExpectedRevision != 1 ||
		facts.changes[0].RequestID == facts.changes[1].RequestID || facts.rule.State != "released" || facts.rule.Revision != 2 {
		t.Fatal("workload browser changed the original scope, revision or request identity")
	}
	if len(facts.searchQueries) != 3 || facts.searchReads != 3 || len(facts.searchOutcomes) != 3 {
		t.Fatal("workload restriction requires source case, workload and restricted-case discovery")
	}
	first, workload, last := facts.searchQueries[0], facts.searchQueries[1], facts.searchQueries[2]
	if first.CaseID != consoleCaptureID(80) || last.CaseID != first.CaseID || workload.CaseID != "" ||
		workload.ClusterID != scope.ClusterID || workload.NamespaceUID != scope.NamespaceUID || workload.WorkloadUID != scope.WorkloadUID ||
		!workload.AcquiredFrom.Equal(scope.AcquiredFrom) || !workload.AcquiredUntil.Equal(scope.AcquiredUntil) ||
		workload.PurposeRef != "synthetic-rights-discovery" || workload.Limit != 12 {
		t.Fatal("workload review did not derive the exact interval from accepted candidate metadata")
	}
	seen := map[string]bool{}
	for _, out := range facts.searchOutcomes {
		if seen[out.Intent.ID] || audit.OperationLane(out.Intent.Name) != "normal" || out.Status != "success" || out.Effect != "none" ||
			!slices.Equal(out.CaseIDs, []string{consoleCaptureID(80)}) || !slices.Equal(out.ArtifactIDs, []string{consoleCaptureID(81)}) ||
			!slices.Equal(out.CaptureIDs, []string{consoleCaptureID(8)}) {
			t.Fatal("workload discovery did not independently audit the selected metadata")
		}
		seen[out.Intent.ID] = true
	}
	t.Log("compiled React reviewed the exact all-purpose workload interval, reloaded its original scope and released the exact revision using synthetic privacy state")
}

func TestConsoleErasureWithBuiltPackage(t *testing.T) {
	root, origin, facts := newConsoleProcessing(t, true)
	runConsoleProcessingBrowser(t, root, origin, "installed-erasure-browser.mjs", 2)
	facts.mu.Lock()
	defer facts.mu.Unlock()
	if len(facts.changes) != 1 || facts.rule.ID != "" || facts.erasureAccepted.IsZero() {
		t.Fatal("controlled early erasure did not record one accepted request")
	}
	change := facts.changes[0]
	if change.Action != value.RequestEarlyErasure || change.RequestedArtifactID != consoleCaptureID(81) ||
		change.RuleID != "" || change.ExpectedRevision != 0 || change.Scope != (value.ProcessingScope{}) {
		t.Fatal("early erasure changed the selected artifact or used a rule")
	}
	if facts.searchReads != 1 || facts.searchOutcome.Status != "success" || facts.statusReads != 2 ||
		len(facts.statusIntents) != 2 || len(facts.statusOutcomes) != 2 || facts.statusIntents[0].ID == facts.statusIntents[1].ID {
		t.Fatal("early erasure did not use one audited discovery and two explicit audited status reads")
	}
	for i, out := range facts.statusOutcomes {
		if out.Intent.ID != facts.statusIntents[i].ID || audit.OperationLane(out.Intent.Name) != "normal" || out.Status != "success" || out.Effect != "none" ||
			!slices.Equal(out.ArtifactIDs, []string{consoleCaptureID(81)}) {
			t.Fatal("erasure status did not audit the exact artifact", i)
		}
	}
	t.Log("compiled React confirmed exact discovered erasure and read pending and verified managed deletion after reload using synthetic custody state")
}

func newConsoleProcessing(t *testing.T, erasure bool) (string, string, *consoleProcessingFacts) {
	t.Helper()
	if os.Getenv("ASSERVAT_CONSOLE_BROWSER_TEST") != "1" {
		t.Skip("set ASSERVAT_CONSOLE_BROWSER_TEST=1 after building web/dist")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	origin := "https://" + server.Listener.Addr().String()
	static, err := console.New(origin, os.DirFS(filepath.Join(root, "web", "dist")))
	if err != nil {
		t.Fatal(err)
	}
	sessions := &consoleSyntheticSessions{origin: origin, state: "ready", expiresAt: time.Now().Add(3 * time.Minute)}
	session := browser.SessionHandler{Origin: origin, Issuer: "https://identity.invalid", Sessions: sessions}
	expires := time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour)
	facts := &consoleProcessingFacts{expires: expires, erasure: erasure}
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
	var status *privacyapp.ProcessingErasureStatus
	if erasure {
		status = &privacyapp.ProcessingErasureStatus{RootID: rootID, InstallationID: rootID, Policies: facts, Recovery: facts, Status: facts, Now: time.Now}
	}
	discovery, err := presentation.NewProcessingDiscoveryOperations(origin, time.Now, custodyID, privacyapp.ProcessingEvidenceDiscovery{
		RootID: rootID, InstallationID: rootID, Policies: facts, Recovery: facts, Discovery: facts, Now: time.Now,
	}, status)
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
	t.Cleanup(mac.Close)
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
	return root, origin, facts
}

func runConsoleProcessingBrowser(t *testing.T, root, origin, script string, acknowledgements int, workloadRestriction ...bool) {
	t.Helper()
	config := map[string]any{"origin": origin, "artifactID": consoleCaptureID(81), "casePath": "/cases/" + consoleCaptureID(80), "parents": []string{consoleCaptureID(83)}, "cookies": []map[string]any{{"name": browser.SessionCookie, "value": strings.Repeat("A", 43), "url": origin, "secure": true, "httpOnly": true, "sameSite": "Strict"}}}
	if len(workloadRestriction) > 0 && workloadRestriction[0] {
		config["workloadRestriction"] = true
	}
	private, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	input := append(private, '\n')
	for range acknowledgements {
		input = append(input, "{\"continue\":true}\n"...)
	}
	defer clear(input)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", filepath.Join(root, "web", "scripts", script))
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
}

type consoleProcessingFacts struct {
	mu                  sync.Mutex
	rule                value.ProcessingInventoryRule
	changes             []value.ProcessingChange
	expires             time.Time
	searchIntent        audit.OperationIntent
	searchOutcome       audit.OperationOutcome
	searchReads         int
	workloadRestriction bool
	searchQueries       []value.ProcessingDiscoveryQuery
	searchOutcomes      []audit.OperationOutcome
	erasure             bool
	erasureAccepted     time.Time
	statusIntents       []audit.OperationIntent
	statusOutcomes      []audit.OperationOutcome
	statusReads         int
}

func (s *consoleProcessingFacts) Configured() bool { return s != nil }

func (s *consoleProcessingFacts) Begin(ctx context.Context, intent audit.OperationIntent) error {
	if ctx.Err() != nil || !intent.Valid() {
		return auditapp.ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch intent.Name {
	case "search_processing_evidence":
		if s.searchIntent.ID != "" && s.searchOutcome.Intent.ID != s.searchIntent.ID || !s.erasure && !s.workloadRestriction && s.rule.State != "restricted" {
			return auditapp.ErrUnavailable
		}
		s.searchIntent = intent
	case "get_processing_erasure":
		if !s.erasure || s.erasureAccepted.IsZero() || len(s.statusIntents) != len(s.statusOutcomes) || len(s.statusIntents) >= 2 {
			return auditapp.ErrUnavailable
		}
		s.statusIntents = append(s.statusIntents, intent)
	}
	return nil
}

func (s *consoleProcessingFacts) Finish(ctx context.Context, outcome audit.OperationOutcome) error {
	if ctx.Err() != nil || !outcome.Valid() {
		return auditapp.ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch outcome.Intent.Name {
	case "search_processing_evidence":
		if outcome.Intent.ID != s.searchIntent.ID || s.searchReads != len(s.searchOutcomes)+1 {
			return auditapp.ErrUnavailable
		}
		s.searchOutcome = outcome
		s.searchOutcomes = append(s.searchOutcomes, outcome)
	case "get_processing_erasure":
		i := len(s.statusOutcomes)
		if i+1 != s.statusReads || i+1 != len(s.statusIntents) || outcome.Intent.ID != s.statusIntents[i].ID {
			return auditapp.ErrUnavailable
		}
		s.statusOutcomes = append(s.statusOutcomes, outcome)
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
	if ctx.Err() != nil || !authority.Valid(now) || !s.erasure && !s.workloadRestriction && s.rule.State != "restricted" || s.searchIntent.ID == "" || s.searchOutcome.Intent.ID == s.searchIntent.ID {
		return value.ProcessingDiscoveryPage{}, value.ErrUnavailable
	}
	if query.CaseID != consoleCaptureID(80) {
		scope := s.workloadScope()
		if !s.workloadRestriction || query.CaseID != "" || query.ClusterID != scope.ClusterID ||
			query.NamespaceUID != scope.NamespaceUID || query.WorkloadUID != scope.WorkloadUID ||
			!query.AcquiredFrom.Equal(scope.AcquiredFrom) || !query.AcquiredUntil.Equal(scope.AcquiredUntil) ||
			query.PurposeRef != "synthetic-rights-discovery" {
			return value.ProcessingDiscoveryPage{}, value.ErrUnavailable
		}
	}
	s.searchQueries = append(s.searchQueries, query)
	s.searchReads++
	origin, parents := "derived", []string{consoleCaptureID(83)}
	if s.erasure {
		origin, parents = "capture", []string{}
	}
	return value.ProcessingDiscoveryPage{RootID: consoleCaptureID(41), Epoch: consoleCaptureID(42), Sequence: 2,
		ObservedAt: authority.ObservedAt, ValidUntil: authority.ValidUntil, Candidates: []value.ProcessingDiscoveryCandidate{{
			ArtifactID: consoleCaptureID(81), CaptureID: consoleCaptureID(8), CaseID: consoleCaptureID(80), ClusterID: consoleCaptureID(1),
			NamespaceUID: "synthetic-namespace-uid", WorkloadUID: "synthetic-workload-uid", PurposeRef: "synthetic-rights-discovery",
			NativeType: "podStatus", DataClass: "metadata", Origin: origin, AnchorAt: s.expires.Add(-time.Hour),
			ExpiresAt: s.expires, DeleteBy: s.expires.Add(5 * time.Minute), CustodyState: artifact.StoredUnpublished, Parents: parents,
		}}}, nil
}

func (s *consoleProcessingFacts) ReadProcessingErasureStatus(ctx context.Context, authority value.ProcessingAuthority, requestID string) (value.ProcessingErasureStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if ctx.Err() != nil || !authority.Valid(now) || !s.erasure || len(s.changes) != 1 || s.changes[0].RequestID != requestID ||
		s.statusReads+1 != len(s.statusIntents) || s.statusReads != len(s.statusOutcomes) || s.statusReads >= 2 {
		return value.ProcessingErasureStatus{}, value.ErrUnavailable
	}
	s.statusReads++
	deleteBy := s.expires.Add(5 * time.Minute)
	status := value.ProcessingErasureStatus{RequestID: requestID, ArtifactID: s.changes[0].RequestedArtifactID,
		AcceptedAt: s.erasureAccepted, AccessUntil: s.expires.Add(-time.Hour), DeleteBy: deleteBy, EffectiveDeleteBy: deleteBy,
		AuditState: value.ProcessingErasureAuditPending, DeletionState: value.ProcessingErasureDeletionPending,
		ObservedAt: authority.ObservedAt, ValidUntil: authority.ValidUntil}
	if s.statusReads == 2 {
		status.AuditState = value.ProcessingErasureAuditAcknowledged
		status.DeletionState, status.DeletedAt = value.ProcessingErasureDeleted, &now
	}
	return status, nil
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
	case value.RequestEarlyErasure:
		if !s.erasure || len(s.changes) != 0 || s.searchOutcome.Status != "success" || c.RequestedArtifactID != consoleCaptureID(81) ||
			c.RuleID != "" || c.ExpectedRevision != 0 || c.Scope != (value.ProcessingScope{}) {
			return value.ProcessingReceipt{}, value.ErrConflict
		}
		s.erasureAccepted = now.Truncate(time.Microsecond)
		s.changes = append(s.changes, c)
		return value.ProcessingReceipt{RootID: consoleCaptureID(41), Epoch: consoleCaptureID(42), RequestID: c.RequestID,
			OperationID: consoleCaptureID(601), State: "erasureRequested", Sequence: 2, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}, nil
	case "restrict_processing":
		if s.rule.ID != "" || c.ExpectedRevision != 0 {
			return value.ProcessingReceipt{}, value.ErrConflict
		}
		scope := value.ProcessingScope{Kind: "artifact", Location: artifact.Location{ClusterID: consoleCaptureID(1), ArtifactID: c.RequestedArtifactID, AttemptID: consoleCaptureID(82)}}
		if s.workloadRestriction {
			if c.RequestedArtifactID != "" || !c.Scope.Equal(s.workloadScope()) || s.searchReads != 2 {
				return value.ProcessingReceipt{}, value.ErrConflict
			}
			scope = c.Scope
		} else if c.RequestedArtifactID != consoleCaptureID(81) {
			return value.ProcessingReceipt{}, value.ErrConflict
		}
		s.rule = value.ProcessingInventoryRule{ID: c.RuleID, State: "restricted", Revision: 1, Scope: scope, AdministrationUntil: now.Add(time.Hour), RetireBy: now.Add(2 * time.Hour)}
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

// workloadScope independently derives the reviewed interval from fixture facts.
func (s *consoleProcessingFacts) workloadScope() value.ProcessingScope {
	second := s.expires.Add(-time.Hour).UTC().Truncate(time.Second)
	return value.ProcessingScope{Kind: "workloadInterval", ClusterID: consoleCaptureID(1),
		NamespaceUID: "synthetic-namespace-uid", WorkloadUID: "synthetic-workload-uid",
		AcquiredFrom: second.Add(-time.Second), AcquiredUntil: second.Add(time.Second)}
}
