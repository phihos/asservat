package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/console"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/transport/browser"
	"asservat.local/asservat/internal/transport/presentation"
)

// The browser and Go HTTP/session/authority/audit path are actual components.
// Retained source rows are explicit synthetic facts, including one deleted
// artifact and one missing outcome, so this does not qualify SQL custody.
func TestConsoleProcessingReportWithBuiltPackage(t *testing.T) {
	if os.Getenv("ASSERVAT_CONSOLE_BROWSER_TEST") != "1" {
		t.Skip("set ASSERVAT_CONSOLE_BROWSER_TEST=1 after building web/dist")
	}
	qualifyConsoleReportResponseCapture(t)
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
	facts := &consoleReportFacts{rows: consoleReportRows(time.Now().UTC().Truncate(time.Microsecond)), intents: map[string]audit.OperationIntent{}, outcomes: map[string]audit.OperationOutcome{}}
	rootID := consoleCaptureID(41)
	report := &privacyapp.ProcessingReport{RootID: rootID, InstallationID: rootID, Policies: facts, Recovery: facts, Reports: facts, Now: time.Now}
	processing, err := presentation.NewProcessingDiscoveryOperations(origin, time.Now, custodyID, privacyapp.ProcessingEvidenceDiscovery{
		RootID: rootID, InstallationID: rootID, Policies: facts, Recovery: facts, Discovery: &facts.consoleProcessingFacts, Now: time.Now,
	}, nil, report)
	if err != nil {
		t.Fatal(err)
	}
	cases, err := presentation.NewContextCaseOperations(presentation.ContextCaseOperationsConfig{PublicOrigin: origin, Now: time.Now, NewID: custodyID},
		&consoleSyntheticCases{state: "ready", expiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	base, err := presentation.NewInvestigationOperations(nil, cases)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := presentation.NewInvestigationProcessingDiscoveryOperations(base, processing)
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
		NormalPerSecond: 64, ResolutionPerSecond: 1, Now: time.Now, NewID: custodyID,
	}, operations, facts, facts, mac)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := browser.NewAuditedInvestigationHandler(session, audited, 4)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/v1/session" || strings.HasPrefix(r.URL.Path, "/auth/"):
			session.ServeHTTP(w, r)
		case strings.HasPrefix(r.URL.Path, "/api/v1/operations/"):
			handler.ServeHTTP(w, r)
		default:
			static.ServeHTTP(w, r)
		}
	})
	server.StartTLS()
	driver, output := startProcessingReportBrowser(t, t.Context(), map[string]any{"origin": origin, "cookies": []map[string]any{{
		"name": browser.SessionCookie, "value": strings.Repeat("A", 43), "url": origin, "secure": true, "httpOnly": true, "sameSite": "Strict",
	}}})
	var sections []string
	pageCount := 0
	records := readProcessingReportExports(t, driver, output, func(summary reportPageSummary, page value.ProcessingReportPage) {
		facts.mu.Lock()
		outcome, ok := facts.outcomes[summary.RequestID]
		facts.mu.Unlock()
		if !ok || outcome.Status != "success" || outcome.Effect != "none" || outcome.OutputBytes != summary.ResponseBytes ||
			outcome.Intent.Name != "get_processing_report" || audit.OperationLane(outcome.Intent.Name) != "normal" {
			t.Fatal("exported page differs from independently acknowledged actual response audit")
		}
		pageCount++
		if len(sections) == 0 || sections[len(sections)-1] != page.Section {
			sections = append(sections, page.Section)
		}
	})
	if !slices.Equal(sections, []string{"artifacts", "shares", "downloads", "operations", "rules", "paths", "processors"}) || pageCount <= 32 {
		t.Fatal("report did not exercise all sections and a second export part", sections, pageCount)
	}
	want := 0
	for _, rows := range facts.rows {
		want += len(rows)
	}
	if len(records) != want {
		t.Fatal("export lost retained records", len(records), want)
	}
	t.Log("compiled report consumer exported all seven sections over two JSON parts with exact HTTP payloads and normal audit byte counts")
}

func qualifyConsoleReportResponseCapture(t *testing.T) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	page := value.ProcessingReportPage{SchemaVersion: value.ProcessingReportFormat, RootID: consoleCaptureID(1), InstallationID: consoleCaptureID(2),
		Section: "processors", SelectionCreatedBefore: now, PolicyRevision: value.ProcessingReportRevision{UID: consoleCaptureID(3), Generation: 1, Digest: strings.Repeat("a", 64)},
		Records: []value.ProcessingReportRecord{}, ObservedAt: now, ValidUntil: now.Add(time.Second), ProcessorDeclarations: "unsupplied", Coverage: value.ProcessingReportCoverage()}
	body, err := json.MarshalIndent(presentation.OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: consoleCaptureID(4), DataClass: "metadata", Status: "ok",
		Data: page, Warnings: []string{"synthetic UTF-8 café"}, Provenance: []any{}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/operations/get_processing_report" {
			_, _ = io.WriteString(w, "<!doctype html><title>synthetic report proxy</title>")
			return
		}
		n := requests.Add(1)
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1024))
		if err != nil || r.Method != http.MethodPost || string(raw) != `{"section":"processors","limit":3}` ||
			r.Header.Get("Origin") != "https://report.synthetic.invalid" || r.Header.Get("Cookie") != "synthetic=original" || r.Header.Get("X-CSRF-Token") != strings.Repeat("A", 43) {
			t.Error("proxied report capture changed original synthetic request")
		}
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			_, _ = w.Write(body)
			return
		}
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error("controlled truncated response", err)
			return
		}
		_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10000\r\n\r\n{\"status\":")
		_ = connection.Close()
	}))
	defer server.Close()
	digest := sha256.Sum256(body)
	command, cancel := installedBoundedCommand(t.Context(), 30*time.Second, "node", filepath.Join("..", "..", "web", "scripts", "processing-report-response-test.mjs"), server.URL, hex.EncodeToString(digest[:]), fmt.Sprint(len(body)))
	defer cancel()
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	command.WaitDelay = 5 * time.Second
	var output consoleBoundedOutput
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		if command.Process != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
		t.Fatal("report response capture proxy boundary", err, output.String())
	}
	if requests.Load() != 2 {
		t.Fatal("report response capture replayed an upstream POST", requests.Load())
	}
	t.Log(output.String())
}

type consoleReportFacts struct {
	consoleProcessingFacts
	mu       sync.Mutex
	rows     map[string][]value.ProcessingReportRecord
	intents  map[string]audit.OperationIntent
	outcomes map[string]audit.OperationOutcome
}

func (f *consoleReportFacts) Configured() bool { return true }
func (f *consoleReportFacts) DownloadPolicy(ctx context.Context) (value.DownloadPolicy, error) {
	policy, err := f.consoleProcessingFacts.DownloadPolicy(ctx)
	policy.Processors = reportFixtureProcessors()
	return policy, err
}
func (f *consoleReportFacts) Begin(ctx context.Context, in audit.OperationIntent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ctx.Err() != nil || !in.Valid() || in.Name != "get_processing_report" || f.intents[in.ID].ID != "" {
		return auditapp.ErrUnavailable
	}
	f.intents[in.ID] = in
	return nil
}
func (f *consoleReportFacts) Finish(ctx context.Context, out audit.OperationOutcome) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ctx.Err() != nil || !out.Valid() || f.intents[out.Intent.ID].ID == "" || f.outcomes[out.Intent.ID].Intent.ID != "" {
		return auditapp.ErrUnavailable
	}
	f.outcomes[out.Intent.ID] = out
	return nil
}
func (f *consoleReportFacts) ReadProcessingReport(ctx context.Context, authority value.ProcessingAuthority, query value.ProcessingReportQuery) (value.ProcessingReportPage, error) {
	if ctx.Err() != nil || !authority.Valid(time.Now()) || !query.Valid() {
		return value.ProcessingReportPage{}, value.ErrUnavailable
	}
	query = query.Normalized()
	selection := query.CreatedBefore
	if selection.IsZero() {
		selection = authority.ObservedAt
	}
	digest := hex.EncodeToString(authority.Policy.Revision.Digest[:])
	page := value.ProcessingReportPage{SchemaVersion: value.ProcessingReportFormat, RootID: authority.Policy.RootID, InstallationID: authority.Policy.InstallationID,
		Section: query.Section, SelectionCreatedBefore: selection, PolicyRevision: value.ProcessingReportRevision{
			UID: authority.Policy.Revision.UID, Generation: authority.Policy.Revision.Generation, Digest: digest},
		Records: []value.ProcessingReportRecord{}, ObservedAt: authority.ObservedAt, ValidUntil: authority.ValidUntil,
		ProcessorDeclarations: "supplied", Coverage: value.ProcessingReportCoverage()}
	rows := f.rows[query.Section]
	index := 0
	if query.After != (value.ProcessingReportCursor{}) {
		index = len(rows)
		for i, row := range rows {
			if reflect.DeepEqual(row.Cursor(), query.After) {
				index = i + 1
				break
			}
		}
	}
	// A finite source with more than 32 full pages forces a part boundary.
	if index < len(rows) {
		page.Records = append(page.Records, rows[index:min(index+query.Limit, len(rows))]...)
	}
	next := value.ProcessingReportQuery{Section: query.Section, Limit: query.Limit, CreatedBefore: selection, PolicyDigest: digest}
	if index+len(page.Records) < len(rows) {
		next.After = page.Records[len(page.Records)-1].Cursor()
		page.Next = &next
	} else {
		sections := []string{"artifacts", "shares", "downloads", "operations", "rules", "paths", "processors"}
		i := slices.Index(sections, query.Section)
		if i+1 < len(sections) {
			next.Section = sections[i+1]
			page.Next = &next
		}
	}
	return page, nil
}

func consoleReportRows(now time.Time) map[string][]value.ProcessingReportRecord {
	visible := now.Add(time.Hour)
	rows := map[string][]value.ProcessingReportRecord{}
	deleted := now.Add(-time.Minute)
	for i := range 100 {
		artifact := &value.ProcessingReportArtifact{ArtifactID: consoleCaptureID(201 + i), CaptureID: consoleCaptureID(301 + i), CaseID: consoleCaptureID(80),
			ClusterID: consoleCaptureID(1), AttemptID: consoleCaptureID(401 + i), NamespaceUID: "synthetic-namespace", WorkloadUID: "synthetic-workload", StoreID: consoleCaptureID(9),
			PurposeRef: "synthetic-report-purpose", NativeType: "podStatus", DataClass: "metadata", PrivacyClass: "potentialPersonalData", Origin: "capture", Parents: []string{},
			AnchorAt: now.Add(-time.Hour), OriginalExpiresAt: now.Add(time.Hour), OriginalDeleteBy: now.Add(2 * time.Hour),
			ExpiresAt: now.Add(time.Hour), DeleteBy: now.Add(2 * time.Hour), CustodyState: "stored_unpublished", DeletionState: "retained"}
		if i == 0 {
			artifact.CustodyState, artifact.DeletionState, artifact.DeletedAt, artifact.ExpiresAt = "deleted", "deleted", &deleted, artifact.AnchorAt
		}
		rows["artifacts"] = append(rows["artifacts"], value.ProcessingReportRecord{VisibleUntil: visible, Artifact: artifact})
	}
	rows["shares"] = []value.ProcessingReportRecord{{VisibleUntil: visible, Share: &value.ProcessingReportShare{
		ShareID: consoleCaptureID(601), ArtifactID: consoleCaptureID(201), RecipientKind: "User", RecipientIssuer: "https://identity.invalid",
		RecipientID: "synthetic-recipient", Ordinal: 1, CreatedAt: now.Add(-30 * time.Minute), ExpiresAt: visible, State: "recorded"}}}
	rows["downloads"] = []value.ProcessingReportRecord{{VisibleUntil: visible, Download: &value.ProcessingReportDownload{
		DownloadID: consoleCaptureID(602), ArtifactID: consoleCaptureID(201), Issuer: "https://identity.invalid", Subject: "synthetic-recipient", ClientID: "console",
		PrincipalKind: identity.Human, State: artifact.DownloadCompleted, CreatedAt: now.Add(-20 * time.Minute), Deadline: visible, EmittedBytes: 321, ClientReceipt: "unknown"}}}
	rows["operations"] = []value.ProcessingReportRecord{{VisibleUntil: visible, Operation: &value.ProcessingReportOperation{
		OperationID: consoleCaptureID(603), Lane: "normal", Name: "get_case", Issuer: "https://identity.invalid", Subject: "synthetic-recipient", ClientID: "console", PrincipalKind: identity.Human,
		CreatedAt: now.Add(-10 * time.Minute), IntentAcknowledged: true, Status: "unknown", ClientReceipt: "unknown"}}}
	scope := value.ProcessingScope{Kind: "workloadInterval", ClusterID: consoleCaptureID(1), NamespaceUID: "synthetic-namespace", WorkloadUID: "synthetic-workload",
		AcquiredFrom: now.Add(-2 * time.Hour), AcquiredUntil: now}
	rows["rules"] = []value.ProcessingReportRecord{{VisibleUntil: visible, Rule: &value.ProcessingReportRule{
		ID: consoleCaptureID(604), Revision: 1, State: "restricted", Scope: value.ProcessingReportScopeFrom(scope), AdministrationUntil: visible, RetireBy: visible.Add(time.Hour)}}}
	rows["paths"] = []value.ProcessingReportRecord{{VisibleUntil: visible, Path: &value.ProcessingReportPath{
		ID: consoleCaptureID(605), TargetClusterID: consoleCaptureID(1), StoreID: consoleCaptureID(9), StorageRegion: "synthetic-region", AcquisitionClusterID: consoleCaptureID(1),
		AcquisitionRegion: "synthetic-region", ConnectorClusterID: consoleCaptureID(1), ConnectorRegion: "synthetic-region", HubClusterID: consoleCaptureID(2), HubRegion: "synthetic-hub-region"}}}
	for _, processor := range reportFixtureProcessors() {
		organization := processor
		rows["processors"] = append(rows["processors"], value.ProcessingReportRecord{VisibleUntil: visible, Processor: &organization})
	}
	return rows
}
