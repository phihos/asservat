package integration

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type reportPageSummary struct {
	Query         value.ProcessingReportQuery `json:"query"`
	RequestID     string                      `json:"requestID"`
	ResponseBytes int64                       `json:"responseBytes"`
}
type reportExportEvent struct {
	Kind     string              `json:"kind"`
	File     string              `json:"file"`
	Part     int                 `json:"part"`
	Complete bool                `json:"complete"`
	Bytes    int64               `json:"bytes"`
	SHA256   string              `json:"sha256"`
	Pages    []reportPageSummary `json:"pages"`
	Stage    string              `json:"stage"`
	Reason   string              `json:"reason"`
	Check    string              `json:"check"`
}
type processingReportExport struct {
	Format   string                       `json:"format"`
	Part     int                          `json:"part"`
	Pages    []installedJourneyEnvelope   `json:"pages"`
	Next     *value.ProcessingReportQuery `json:"next,omitempty"`
	Complete bool                         `json:"complete"`
}

func TestInstalledReportSharingAuthority(t *testing.T) {
	for _, fixture := range []struct {
		foci  string
		owner bool
	}{
		{"privacy-inventory", true}, {"share", true}, {"browser", true},
		{"early-erasure", false}, {"early-erasure,privacy-inventory", true},
	} {
		t.Run(fixture.foci, func(t *testing.T) {
			t.Setenv("ASSERVAT_JOURNEY_FOCUS", fixture.foci)
			owner := false
			for _, role := range installedRegionalBindingRoles() {
				owner = owner || role == "evidence-owner"
			}
			if owner != fixture.owner {
				t.Fatal("installed sharing fixture must bind evidence-owner before capture so it joins the retained audience", owner, fixture.owner)
			}
		})
	}
}

func startProcessingReportBrowser(t *testing.T, ctx context.Context, config map[string]any) (*installedLiveBrowser, string) {
	t.Helper()
	output := t.TempDir()
	config["outputDirectory"] = output
	command, cancel := installedBoundedCommand(ctx, 3*time.Minute, "node", filepath.Join("..", "..", "web", "scripts", "installed-processing-report-browser.mjs"))
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	in, err := command.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	out, err := command.StdoutPipe()
	if err != nil {
		cancel()
		in.Close()
		t.Fatal(err)
	}
	diagnostic := &consoleBoundedOutput{}
	command.Stderr = diagnostic
	driver := &installedLiveBrowser{t: t, in: in, events: make(chan json.RawMessage, 8), done: make(chan error, 1), cancel: cancel, cmd: command, diagnostic: diagnostic}
	if err = command.Start(); err != nil {
		cancel()
		in.Close()
		t.Fatal(err)
	}
	go func() {
		scanner := bufio.NewScanner(out)
		scanner.Buffer(make([]byte, 1024), 64<<10)
		for scanner.Scan() {
			raw := append(json.RawMessage(nil), scanner.Bytes()...)
			select {
			case driver.events <- raw:
			case <-ctx.Done():
			}
		}
		close(driver.events)
		err := command.Wait()
		if err == nil {
			err = scanner.Err()
		}
		driver.done <- err
	}()
	t.Cleanup(func() {
		driver.once.Do(func() {
			driver.cancel()
			driver.in.Close()
			installedAwait(t, "processing report browser", driver.done, 30*time.Second)
		})
	})
	driver.send(config)
	return driver, output
}

func readProcessingReportExports(t *testing.T, driver *installedLiveBrowser, directory string, check func(reportPageSummary, value.ProcessingReportPage)) []value.ProcessingReportRecord {
	t.Helper()
	var records []value.ProcessingReportRecord
	seen := map[string]bool{}
	var previous *value.ProcessingReportQuery
	parts := 0
	for {
		var event reportExportEvent
		driver.read(&event)
		if event.Kind == "failed" {
			t.Fatalf("processing report browser stage=%s reason=%s check=%s", event.Stage, event.Reason, event.Check)
		}
		if event.Kind == "complete" {
			if parts == 0 || previous != nil {
				t.Fatal("report browser completed without a terminal exported part")
			}
			break
		}
		parts++
		if event.Kind != "exported" || event.Part != parts || parts > 8 || event.File != fmt.Sprintf("processing-report-%d.json", parts) || event.Bytes < 1 || event.Bytes > 4<<20 {
			t.Fatal("invalid bounded report part summary")
		}
		raw, err := os.ReadFile(filepath.Join(directory, event.File))
		sum := sha256.Sum256(raw)
		if err != nil || int64(len(raw)) != event.Bytes || hex.EncodeToString(sum[:]) != event.SHA256 {
			t.Fatal("downloaded report bytes differ from the browser file", err)
		}
		var exported processingReportExport
		if json.Unmarshal(raw, &exported) != nil || exported.Format != "asservat-processing-inventory/v1" || exported.Part != event.Part ||
			exported.Complete != event.Complete || len(exported.Pages) != len(event.Pages) || len(exported.Pages) == 0 || len(exported.Pages) > 32 {
			t.Fatal("invalid downloaded report document")
		}
		for i, envelope := range exported.Pages {
			summary := event.Pages[i]
			if summary.RequestID != envelope.RequestID || envelope.Status != "ok" || envelope.DataClass != "metadata" ||
				summary.ResponseBytes < 1 || summary.ResponseBytes > contracts.InvestigationOutputLimit {
				t.Fatal("downloaded report page does not match its HTTP response")
			}
			if previous != nil && !reflect.DeepEqual(summary.Query, *previous) {
				t.Fatal("report did not follow the original continuation")
			}
			var page value.ProcessingReportPage
			if json.Unmarshal(envelope.Data, &page) != nil || !page.Valid(summary.Query, page.ObservedAt) {
				t.Fatal("downloaded report page lost canonical source bounds")
			}
			for _, record := range page.Records {
				cursor, _ := json.Marshal(record.Cursor())
				key := page.Section + string(cursor)
				if seen[key] {
					t.Fatal("export repeated a report record", page.Section)
				}
				seen[key] = true
				records = append(records, record)
			}
			check(summary, page)
			previous = page.Next
		}
		if !reflect.DeepEqual(exported.Next, previous) || exported.Complete != (previous == nil) {
			t.Fatal("report document lost terminal or continuation state")
		}
		driver.send(map[string]bool{"continue": true})
	}
	awaitInstalledProcessingBrowser(t, driver)
	return records
}

func qualifyInstalledProcessingReport(t *testing.T, parent context.Context, cluster string, run installedProcessingRun, erasure installedEarlyErasure) {
	t.Helper()
	ctx, stop := context.WithDeadline(parent, run.ExpiresAt)
	defer stop()
	defer func() {
		if t.Failed() {
			run.Diagnose()
		}
	}()
	shared := createInstalledReportShare(t, ctx, run)
	erasure.qualify(t, ctx, cluster, run)
	session := run.Identity.consoleSession(t, ctx, run.PublicRoot, run.Address, run.Origin)
	origin, err := url.Parse(session.base)
	if err != nil {
		t.Fatal(err)
	}
	var cookies []map[string]any
	for _, c := range session.client.Jar.Cookies(origin) {
		cookies = append(cookies, map[string]any{"name": c.Name, "value": c.Value, "url": session.base, "httpOnly": true, "secure": true, "sameSite": "Lax"})
	}
	driver, output := startProcessingReportBrowser(t, ctx, map[string]any{"origin": session.base, "proxy": installedHistoryBrowserTunnel(t, ctx, session.base, run.Address), "cookies": cookies})
	clear(cookies)
	source, err := erasure.hub.CoreV1().ConfigMaps(erasure.namespace).Get(ctx, contracts.OwnerDownloadEnvironmentName(erasure.installation), meta.GetOptions{})
	if err != nil {
		t.Fatal("installed report declared source", err)
	}
	var settings contracts.DownloadEnvironmentSettings
	if json.Unmarshal([]byte(source.Data[contracts.DownloadEnvironmentFile]), &settings) != nil {
		t.Fatal("installed report protected source decoding")
	}
	canonical, err := canonicalReportSource(source.Data[contracts.DownloadEnvironmentFile])
	if err != nil {
		t.Fatal(err)
	}
	policy := sha256.Sum256(canonical)
	sharePages := 0
	var shareAfter value.ProcessingReportCursor
	records := readProcessingReportExports(t, driver, output, func(summary reportPageSummary, page value.ProcessingReportPage) {
		if page.RootID != run.RootID || page.InstallationID != erasure.installation || page.PolicyRevision.UID != string(source.UID) ||
			page.PolicyRevision.Generation != settings.Revision || page.PolicyRevision.Digest != hex.EncodeToString(policy[:]) || page.ProcessorDeclarations != "supplied" {
			t.Fatal("installed report changed the actual accepted policy or declaration provenance")
		}
		if page.Section == "shares" {
			sharePages++
			if summary.Query.Limit != 3 || sharePages > 2 {
				t.Fatal("installed report did not paginate the four real recipients at three records per page")
			}
			for _, record := range page.Records {
				if record.Share == nil || record.Share.ShareID != shared.ID {
					t.Fatal("installed report recipient page changed the actual share")
				}
			}
			if sharePages == 1 {
				if len(page.Records) != 3 || page.Next == nil || page.Next.Section != "shares" {
					t.Fatal("installed report failed to continue inside a share's recipient list")
				}
				shareAfter = page.Records[2].Cursor()
				if shareAfter.Ordinal != 3 || !reflect.DeepEqual(page.Next.After, shareAfter) {
					t.Fatal("installed report lost the third recipient continuation")
				}
			} else if len(page.Records) != 1 || !reflect.DeepEqual(summary.Query.After, shareAfter) || page.Next == nil || page.Next.Section != "downloads" {
				t.Fatal("installed report did not finish the same share with its fourth recipient")
			}
		}
		installedJourneyReadOnly(t, ctx, run.SQL, func(tx pgx.Tx) error {
			var exact bool
			err := tx.QueryRow(ctx, `
SELECT o.lane='normal' AND o.intent->>'Name'='get_processing_report' AND o.intent->>'InputFormat'='context-input/v1'
 AND o.outcome->>'Status'='success' AND o.outcome->>'Effect'='none'
 AND (o.outcome->>'OutputBytes')::bigint=$3 AND o.intent_receipt IS NOT NULL AND o.outcome_receipt IS NOT NULL
 AND l.binding=o.intent->'Lifecycle' AND l.intent_completion->'Receipt'=o.intent_receipt AND l.outcome_completion->'Receipt'=o.outcome_receipt
FROM operation_audit o JOIN operation_audit_lifecycle l ON l.root_id=o.root_id AND l.operation_id=o.id AND l.lane=o.lane
WHERE o.root_id=$1 AND o.id=$2`, run.RootID, summary.RequestID, summary.ResponseBytes).Scan(&exact)
			if err != nil || !exact {
				t.Fatal("downloaded report page lacks exact acknowledged output audit", page.Section, err)
			}
			return nil
		})
	})
	artifactFound, downloadFound := false, false
	recipients := map[string]bool{}
	var processors []value.ProcessingOrganization
	for _, record := range records {
		if a := record.Artifact; a != nil && a.ArtifactID == run.ArtifactID {
			artifactFound = true
			if a.CaseID != run.CaseID || a.ClusterID != cluster || a.CustodyState != "deleted" || a.DeletionState != "deleted" ||
				a.DeletedAt == nil || !a.OriginalExpiresAt.Equal(run.ExpiresAt) || !a.ExpiresAt.Equal(a.AnchorAt) {
				t.Fatal("installed report lost retained erasure and original provenance")
			}
		}
		if share := record.Share; share != nil && share.ShareID == shared.ID {
			recipient := authorization.ShareRecipient{Kind: share.RecipientKind, Issuer: share.RecipientIssuer, ID: share.RecipientID}
			ordinal := slices.Index(shared.Recipients, recipient) + 1
			if share.ArtifactID != run.ArtifactID || ordinal == 0 || share.Ordinal != int64(ordinal) || recipients[recipient.Key()] {
				t.Fatal("installed export changed, repeated or invented an actual share recipient")
			}
			recipients[recipient.Key()] = true
		}
		if download := record.Download; download != nil && download.ArtifactID == run.ArtifactID && download.State == "Completed" && download.EmittedBytes > 0 && download.ClientReceipt == "unknown" {
			downloadFound = true
		}
		if record.Processor != nil {
			processors = append(processors, *record.Processor)
		}
	}
	if !artifactFound || len(recipients) != 4 || sharePages != 2 || !downloadFound || !reflect.DeepEqual(processors, reportFixtureProcessors()) {
		t.Fatal("installed export omitted source artifact, four paginated recipients, completed session or declarations", artifactFound, len(recipients), sharePages, downloadFound)
	}
	outsider := run.Identity.unrelated().consoleSession(t, ctx, run.PublicRoot, run.Address, run.Origin)
	denialCounts := func() (total, acknowledged int64) {
		t.Helper()
		installedJourneyReadOnly(t, ctx, run.SQL, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `
SELECT count(*),count(*) FILTER(WHERE o.lane='normal' AND o.intent->>'InputFormat'='context-input/v1'
 AND o.outcome->>'Status'='denied' AND o.outcome->>'Effect'='none'
 AND o.intent_receipt IS NOT NULL AND o.outcome_receipt IS NOT NULL
 AND l.binding=o.intent->'Lifecycle' AND l.intent_completion->'Receipt'=o.intent_receipt
 AND l.outcome_completion->'Receipt'=o.outcome_receipt)
FROM operation_audit o LEFT JOIN operation_audit_lifecycle l
 ON l.root_id=o.root_id AND l.operation_id=o.id AND l.lane=o.lane
WHERE o.root_id=$1 AND o.intent->>'Name'='get_processing_report'
 AND o.intent#>>'{Actor,Issuer}'=$2 AND o.intent#>>'{Actor,Subject}'=$3`, run.RootID, run.Identity.Issuer, shared.OutsiderID).Scan(&total, &acknowledged)
		})
		return total, acknowledged
	}
	beforeTotal, beforeAcknowledged := denialCounts()
	if _, status, err := outsider.operation(ctx, "get_processing_report", map[string]any{"section": "artifacts", "limit": 1}, ""); err == nil || status != http.StatusUnauthorized {
		t.Fatal("installed report nonoperator refusal", status, err)
	}
	if total, acknowledged := denialCounts(); total != beforeTotal+1 || acknowledged != beforeAcknowledged+1 {
		t.Fatal("nonoperator report refusal lacks one new independently acknowledged denial audit", total-beforeTotal, acknowledged-beforeAcknowledged)
	}
	qualifyInstalledReportRollbackGuard(t, ctx, run.SQL)
	t.Log("installed privacy inventory exported every section with exact page audit bytes, recorded recipient and completed session, retained verified deletion and operator declarations")
}

func qualifyInstalledReportRollbackGuard(t *testing.T, parent context.Context, admin *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", "00152_processing_report.sql"))
	if err != nil {
		t.Fatal("read exact processing report migration", err)
	}
	_, down, found := strings.Cut(string(raw), "-- +goose Down\n")
	lock, statement, begin := strings.Cut(down, "-- +goose StatementBegin\n")
	guard, _, end := strings.Cut(statement, "\n-- +goose StatementEnd")
	if !found || !begin || !end || strings.TrimSpace(lock) != "LOCK TABLE public.operation_audit IN SHARE MODE;" ||
		!strings.HasPrefix(guard, "DO $$ BEGIN\n") || !strings.HasSuffix(guard, "END $$;") {
		t.Fatal("processing report Down guard source shape changed")
	}
	readLayout := func() string {
		t.Helper()
		var head, indexes int64
		var applied bool
		var definitions string
		if err := admin.QueryRow(ctx, `
SELECT v.version_id,v.is_applied,
 (SELECT count(*) FROM pg_indexes WHERE schemaname='public' AND indexname IN ('processing_report_downloads','processing_report_operations','processing_report_rule_created')),
 (SELECT jsonb_object_agg(indexname,indexdef ORDER BY indexname)::text FROM pg_indexes WHERE schemaname='public' AND indexname IN ('processing_report_downloads','processing_report_operations','processing_report_rule_created'))
FROM goose_db_version v ORDER BY v.id DESC LIMIT 1`).Scan(&head, &applied, &indexes, &definitions); err != nil || head != 152 || !applied || indexes != 3 {
			t.Fatal("processing report retained layout", head, applied, indexes, err)
		}
		return definitions
	}
	before := readLayout()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal("begin rollback guard qualification", err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, lock); err != nil {
		t.Fatal("acquire exact Down audit lock", err)
	}
	_, err = tx.Exec(ctx, guard)
	var refusal *pgconn.PgError
	if !errors.As(err, &refusal) || refusal.Code != "23514" || refusal.Message != "retained processing report audit prevents rollback" {
		t.Fatal("actual retained report audit did not refuse exact Down guard", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal("rollback refused report guard transaction", err)
	}
	if after := readLayout(); after != before {
		t.Fatal("refused report guard changed report index definitions")
	}
	t.Log("exact SQL152 Down guard refused retained report audit with 23514; rolled back, schema152 and all three index definitions unchanged")
}

type installedReportShare struct {
	ID, OutsiderID string
	Recipients     []authorization.ShareRecipient
}

func createInstalledReportShare(t *testing.T, ctx context.Context, run installedProcessingRun) installedReportShare {
	t.Helper()
	reply, err := run.Call(ctx, "get_case", map[string]string{"case_id": run.CaseID})
	// Public case metadata supplies the exact version; SQL supplies no input.
	var data struct {
		Artifacts []struct {
			ID     string `json:"artifact_id"`
			Digest string `json:"digest"`
		} `json:"artifacts"`
	}
	decodeErr := json.Unmarshal(reply.Data, &data)
	if err != nil || reply.Status != "ok" || decodeErr != nil || len(data.Artifacts) != 1 || data.Artifacts[0].ID != run.ArtifactID {
		t.Fatal("installed report share source case", "status", reply.Status, "request", reply.RequestID, "call", err, "decode", decodeErr, "artifacts", len(data.Artifacts))
	}
	recipient := run.Identity.unrelated().mcpTokenSource(run.Origin)
	if _, err := recipient.Token(ctx); err != nil || recipient.subject == "" {
		t.Fatal("installed report recipient", err)
	}
	client := sdk.NewClient(&sdk.Implementation{Name: "installed-report-share", Version: "1"}, &sdk.ClientOptions{Capabilities: &sdk.ClientCapabilities{}})
	owner := run.Identity.shareTokenSource(run.Origin)
	if _, err := owner.Token(ctx); err != nil || owner.subject == "" {
		t.Fatal("installed report owner", err)
	}
	// These two users and stable groups are created by the actual fixture
	// realm. Four recipients exercise a continuation within one share at limit 3.
	recipients := []authorization.ShareRecipient{
		{Kind: "User", Issuer: run.Identity.Issuer, ID: recipient.subject},
		{Kind: "User", Issuer: run.Identity.Issuer, ID: owner.subject},
		{Kind: "Group", Issuer: run.Identity.Issuer, ID: installedIdentityGroup},
		{Kind: "Group", Issuer: run.Identity.Issuer, ID: installedUnrelatedGroup},
	}
	slices.SortFunc(recipients, func(a, b authorization.ShareRecipient) int { return strings.Compare(a.Key(), b.Key()) })
	wires := make([]map[string]string, 0, len(recipients))
	for _, recipient := range recipients {
		wires = append(wires, map[string]string{"kind": recipient.Kind, "issuer": recipient.Issuer, "id": recipient.ID})
	}
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: strings.TrimSuffix(run.Origin, "/") + "/mcp",
		HTTPClient: &http.Client{Transport: installedJourneyBearer{run.Transport, owner.Token}, Timeout: 30 * time.Second}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal("installed report share session", err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "create_share", Arguments: map[string]any{
		"case_id": run.CaseID, "artifacts": []map[string]string{{"artifactID": run.ArtifactID, "digest": data.Artifacts[0].Digest}},
		"recipients":   wires,
		"data_classes": []string{"metadata"}, "operations": []string{"get_case"}, "expires_at": run.ExpiresAt.UTC().Format(time.RFC3339Nano),
		"reason": "synthetic inventory report qualification", "idempotency_key": "installed-inventory-share",
	}})
	wire, wireErr := contracts.NewInvestigationContracts()
	if err != nil || wireErr != nil {
		t.Fatal("installed report share", err, wireErr)
	}
	envelope, code, err := installedJourneyReplyCode(wire, "create_share", result)
	var created struct {
		ID    string `json:"share_id"`
		Phase string `json:"phase"`
	}
	decodeErr = json.Unmarshal(envelope.Data, &created)
	if err != nil || envelope.Status != "ok" || decodeErr != nil || created.ID == "" || created.Phase != "Active" {
		t.Fatal("installed report share receipt", "status", envelope.Status, "code", code, "request", envelope.RequestID, "contract", err, "decode", decodeErr, "phase", created.Phase)
	}
	t.Logf("installed report create_share -> %s %s request %s with %d existing fixture recipients", envelope.Status, created.Phase, envelope.RequestID, len(recipients))
	return installedReportShare{ID: created.ID, OutsiderID: recipient.subject, Recipients: recipients}
}

func canonicalReportSource(raw string) ([]byte, error) {
	value := jsontext.Value(raw)
	if err := value.Canonicalize(); err != nil {
		return nil, err
	}
	return value, nil
}
