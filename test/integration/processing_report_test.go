package integration

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	auditapp "asservat.local/asservat/internal/application/audit"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func reportFixtureProcessors() []value.ProcessingOrganization {
	return []value.ProcessingOrganization{
		{ID: "synthetic-evidence-processor", Name: "Synthetic evidence processor", Activities: []string{"managed evidence storage"}, Regions: []string{"synthetic-evidence-region"}},
		{ID: "synthetic-identity-processor", Name: "Synthetic identity processor", Activities: []string{"identity verification"}, Regions: []string{"synthetic-identity-region"}},
	}
}

// Read the actual source through the compiled hub pool before erasure and
// after independently acknowledged physical deletion. Policy/identity inputs
// remain the existing explicit synthetic service-fixture authority.
func qualifyProcessingReport(t *testing.T, ctx context.Context, hub *pgxpool.Pool, s captureAdmissionScenario, f *processingTestFixture, e artifact.ContextExpectation, custodyState, unknownOperation string) {
	t.Helper()
	reader, err := postgres.NewProcessingInventory(ctx, hub, s.a.RootID, s.recovery.guard)
	if err != nil {
		t.Fatal("compiled processing report source", err)
	}
	service := privacyapp.ProcessingReport{RootID: s.a.RootID, InstallationID: s.recovery.installation, Policies: f.policy, Recovery: s.recovery.reader, Reports: reader, Now: time.Now}
	var records []value.ProcessingReportRecord
	sections := []string{}
	query := value.ProcessingReportQuery{Section: "artifacts", Limit: 1}
	seen := map[string]bool{}
	pages := 0
	for {
		page, err := service.Get(ctx, f.actor, query)
		if err != nil || !page.Valid(query, time.Now()) {
			t.Fatal("real processing report page", query.Section, err)
		}
		pages++
		if pages > 64 {
			t.Fatal("report did not finish within its bounded source fixture")
		}
		if len(sections) == 0 || sections[len(sections)-1] != page.Section {
			sections = append(sections, page.Section)
		}
		for _, record := range page.Records {
			key, _ := json.Marshal(record.Cursor())
			if seen[page.Section+string(key)] {
				t.Fatal("processing report repeated a source record", page.Section)
			}
			seen[page.Section+string(key)] = true
			records = append(records, record)
		}
		if page.Next == nil {
			break
		}
		query = *page.Next
	}
	if !slices.Equal(sections, []string{"artifacts", "shares", "downloads", "operations", "rules", "paths", "processors"}) || pages < 8 {
		t.Fatal("processing report did not complete all paginated sections", sections, pages)
	}
	artifacts, processors, paths, rules, unknown := 0, []value.ProcessingOrganization{}, 0, 0, false
	for _, record := range records {
		if a := record.Artifact; a != nil {
			artifacts++
			if a.ArtifactID != e.Registration.Location.ArtifactID || a.CaptureID != e.CaptureUID || a.CaseID != e.CaseID ||
				a.StoreID != e.Registration.StoreID || a.PurposeRef != e.PurposeRef || a.PrivacyClass != "potentialPersonalData" ||
				!a.OriginalExpiresAt.Equal(e.Registration.ExpiresAt) || !a.OriginalDeleteBy.Equal(e.Registration.DeleteBy) || a.CustodyState != custodyState {
				t.Fatal("report lost original artifact identity, purpose or retention", a)
			}
			if custodyState == "deleted" && (a.DeletedAt == nil || a.DeletionState != "deleted" || !a.ExpiresAt.Equal(e.Registration.AnchorAt)) {
				t.Fatal("deleted artifact disappeared from report or lost exact erasure cutoff", a)
			}
		}
		if record.Processor != nil {
			processors = append(processors, *record.Processor)
		}
		if record.Path != nil {
			paths++
			if record.Path.ID != f.policy.value.Paths[0].ID {
				t.Fatal("report changed declared current path")
			}
		}
		if rule := record.Rule; rule != nil {
			rules++
			scope := rule.Scope.Domain()
			if rule.State != "released" || rule.Revision != 2 || scope.Kind != "artifact" || scope.Location != e.Registration.Location {
				t.Fatal("report changed the real immutable restriction/release scope", rule)
			}
		}
		if op := record.Operation; op != nil && op.OperationID == unknownOperation {
			unknown = true
			if !op.IntentAcknowledged || op.OutcomeAcknowledged || op.Status != "unknown" || op.OutputBytes != nil || op.ClientReceipt != "unknown" {
				t.Fatal("report invented delivery or output for missing outcome", op)
			}
		}
	}
	wantProcessors, _ := json.Marshal(f.policy.value.Processors)
	gotProcessors, _ := json.Marshal(processors)
	if artifacts != 1 || rules != 1 || paths != len(f.policy.value.Paths) || !unknown || string(gotProcessors) != string(wantProcessors) {
		t.Fatal("report incomplete source coverage or changed operator declarations", artifacts, rules, paths, unknown, string(gotProcessors))
	}
	outsider := f.actor
	outsider.value.Principal.Subject = "synthetic-report-outsider"
	if _, err := service.Get(ctx, outsider, value.ProcessingReportQuery{}); err == nil {
		t.Fatal("nonoperator read the real privacy report")
	}
}

func stageProcessingReportRule(t *testing.T, ctx context.Context, f *processingTestFixture, e artifact.ContextExpectation) {
	t.Helper()
	operator := f.actor
	operator.value.Principal.Subject = "synthetic-report-unconfirmed-client"
	f.policy.value.Operators = append(f.policy.value.Operators, value.ProcessingOperator{
		Issuer: operator.value.Principal.Issuer, ClientID: operator.value.Principal.ClientID, Kind: "User", ID: operator.value.Principal.Subject,
	})
	service := f.service
	service.Policies = f.policy
	rule := custodyID()
	scope := value.ProcessingScope{Kind: "artifact", Location: e.Registration.Location}
	if _, err := service.Change(ctx, operator, value.ProcessingChange{
		RequestID: custodyID(), RuleID: rule, Action: "restrict_processing", Scope: scope,
	}); err != nil {
		t.Fatal("real report restriction source", err)
	}
	if _, err := service.Change(ctx, operator, value.ProcessingChange{
		RequestID: custodyID(), RuleID: rule, Action: "release_processing", ExpectedRevision: 1, Scope: scope,
	}); err != nil {
		t.Fatal("real report exact release source", err)
	}
}

func stageProcessingReportUnknown(t *testing.T, ctx context.Context, f *processingTestFixture) string {
	t.Helper()
	n := time.Now().UTC().Truncate(time.Microsecond)
	actor := f.actor.value.Principal
	actor.Subject = "synthetic-report-unconfirmed-client"
	account, err := f.mac.Principal(actor)
	if err != nil {
		t.Fatal(err)
	}
	in := audit.OperationIntent{ID: custodyID(), RootID: f.service.RootID, TraceID: custodyID(), Name: "get_case", InputFormat: "context-input/v1",
		MACVersion: f.mac.Version(), AccountVersion: f.mac.AccountVersion(), Actor: actor, PrincipalDigest: account, InputDigest: artifact.Digest{73},
		CreatedAt: n, RequestUntil: n.Add(5 * time.Second), WriteUntil: n.Add(30 * time.Second), RetainUntil: n.Add(time.Hour)}
	in, err = auditapp.BindOperationLifecycle(in, f.service.AuditPolicy)
	if err != nil || !in.Valid() || actor.Kind != identity.Human {
		t.Fatal("unconfirmed report operation fixture", err)
	}
	if err = f.service.Audit.Begin(ctx, in); err != nil {
		t.Fatal("stage real acknowledged intent with unknown outcome", err)
	}
	return in.ID
}

func (f *capacitySQLFixture) assertReportOriginalSession(t *testing.T, session artifact.DownloadSession) {
	t.Helper()
	var original, shared, metadata time.Time
	var revision int64
	if err := f.admin.QueryRow(f.ctx, `
SELECT (d.capacity_backing#>>'{Native,RetireBy}')::timestamptz,b.retire_by,p.retire_by,(s.root_configuration->>'Revision')::bigint
FROM artifact_download d JOIN download_native_backing b ON b.root_id=d.root_id AND b.allocation_id=d.allocation_id
JOIN context_processing p ON p.root_id=d.root_id AND p.artifact_id=d.artifact_id
JOIN capacity_source s ON s.root_id=d.root_id
WHERE d.id=$1`, session.ID).Scan(&original, &shared, &metadata, &revision); err != nil || !metadata.After(original) || shared.Before(original) || revision > 1 && !shared.After(original) {
		t.Fatal("report fixture does not isolate original session retirement from parent metadata", original, shared, metadata, err)
	}
	q := custodydb.New(f.roles["hub-runtime"])
	read := func(observed time.Time) []custodydb.ReportProcessingDownloadsRow {
		t.Helper()
		rows, err := q.ReportProcessingDownloads(f.ctx, custodydb.ReportProcessingDownloadsParams{
			RootID: capacityProjectionUUID(t, session.Scope.RootID), AfterID: capacityProjectionUUID(t, "00000000-0000-0000-0000-000000000000"),
			CreatedBefore: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}, ObservedAt: pgtype.Timestamptz{Time: observed, Valid: true}, PageLimit: 3,
		})
		if err != nil {
			t.Fatal("compiled report session query", err)
		}
		return rows
	}
	before := read(original.Add(-time.Microsecond))
	found := false
	for _, row := range before {
		if row.ID == capacityProjectionUUID(t, session.ID) {
			found = true
			if !row.VisibleUntil.Time.Equal(original) {
				t.Fatal("report renewed the original session visibility", row.VisibleUntil.Time, original)
			}
		}
	}
	if !found {
		t.Fatal("original managed session missing before report retirement")
	}
	for _, row := range read(original) {
		if row.ID == capacityProjectionUUID(t, session.ID) {
			t.Fatal("report disclosed a session at its original retirement after shared backing renewal")
		}
	}
	if shared.After(original) {
		t.Log("report retained original session visibility while both shared backing and artifact metadata remained valid beyond it")
	}
}
