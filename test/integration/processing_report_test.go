package integration

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/privacy"
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
func qualifyProcessingReport(t *testing.T, ctx context.Context, hub *pgxpool.Pool, s captureAdmissionScenario, f *processingTestFixture, e artifact.ContextExpectation, custodyState, callOperation string) {
	t.Helper()
	reader, err := postgres.NewProcessingInventory(ctx, hub, s.a.RootID)
	if err != nil {
		t.Fatal("compiled processing report source", err)
	}
	service := privacyapp.ProcessingReport{RootID: s.a.RootID, InstallationID: s.recovery.installation, Policies: f.policy, Reports: reader, Now: time.Now}
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
	artifacts, processors, paths, rules, call, decisions := 0, []value.ProcessingOrganization{}, 0, 0, false, 0
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
		if op := record.Operation; op != nil && op.OperationID == callOperation {
			call = true
			if op.Name != "get_case" || op.ArtifactID != e.Registration.Location.ArtifactID || op.Status != "success" || op.OutputBytes == nil || *op.OutputBytes != 512 || op.ClientReceipt != "unknown" {
				t.Fatal("report changed the call audit row", op)
			}
		}
		if op := record.Operation; op != nil && (op.Name == "restrict_processing" || op.Name == "release_processing") && op.Subject == "synthetic-report-operator" {
			decisions++
		}
	}
	wantProcessors, _ := json.Marshal(f.policy.value.Processors)
	gotProcessors, _ := json.Marshal(processors)
	if artifacts != 1 || rules != 1 || paths != len(f.policy.value.Paths) || !call || decisions != 2 || string(gotProcessors) != string(wantProcessors) {
		t.Fatal("report incomplete source coverage or changed operator declarations", artifacts, rules, paths, call, decisions, string(gotProcessors))
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
	operator.value.Principal.Subject = "synthetic-report-operator"
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

// stageProcessingReportCall writes the audit row the public boundary writes
// for one call (REQ-AUT-005).
func stageProcessingReportCall(t *testing.T, ctx context.Context, hub *pgxpool.Pool, f *processingTestFixture, e artifact.ContextExpectation) string {
	t.Helper()
	events, err := postgres.NewAuditEvents(hub)
	if err != nil {
		t.Fatal(err)
	}
	actor := f.actor.value.Principal
	actor.Subject = "synthetic-report-reader"
	operation := custodyID()
	if err = events.Record(ctx, audit.Event{ID: custodyID(), OperationID: operation, Kind: "call", Operation: "get_case", Actor: actor, InputDigest: &artifact.Digest{73},
		Status: "success", Effect: "none", ArtifactIDs: []string{e.Registration.Location.ArtifactID}, OutputBytes: 512}); err != nil {
		t.Fatal("stage call audit row", err)
	}
	return operation
}
