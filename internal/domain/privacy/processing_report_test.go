package privacy

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/identity"
)

func TestProcessingReportCursorShape(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	base := ProcessingReportQuery{Section: "operations", Limit: 3, CreatedBefore: now, PolicyDigest: strings.Repeat("01", 32),
		After: ProcessingReportCursor{ID: processingID(1), Ordinal: 2}}
	if !base.Valid() || !(ProcessingReportQuery{}).Valid() {
		t.Fatal("valid initial or continuation refused")
	}
	for _, change := range []func(*ProcessingReportQuery){
		func(q *ProcessingReportQuery) { q.CreatedBefore = time.Time{} },
		func(q *ProcessingReportQuery) { q.PolicyDigest = strings.Repeat("AB", 32) },
		func(q *ProcessingReportQuery) { q.PolicyDigest = "g" + strings.Repeat("0", 63) },
		func(q *ProcessingReportQuery) { q.PolicyDigest = strings.Repeat("0", 63) },
		func(q *ProcessingReportQuery) { q.After.Ordinal = 101 },
		func(q *ProcessingReportQuery) { q.After.CreatedAt = now },
		func(q *ProcessingReportQuery) { q.Section = "downloads" },
		func(q *ProcessingReportQuery) { q.Limit = 4 },
	} {
		bad := base
		change(&bad)
		if bad.Valid() {
			t.Fatal("invalid continuation accepted", bad)
		}
	}
	base.Section = "shares"
	base.After.CreatedAt = now
	if !base.Valid() {
		t.Fatal("valid recipient continuation refused")
	}
	base.After.Ordinal = 0
	if base.Valid() {
		t.Fatal("share continuation lost its recipient ordinal")
	}
}

func TestProcessingReportSequentialPagesAndOriginalCutoff(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := hex.EncodeToString(make([]byte, 32))
	q := ProcessingReportQuery{Section: "processors", Limit: 1, CreatedBefore: now, PolicyDigest: digest}
	org := ProcessingOrganization{ID: "processor-a", Name: "Synthetic operator declaration", Activities: []string{"storage"}, Regions: []string{}}
	page := ProcessingReportPage{SchemaVersion: ProcessingReportFormat, RootID: processingID(1), InstallationID: processingID(2),
		Section: "processors", SelectionCreatedBefore: now, PolicyRevision: ProcessingReportRevision{UID: "synthetic-policy", Generation: 1, Digest: digest},
		Records: []ProcessingReportRecord{{VisibleUntil: now.Add(time.Second), Processor: &org}}, ObservedAt: now, ValidUntil: now.Add(time.Second),
		ProcessorDeclarations: "supplied", Coverage: ProcessingReportCoverage()}
	if !page.Valid(q, now) {
		t.Fatal("valid final report page refused")
	}
	if page.Valid(q, now.Add(time.Second)) {
		t.Fatal("original individual cutoff was renewed")
	}
	q.Section, page.Section = "paths", "paths"
	page.Records = []ProcessingReportRecord{}
	if page.Valid(q, now) {
		t.Fatal("report ended before processor declarations")
	}
	next := q
	next.Section = "processors"
	page.Next = &next
	if !page.Valid(q, now) {
		t.Fatal("empty section could not advance")
	}
	next.Section = "artifacts"
	if page.Valid(q, now) {
		t.Fatal("section order moved backwards")
	}
}

func TestProcessingReportRuleScopePreservesStoredRepresentation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	stored := ProcessingScope{Kind: "workloadInterval", ClusterID: processingID(9), NamespaceUID: "namespace", WorkloadUID: "workload",
		AcquiredFrom: now.Add(-time.Minute), AcquiredUntil: now}
	before, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	wire := ProcessingReportScopeFrom(stored)
	raw, err := json.Marshal(wire)
	if err != nil || strings.Contains(string(raw), "AcquiredFrom") || !strings.Contains(string(raw), "\"acquired_from\"") {
		t.Fatal("report scope did not use its own snake case DTO", string(raw), err)
	}
	if !wire.Domain().Equal(stored) {
		t.Fatal("report scope changed immutable scope")
	}
	after, _ := json.Marshal(stored)
	if string(before) != string(after) {
		t.Fatal("report conversion mutated stored scope")
	}
}

func TestProcessingReportClientOperationLanes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	operation := ProcessingReportOperation{
		OperationID: processingID(20), Name: "resolve_capture_request", Lane: "resolution",
		Issuer: "https://identity.invalid", Subject: "synthetic-operator", ClientID: "console",
		PrincipalKind: identity.Human, CreatedAt: now, Status: "unknown", ClientReceipt: "unknown",
	}
	record := ProcessingReportRecord{VisibleUntil: now.Add(time.Second), Operation: &operation}
	for _, lane := range []string{"normal", "resolution", "processing"} {
		operation.Lane = lane
		if !record.Valid("operations", now) {
			t.Fatal("client operation lane was omitted from inventory", lane)
		}
	}
	for _, lane := range []string{"", "identity", "capture", "arbitrary"} {
		operation.Lane = lane
		if record.Valid("operations", now) {
			t.Fatal("private or unsupported operation lane entered client inventory", lane)
		}
	}
	operation.Lane = "resolution"
	operation.OutcomeAcknowledged = true
	if record.Valid("operations", now) {
		t.Fatal("a missing outcome became an acknowledged zero-byte disclosure")
	}
}
