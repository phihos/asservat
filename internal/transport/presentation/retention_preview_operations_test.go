package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

type retentionPreviewOpsFixture struct {
	now     time.Time
	preview privacy.RetentionPreview
	err     error
	got     []privacyapp.ProposedRetentionChange
}

func (f *retentionPreviewOpsFixture) ResolveIdentity(context.Context) (identity.Identity, error) {
	return identity.Identity{Principal: identity.Principal{Issuer: "https://id.example.invalid", Subject: "admin", ClientID: "console", Kind: identity.Human}, Groups: []string{"platform-admins"}, Policy: identity.Revision{UID: "identity", Generation: 1, Digest: artifact.Digest{1}}, VerifiedAt: f.now, ValidUntil: f.now.Add(30 * time.Second)}, nil
}
func (f *retentionPreviewOpsFixture) Preview(_ context.Context, _ privacyapp.PreviewIdentity, changes []privacyapp.ProposedRetentionChange) (privacy.RetentionPreview, time.Time, error) {
	f.got = changes
	return f.preview, f.now.Add(5 * time.Second), f.err
}

const retentionSpecJSON = `{"scope":{},"purposeRef":"diagnostics","defaults":{"evidenceSeconds":3600,"caseMetadataSeconds":3600,"auditMetadataSeconds":3600},` +
	`"maxima":{"evidenceSeconds":7200,"caseMetadataSeconds":7200,"auditMetadataSeconds":7200},"rules":[],"deletionBudgetSeconds":300,"legalExceptions":"disabled"}`

func newRetentionPreviewOps(t *testing.T) (*retentionPreviewOpsFixture, *RetentionPreviewOperations) {
	t.Helper()
	f := &retentionPreviewOpsFixture{now: time.Now().UTC()}
	ops, err := NewRetentionPreviewOperations("https://asservat.example.invalid", time.Now, func() string { return "00000000-0000-4000-8000-000000000042" }, f)
	if err != nil {
		t.Fatal(err)
	}
	return f, ops
}

func callRetentionPreview(t *testing.T, f *retentionPreviewOpsFixture, ops *RetentionPreviewOperations, input string) map[string]any {
	t.Helper()
	reply, err := ops.Call(context.Background(), f, "preview_retention_change", json.RawMessage(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(reply.Body) > contracts.InvestigationOutputLimit {
		t.Fatalf("reply %d bytes", len(reply.Body))
	}
	t.Logf("reply %d bytes", len(reply.Body))
	var out map[string]any
	if err = json.Unmarshal(reply.Body, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// ADR-240: the reply is the canonical contract, carries the totals and dates,
// and the raw spec reaches the use case unchanged.
func TestRetentionPreviewOperationReply(t *testing.T) {
	f, ops := newRetentionPreviewOps(t)
	cluster := "22222222-3333-4444-8555-666666666666"
	at := f.now.Add(time.Hour).Truncate(time.Microsecond)
	f.preview = privacy.RetentionPreview{Scanned: 3, Affected: 2, ReadClosed: 1, DeletionDue: 1, Unknown: 1, EarliestExpiresAt: at, EarliestDeleteBy: at.Add(time.Minute), ObservedAt: f.now,
		Groups:       []privacy.RetentionPreviewGroup{{ClusterID: cluster, PrivacyClass: "potentialPersonalData", EvidenceType: "context", Scanned: 3, Affected: 2, ReadClosed: 1, DeletionDue: 1, Unknown: 1, EarliestExpiresAt: at, EarliestDeleteBy: at.Add(time.Minute)}},
		Incomplete:   []privacy.PreviewIncomplete{{ClusterID: cluster, Reason: privacy.PreviewSourceUnavailable}},
		NotEvaluated: []privacy.PreviewNotEvaluated{{Action: "update", SourceClusterID: cluster, UID: "gone", Reason: privacy.PreviewUnknownObject}}}
	out := callRetentionPreview(t, f, ops, `{"changes":[{"action":"update","uid":"baseline","spec":`+retentionSpecJSON+`},{"action":"delete","source_cluster_id":"`+cluster+`","uid":"local"}]}`)
	data := out["data"].(map[string]any)
	if out["status"] != "ok" || data["complete"] != false || data["affected_total"] != 2.0 || data["unknown_total"] != 1.0 || data["groups_total"] != 1.0 || data["incomplete_total"] != 1.0 || data["earliest_delete_by"] == nil || out["next_cursor"] != nil {
		t.Fatalf("%v", out)
	}
	if len(f.got) != 2 || f.got[0].Action != "update" || f.got[0].SourceClusterID != "" || string(f.got[0].Spec) != retentionSpecJSON || f.got[1].SourceClusterID != cluster || len(f.got[1].Spec) != 0 {
		t.Fatalf("%+v", f.got)
	}
}

// The largest reply (32 listed groups, 32 incomplete clusters, 16 changes
// not evaluated) fits the shared 24 KiB operation reply; totals count all.
func TestRetentionPreviewOperationLargestReply(t *testing.T) {
	f, ops := newRetentionPreviewOps(t)
	at := f.now.Add(time.Hour).Truncate(time.Microsecond)
	for i := range 200 {
		cluster := fmt.Sprintf("22222222-3333-4444-8555-%012d", i)
		f.preview.Groups = append(f.preview.Groups, privacy.RetentionPreviewGroup{ClusterID: cluster, PrivacyClass: "specialCategoryPossible", EvidenceType: "commandOutput", Scanned: 10000, Affected: 10000, ReadClosed: 10000, DeletionDue: 10000, Unknown: 10000, EarliestExpiresAt: at, EarliestDeleteBy: at})
		f.preview.Incomplete = append(f.preview.Incomplete, privacy.PreviewIncomplete{ClusterID: cluster, Reason: privacy.PreviewSourceUnavailable})
	}
	for i := range 16 {
		f.preview.NotEvaluated = append(f.preview.NotEvaluated, privacy.PreviewNotEvaluated{Action: "update", SourceClusterID: "22222222-3333-4444-8555-666666666666", UID: fmt.Sprintf("%064d", i), Reason: privacy.PreviewSourceAmbiguous})
	}
	f.preview.ObservedAt = f.now
	data := callRetentionPreview(t, f, ops, `{"changes":[{"action":"delete","uid":"baseline"}]}`)["data"].(map[string]any)
	if len(data["groups"].([]any)) != 32 || data["groups_total"] != 200.0 || len(data["incomplete_clusters"].([]any)) != 32 || data["incomplete_total"] != 200.0 || len(data["not_evaluated"].([]any)) != 16 {
		t.Fatalf("%v", data)
	}
}

func TestRetentionPreviewOperationFailures(t *testing.T) {
	for err, code := range map[error]string{privacy.ErrPreviewLimit: "PreviewTooLarge", privacy.ErrInvalid: "InvalidProposal", identity.ErrDenied: "AdministratorRequired", identity.ErrUnavailable: "NotAvailable"} {
		f, ops := newRetentionPreviewOps(t)
		f.err = err
		out := callRetentionPreview(t, f, ops, `{"changes":[{"action":"delete","uid":"baseline"}]}`)
		if out["status"] != "error" || out["data"].(map[string]any)["code"] != code {
			t.Fatalf("%v: %v", err, out)
		}
	}
	f, ops := newRetentionPreviewOps(t)
	for _, bad := range []string{
		`{"changes":[]}`,
		`{"changes":[{"action":"delete"}]}`,
		`{"changes":[{"action":"create","uid":"x","spec":` + retentionSpecJSON + `}]}`,
		`{"changes":[{"action":"update","uid":"x","spec":{"purposeRef":"x"}}]}`,
		`{"changes":[{"action":"delete","uid":"x","source_cluster_id":"cluster"}]}`,
	} {
		if _, err := ops.Call(context.Background(), f, "preview_retention_change", json.RawMessage(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	if d, ok := ops.Tool("preview_retention_change"); !ok || d.MCP() {
		t.Fatal("the retention preview must be browser-only")
	}
	if _, err := ops.Call(context.Background(), f, "explain_access", json.RawMessage(`{}`)); !errors.Is(err, contracts.ErrInvestigationWire) {
		t.Fatal(err)
	}
}
