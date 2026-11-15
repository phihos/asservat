package integration

import (
	"context"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	authapp "asservat.local/asservat/internal/application/authorization"
	captureapp "asservat.local/asservat/internal/application/capture"
	executionapp "asservat.local/asservat/internal/application/execution"
	identities "asservat.local/asservat/internal/application/identity"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/capture"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This only retains the actual runner result for the existing independent
// publication assertions. It supplies no authorization or synthetic execution.
type nativeContinuationStart struct {
	runner   *executionapp.APIContextRunner
	regional captureapp.ContextAcceptedStart
	result   executionapp.ContextResult
	calls    int
}

func (s *nativeContinuationStart) StartContext(ctx context.Context, current identities.CurrentIdentity, id string) error {
	s.calls++
	if s.regional != nil {
		return s.regional.StartContext(ctx, current, id)
	}
	if s.runner == nil {
		return value.ErrUnavailable
	}
	r, err := s.runner.Execute(ctx, current, id)
	if err == nil && r.State == "StoredPendingVerification" {
		s.result = r
	}
	return err
}

func nativeContinuationSubmission(t *testing.T, ctx context.Context, n *nativeAPIEnvironment, s captureAdmissionScenario, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys, start *nativeContinuationStart) captureapp.ContextSubmission {
	t.Helper()
	investigation, publication := nativeContinuationApplicationServices(t, ctx, n, s, admin, poolFor, store, keys)
	admissions := investigation.Admission.(*postgres.ContextAdmissions)
	investigation.Replay = nativeContinuationAdmissions{t, admissions}
	investigation.Admission = nativeContinuationAdmissions{t, admissions}
	return captureapp.ContextSubmission{ContextInvestigation: investigation, Intents: nativeContinuationIntents{t, publication}, Start: start}
}

// Reuse the original real admission/audit services in the shared operation
// assembly without reconstructing or replacing their accepted root or receipts.
func nativeContinuationApplicationServices(t *testing.T, ctx context.Context, n *nativeAPIEnvironment, s captureAdmissionScenario, admin *pgxpool.Pool, poolFor func(string, string) *pgxpool.Pool, store *objectstore.Store, keys authorityTestKeys) (captureapp.ContextInvestigation, captureapp.ContextAcceptedIntents) {
	t.Helper()
	pool := func(user, password string) *pgxpool.Pool { p := poolFor(user, password); t.Cleanup(p.Close); return p }
	previews, err := postgres.NewContextPreviews(ctx, pool("context_preview_runtime", "synthetic-context-preview"), s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	storage, err := postgres.NewContextStorageReader(ctx, pool("context_storage_read_runtime", "synthetic-context-storage-read"), s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	admit := pool("capture_operation_admit_runtime", "synthetic-capture-operation-admit")
	admissions, err := postgres.NewContextAdmissions(ctx, admit, s.a.RootID, s.recovery.installation, s.retention.guard)
	if err != nil {
		t.Fatal(err)
	}
	intents, err := postgres.NewCaptureIntents(ctx, admit, s.a.RootID)
	if err != nil {
		t.Fatal(err)
	}
	processing, err := postgres.NewProcessingReads(ctx, pool("context_catalog_read_runtime", "synthetic-context-read"), s.a.RootID, s.recovery.installation)
	if err != nil {
		t.Fatal("current pre-collection processing reader", err)
	}

	return captureapp.ContextInvestigation{RootID: s.a.RootID, InstallationID: s.recovery.installation, Previews: previews, Replay: admissions, Admission: admissions, Targets: n.resolver, Eligibility: authapp.Evaluator{Permissions: s.p, Now: time.Now}, Capabilities: nativeAPICapability{s.a.Plan.Input.Capability}, Retention: nativeAPIRetention{s.retention}, Storage: storage, Processing: processing, Lifetime: 30 * time.Second, Now: time.Now, NewID: custodyID}, intents
}

// Test-only boundary diagnostics report no identity, source, receipt or evidence
// fields, and never replay an operation to infer its outcome.
type nativeContinuationAdmissions struct {
	t     *testing.T
	inner *postgres.ContextAdmissions
}

func (s nativeContinuationAdmissions) LookupContextAdmission(ctx context.Context, in value.ReplayQuery) (value.Accepted, bool, error) {
	started := time.Now()
	a, found, err := s.inner.LookupContextAdmission(ctx, in)
	s.t.Logf("native continuation stage=lookup elapsed=%s found=%t accepted=%t error=%v", time.Since(started), found, a.CaptureID != "", err)
	return a, found, err
}
func (s nativeContinuationAdmissions) AdmitReviewedContext(ctx context.Context, preview string, in value.Admission) (value.Accepted, error) {
	started := time.Now()
	a, err := s.inner.AdmitReviewedContext(ctx, preview, in)
	s.t.Logf("native continuation stage=reviewed-admission elapsed=%s accepted=%t error=%v", time.Since(started), a.CaptureID != "", err)
	return a, err
}

type nativeContinuationIntents struct {
	t     *testing.T
	inner captureapp.ContextAcceptedIntents
}

func (s nativeContinuationIntents) AcceptedCaptureIntent(ctx context.Context, id string) (auditvalue.CaptureIntent, error) {
	started := time.Now()
	intent, err := s.inner.AcceptedCaptureIntent(ctx, id)
	s.t.Logf("native continuation stage=intent-read elapsed=%s valid=%t error=%v", time.Since(started), intent.Valid(), err)
	return intent, err
}
func diagnoseNativeContinuation(t *testing.T, ctx context.Context, admin *pgxpool.Pool, root, preview string) {
	t.Helper()
	read, end := context.WithTimeout(ctx, 2*time.Second)
	defer end()
	var previews, closed, captures, audits int64
	err := admin.QueryRow(read, `SELECT
  (SELECT count(*) FROM context_preview WHERE root_id=$1 AND id=$2),
  (SELECT count(*) FROM context_preview WHERE root_id=$1 AND id=$2 AND closed_at IS NOT NULL),
  (SELECT count(*) FROM context_capture WHERE root_id=$1 AND preview_id=$2),
  (SELECT count(*) FROM audit_event a JOIN context_capture c ON c.id=a.operation_id WHERE c.root_id=$1 AND c.preview_id=$2 AND a.kind='capture.start')`, root, preview).Scan(&previews, &closed, &captures, &audits)
	t.Logf("native continuation retained-state previews=%d closed=%d captures=%d audits=%d diagnostic-error=%v", previews, closed, captures, audits, err)
}
