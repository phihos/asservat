package integration

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/privacy"
)

// This uses the actual fixed purpose15/40 credentials and managed SQL54 account.
// It creates no audit object, runs no collector and never mutates backing to
// make a negative pass. Original human/target/source setup remains synthetic.
func (f *capacitySQLFixture) checkManagedProcessingAdmission(t *testing.T, admissions *postgres.ContextAdmissions, recovery *postgres.RecoveryTransactionGuard, policies privacy.PolicySet, original value.Admission) {
	t.Helper()
	ctx, end := context.WithDeadline(f.ctx, original.Eligibility.VerifiedIdentity.ValidUntil)
	defer end()
	reader, err := postgres.NewProcessingReads(ctx, f.roles["hub-metadata-read"], f.input.PermissionRootID, recovery)
	if err != nil {
		t.Fatal("fixed processing-read constructor", err)
	}
	input := original.Plan.Input
	requested := int64(3600)
	resolved, err := privacy.Resolve(policies, privacy.Input{Target: input.Target.Target(), PrivacyClass: "potentialPersonalData", EvidenceType: "context", AnchorAt: input.Retention.AnchorAt, RequestedSeconds: requested}, time.Now())
	if err != nil {
		t.Fatal("long retention fixture shape", err)
	}
	input.CaptureID = custodyID()
	input.Retention = resolved
	plan, err := planning.CompileContext(input, time.Now())
	if err != nil {
		t.Fatal("long retention plan shape", err)
	}
	denied := original
	denied.Plan = plan
	denied.IdempotencyKey = "processing-coverage-denied-original"
	denied.SubmissionDigest = artifact.Digest{146}
	denied.Registration.Location.ArtifactID = custodyID()
	denied.Registration.Location.AttemptID = custodyID()
	denied.Registration.ExpiresAt = resolved.ExpiresAt
	denied.Registration.DeleteBy = resolved.DeleteBy
	if denied.Registration.Validate() != nil || !planning.VerifyContextPlan(denied.Plan, time.Now()) || denied.Plan.Input.Retention.RequestedSeconds != requested {
		t.Fatal("long retention request malformed")
	}
	query := value.ProcessingCoverageRequest{RootID: denied.RootID, Location: denied.Registration.Location, Target: denied.Plan.Input.Target.Target(), AnchorAt: denied.Registration.AnchorAt, DeleteBy: denied.Registration.DeleteBy}
	if !query.Valid() {
		t.Fatal("coverage request malformed")
	}
	snapshot := func() []byte {
		var data []byte
		err := f.admin.QueryRow(ctx, `SELECT jsonb_build_object(
 'storage',(SELECT jsonb_build_array(charged_bytes,charged_objects) FROM custody_allocation WHERE id=$2),
 'control',(SELECT jsonb_build_array(charged_full,charged_replay) FROM context_control_account WHERE root_id=$1 AND allocation_id=$2),
 'attempts',(SELECT count(*) FROM custody_attempt WHERE allocation_id=$2),
 'captures',(SELECT count(*) FROM context_capture WHERE root_id=$1),
 'audit',(SELECT COALESCE(jsonb_agg(jsonb_build_array(principal_digest,charged) ORDER BY principal_digest),'[]') FROM operation_audit_account WHERE root_id=$1 AND lane='capture'),
 'pairs',(SELECT count(*) FROM operation_audit WHERE root_id=$1 AND lane='capture'),
 'bindings',(SELECT count(*) FROM capture_audit_binding WHERE root_id=$1),
 'lineage',(SELECT captures FROM processing_root WHERE root_id=$1))::text`, original.RootID, original.Registration.AllocationID).Scan(&data)
		if err != nil {
			t.Fatal("processing no-charge snapshot unavailable", err)
		}
		return data
	}
	before := snapshot()
	t.Run("processing-read-rejects-uncovered-retention", func(t *testing.T) {
		out, err := reader.ContextProcessingCoverage(ctx, query, original.Recovery)
		if !errors.Is(err, value.ErrProcessingCoverage) || out != (value.ProcessingCoverage{}) {
			t.Fatal("known original horizon not rejected by purpose15", err)
		}
	})
	t.Run("managed-admission-rejects-uncovered-retention-without-charge", func(t *testing.T) {
		_, err := admissions.AdmitContext(ctx, denied)
		if !errors.Is(err, value.ErrProcessingCoverage) {
			t.Fatal("managed admission did not reach actual coverage gate", err)
		}
		if after := snapshot(); !bytes.Equal(before, after) {
			t.Fatal("known rejected new capture consumed backing")
		}
		if denied.Plan.Input.Retention.RequestedSeconds != requested || denied.Registration.DeleteBy != resolved.DeleteBy {
			t.Fatal("requested retention rewritten")
		}
	})
	t.Run("managed-admission-original-expiry-after-permission-wait", func(t *testing.T) {
		tx, err := f.admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(f.ctx)
		var locked string
		if err = tx.QueryRow(ctx, `SELECT id::text FROM permission_stream WHERE id=$1 FOR UPDATE`, original.RootID).Scan(&locked); err != nil {
			t.Fatal(err)
		}
		call, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
		defer cancel()
		result := make(chan error, 1)
		joined := make(chan struct{})
		defer func() { cancel(); <-joined }()
		go func() { defer close(joined); _, e := admissions.AdmitContext(call, denied); result <- e }()
		f.waitBlocked(t, f.roles["capture-admit"].Config().ConnConfig.User, call)
		select {
		case err = <-result:
			if !errors.Is(err, value.ErrUnavailable) {
				t.Fatal("original caller expiry escaped blocking admission", err)
			}
		case <-ctx.Done():
			t.Fatal("expired admission did not join")
		}
		if err = tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if after := snapshot(); !bytes.Equal(before, after) {
			t.Fatal("expired waiting request consumed backing")
		}
	})
	if t.Failed() {
		t.FailNow()
	}
	// The already prepared short request receives a read-only positive observation
	// under its existing interval. No new phase or request deadline is issued.
	query.Location = original.Registration.Location
	query.AnchorAt = original.Registration.AnchorAt
	query.DeleteBy = original.Registration.DeleteBy
	if out, err := reader.ContextProcessingCoverage(ctx, query, original.Recovery); err != nil || !out.Current(time.Now()) || out.Request != query {
		t.Fatal("current short retention coverage unavailable", err)
	}
}
