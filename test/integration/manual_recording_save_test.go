//go:build cgo && libpcap

package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	capacity "asservat.local/asservat/internal/application/capacity"
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/capture"
	executionvalue "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
)

type manualSaveCounters struct {
	Executions, Collected, Observed   int64
	Shares, Occurrences, Reservations int
	SharingEligible                   bool
}

func readManualSaveCounters(t *testing.T, ctx context.Context, f *capacitySQLFixture, policy policySourceAcceptedFixture) manualSaveCounters {
	t.Helper()
	var out manualSaveCounters
	err := f.admin.QueryRow(ctx, `SELECT a.executions_spent,a.collected_bytes_spent,a.observed_bytes_spent,a.shares_spent,
 (SELECT count(*) FROM policy_occurrence o WHERE o.root_id=a.root_id AND o.policy_uid=a.policy_uid),
 (SELECT count(*) FROM recording_save_reservation r WHERE r.root_id=a.root_id AND r.acceptance_id=a.id),
 COALESCE(jsonb_typeof(a.record->'Sharing')='object' AND (a.record#>>'{Sharing,MaxCaptures}')::integer>0 AND (a.record#>>'{Sharing,NotAfter}')::timestamptz>clock_timestamp() AND a.sharing_revoked_at IS NULL AND a.sharing_stopped_at IS NULL,false)
 FROM policy_acceptance a WHERE a.root_id=$1 AND a.id=$2`, policy.Scenario.a.RootID, policy.Record.Record.ID).Scan(&out.Executions, &out.Collected, &out.Observed, &out.Shares, &out.Occurrences, &out.Reservations, &out.SharingEligible)
	if err != nil {
		t.Fatal("manual policy counters", err)
	}
	return out
}

// Genuine source/policy/permission/custody SQL; initial identity, target, node,
// source report and packet observations remain explicit synthetic fixture facts.
func qualifyManualRecordingSave(t *testing.T, ctx context.Context, f *capacitySQLFixture, admissions *postgres.ContextAdmissions, policy policySourceAcceptedFixture, source captureapp.PolicySourceAdmission, fresh captureapp.PolicySourceCheck, intents auditapp.CaptureOperationPublication) {
	t.Helper()
	before := readManualSaveCounters(t, ctx, f, policy)
	var beforeGrant manualPolicyGrantSpend
	if policy.GrantID != "" {
		beforeGrant = readManualPolicyGrantSpend(t, ctx, f, policy.GrantID)
		if beforeGrant.Executions != 0 || beforeGrant.Bytes != 0 || beforeGrant.Observed != 0 || !beforeGrant.Ordinary {
			t.Fatal("source replay/renewal changed ordinary grant pools before manual save", beforeGrant)
		}
	}
	if !before.SharingEligible || before.Occurrences != 0 {
		t.Fatal("fixture needs genuinely accepted live recurring sharing and no detector occurrence", before)
	}
	var original value.Admission
	var preview value.ContextPreview
	snapshot := admitManualRecordingSaveFixture(t, ctx, f.roles["hub-runtime"], admissions, policy, source, fresh, min(policy.Compiled.Recorder.Action.MaxBytes, int64(artifact.RecordingNativeLimit)), func(t *testing.T, a value.Admission, p value.ContextPreview) {
		original, preview = a, p.Clone()
		t.Run("reject-current-initiator-without-rights", func(t *testing.T) {
			candidate := a
			manual := *a.RecordingSave
			candidate.RecordingSave = &manual
			candidate.RecordingSave.Initiator.VerifiedIdentity.Groups = []string{"not-a-current-maintainer"}
			if _, err := admissions.AdmitReviewedContext(ctx, p.ID, candidate); err == nil {
				t.Fatal("claimed eligibility bypassed current initiator permissions")
			}
			if got := readManualSaveCounters(t, ctx, f, policy); got != before {
				t.Fatal("denied manual initiator spent policy resources", got, before)
			}
		})
		t.Run("reject-disabled-policy-opt-in", func(t *testing.T) {
			candidate := a
			manual := *a.RecordingSave
			candidate.RecordingSave = &manual
			candidate.RecordingSave.Policy.RecordingSaves = false
			if _, err := admissions.AdmitReviewedContext(ctx, p.ID, candidate); err == nil {
				t.Fatal("disabled recording save admitted")
			}
			if got := readManualSaveCounters(t, ctx, f, policy); got != before {
				t.Fatal("disabled opt-in spent policy resources", got, before)
			}
		})
	})
	accepted := snapshot.Accepted
	t.Run("first-admission-t0-and-replay", func(t *testing.T) {
		if accepted.Expectation.Snapshot == nil || !accepted.Expectation.Snapshot.T0.Equal(accepted.CreatedAt) || !accepted.CreatedAt.After(preview.CreatedAt) || !accepted.CreatedAt.After(preview.Intent.Snapshot.Request.T0) {
			t.Fatal("manual T0 came from passive preview", accepted.CreatedAt, preview.CreatedAt)
		}
		replay, err := admissions.AdmitReviewedContext(ctx, preview.ID, original)
		if err != nil || replay.CaptureID != accepted.CaptureID || !replay.CreatedAt.Equal(accepted.CreatedAt) || replay.Expectation.Snapshot == nil || !replay.Expectation.Snapshot.Equal(*accepted.Expectation.Snapshot) || replay.Expectation.Registration != accepted.Expectation.Registration {
			t.Fatal("manual replay renewed first acceptance", replay, err)
		}
	})
	after := readManualSaveCounters(t, ctx, f, policy)
	var reserved int64
	var at, until time.Time
	var grant string
	if err := f.admin.QueryRow(ctx, `SELECT reserved_bytes,accepted_at,processing_until,COALESCE(grant_id::text,'') FROM recording_save_reservation WHERE root_id=$1 AND capture_id=$2`, original.RootID, accepted.CaptureID).Scan(&reserved, &at, &until, &grant); err != nil || reserved <= 0 || !at.Equal(accepted.CreatedAt) || !until.Equal(accepted.Deadline) {
		t.Fatal("manual reservation changed accepted clock or output", reserved, at, until, err)
	}
	if after.Executions != before.Executions+1 || after.Collected != before.Collected+reserved || after.Observed != before.Observed || after.Reservations != before.Reservations+1 || after.Occurrences != 0 || after.Shares != before.Shares {
		t.Fatal("manual admission/replay did not use existing shared pools exactly once", before, after, reserved)
	}
	var spentGrant manualPolicyGrantSpend
	if policy.GrantID != "" {
		t.Run("manual-policy-grant-spend-and-replay", func(t *testing.T) {
			spentGrant = readManualPolicyGrantSpend(t, ctx, f, policy.GrantID)
			want := beforeGrant
			want.Executions++
			want.Bytes += reserved
			if grant != policy.GrantID || spentGrant != want {
				t.Fatal("manual admission/replay changed original grant or charged wrong pools", grant, spentGrant, want)
			}
		})
	}
	t.Run("manual-history-and-no-inherited-sharing", func(t *testing.T) {
		var origin string
		var unshared bool
		if err := f.admin.QueryRow(ctx, `SELECT history_origin,share_instruction IS NULL FROM context_capture WHERE root_id=$1 AND id=$2`, original.RootID, accepted.CaptureID).Scan(&origin, &unshared); err != nil || origin != "manual" || !unshared {
			t.Fatal("manual Save inherited recurring sharing or policy origin", origin, unshared, err)
		}
	})
	t.Run("encrypted-completion-publication-native", func(t *testing.T) {
		var cancelCheck value.CancellationCheck
		var cancelExecution executionvalue.APIExecution
		var cancelProcess executionvalue.APIProcessObservation
		var cancellationLedger *postgres.APIContextExecutions
		qualifySourceSnapshotCompletion(t, ctx, f, policy, snapshot, intents, func(executions *postgres.APIContextExecutions, candidate executionvalue.APIExecution, process executionvalue.APIProcessObservation, recovery artifact.RecoveryProof) {
			var revision int64
			if err := f.admin.QueryRow(ctx, `SELECT progress_revision FROM context_capture WHERE root_id=$1 AND id=$2`, original.RootID, accepted.CaptureID).Scan(&revision); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			human := original.RecordingSave.Initiator.VerifiedIdentity
			cancelCheck = value.CancellationCheck{RootID: original.RootID, Request: value.CancellationRequest{CaptureID: accepted.CaptureID, ExpectedRevision: revision, IdempotencyKey: "manual-stored-race-" + custodyID()}, Identity: human, Recovery: recovery, CheckedAt: now, ValidUntil: identity.Earlier(human.ValidUntil, identity.Earlier(recovery.FreshUntil, now.Add(5*time.Second)))}
			work, err := executions.RequestCaptureCancellation(ctx, cancelCheck)
			if err != nil || !work.Decision.Requested || work.Decision.Phase != "Running" || work.Snapshot == nil || work.Snapshot.CaptureID != accepted.CaptureID || work.Snapshot.AttemptID != accepted.Expectation.Registration.Location.AttemptID || work.Snapshot.WriterPodUID != candidate.Process.PodUID || work.Snapshot.WriterEpoch != candidate.Process.ProcessEpoch {
				t.Fatal("durable cancellation before positive SQL storage completion", work, err)
			}
			cancellationLedger, cancelExecution, cancelProcess = executions, candidate, process
		})
		t.Run("positive-stored-completion-wins-cancellation", func(t *testing.T) {
			work, err := cancellationLedger.RequestCaptureCancellation(ctx, cancelCheck)
			if err != nil || work.Decision.Phase != "Finalizing" || work.Snapshot != nil {
				t.Fatal("stored completion was replaced by cancellation", work, err)
			}
			proof := artifact.SourceSnapshotCancellation{CaptureID: accepted.CaptureID, AttemptID: accepted.Expectation.Registration.Location.AttemptID, Request: *accepted.Expectation.Snapshot, AcceptedExpectationDigest: evidence.ContextExpectationDigest(accepted.Expectation), JoinedAt: time.Now().UTC().Truncate(time.Microsecond)}
			cancelled := cancelExecution
			cancelled.Phase = "cancelled"
			cancelled.Copies = artifact.Copies{}
			cancelled.AcquiredAt = time.Time{}
			cancelled.CompletedAt = proof.JoinedAt
			if !proof.Valid() || !cancelled.Valid() {
				t.Fatal("late cancellation fixture is not a valid joined-proof candidate")
			}
			if _, err = cancellationLedger.RecordAPISnapshotCancellation(ctx, cancelled, proof, cancelProcess, cancelCheck.Recovery); err == nil {
				t.Fatal("late joined cancellation overwrote positively stored evidence")
			}
		})
		intent, err := intents.AcknowledgedCaptureIntent(ctx, accepted.CaptureID)
		if err != nil || intent.Actor != policy.Authority.Executor || intent.Initiator == nil || *intent.Initiator != original.RecordingSave.Initiator.Principal {
			t.Fatal("immutable manual initiator and original executor audit", intent, err)
		}
		var raw []byte
		if err = f.admin.QueryRow(ctx, `SELECT intent->'Actor' FROM operation_audit WHERE root_id=$1 AND id=$2`, original.RootID, accepted.CaptureID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var actor identity.Principal
		if json.Unmarshal(raw, &actor) != nil || actor != *intent.Initiator {
			t.Fatal("operation audit actor is not actual manual initiator", actor)
		}
		var anchor, deleteBy time.Time
		if err = f.admin.QueryRow(ctx, `SELECT anchor_at,delete_by FROM context_processing WHERE root_id=$1 AND capture_id=$2`, original.RootID, accepted.CaptureID).Scan(&anchor, &deleteBy); err != nil || !anchor.Equal(accepted.Expectation.Registration.AnchorAt) || !deleteBy.Equal(accepted.Expectation.Registration.DeleteBy) {
			t.Fatal("manual processing lineage changed source age", anchor, deleteBy, err)
		}
	})
	if final := readManualSaveCounters(t, ctx, f, policy); final != after {
		t.Fatal("publication changed policy/shared spend", after, final)
	}
	if policy.GrantID != "" {
		if final := readManualPolicyGrantSpend(t, ctx, f, policy.GrantID); final != spentGrant {
			t.Fatal("completion/publication/cancellation changed original grant spend", spentGrant, final)
		}
	}
	t.Logf("manual existing source: one policy execution, reserved output=%d; no detector occurrence, no observation refill or inherited sharing; policy grant present=%t; identity/target/packet/clock facts synthetic", reserved, grant != "")
}

// Declare adequate fixture backing before initialization; production limits do
// not change. The configured8MiB ceiling is a bound, not measured output.
func configureManualSourceCapacity(f *capacitySQLFixture) {
	unit := (artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes()
	protected := capacity.BudgetAmount{Bytes: 3 * unit, Objects: 12}
	policy := f.template.Policies[0].Budget
	policy.Protected, policy.Hard, policy.Context = protected, protected, protected
	policy.NamespaceMaximum = capacity.BudgetAmount{Bytes: capacityNativeAccounts * protected.Bytes, Objects: capacityNativeAccounts * protected.Objects}
	pool := f.template.Pools[0].Budget
	pool.Slots[0].Protected = protected
	pool.Burst = capacity.BudgetAmount{Bytes: unit, Objects: 4}

}

func TestManualRecordingSaveFixtureFundsActualOutputCeiling(t *testing.T) {
	root, installation, cluster, control, account := custodyID(), custodyID(), custodyID(), custodyID(), "synthetic-account-v1"
	q, template := capacityNativeQualification(t, root, installation, cluster, control, account)
	f := &capacitySQLFixture{qualification: q, template: template}
	configureManualSourceCapacity(f)
	plan, err := capacity.CompileProtectedPoolPlan(f.template, f.template.Pools[0].Budget.Name)
	if err != nil {
		t.Fatal("manual fixture protected pool", err)
	}
	if _, err = capacity.CompileQualifiedRootBacking(q, plan); err != nil {
		t.Fatal("manual fixture backing cannot cover authored8MiB output", err)
	}
	unit := (artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes()
	if f.template.Policies[0].Budget.Protected.Bytes != 3*unit || f.template.Policies[0].Budget.Hard.Bytes != 3*unit || f.template.Policies[0].Budget.Context.Bytes != 3*unit {
		t.Fatal("fixture changed record count or underfunded output")
	}
}

// Real SQL accounting and the real current policy attachment, not a source-row
// grant field or a fabricated occurrence. Review authority is fixture-supplied.
type manualPolicyGrantSpend struct {
	Executions, Bytes, Observed, Revision int64
	PolicyNotAfter                        time.Time
	Ordinary                              bool
	AttachmentGrant                       string
}

func readManualPolicyGrantSpend(t *testing.T, ctx context.Context, f *capacitySQLFixture, grantID string) manualPolicyGrantSpend {
	t.Helper()
	var out manualPolicyGrantSpend
	if grantID == "" {
		t.Fatal("expected a genuine attached grant")
	}
	err := f.admin.QueryRow(ctx, `SELECT g.policy_executions_spent,g.policy_bytes_spent,g.policy_observed_bytes_spent,g.revision,g.policy_not_after,
 COALESCE(g.policy_scope->'Observation'='null'::jsonb,true) AND g.policy_max_observed_bytes=0,
 a.grant_id::text FROM access_grant g JOIN policy_source p ON p.root_id=g.root_id AND p.policy_uid=g.policy_uid
 JOIN policy_grant_attachment a ON a.root_id=p.root_id AND a.id=p.grant_attachment_id AND a.acceptance_id=p.active_id
 WHERE g.id=$1 AND g.decision='approved' AND g.revoked_at IS NULL AND a.grant_id=g.id`, grantID).Scan(&out.Executions, &out.Bytes, &out.Observed, &out.Revision, &out.PolicyNotAfter, &out.Ordinary, &out.AttachmentGrant)
	if err != nil {
		t.Fatal("actual policy grant counters/current attachment", err)
	}
	out.PolicyNotAfter = out.PolicyNotAfter.UTC()
	return out
}
