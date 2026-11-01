//go:build cgo && libpcap

package integration

import (
	"asservat.local/asservat/internal/adapters/postgres"
	auditapp "asservat.local/asservat/internal/application/audit"
	captureapp "asservat.local/asservat/internal/application/capture"
	"asservat.local/asservat/internal/application/evidence"
	executionapp "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	executionvalue "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"
)

// Same current SQL/authority preflight as the encrypted completion fixture,
// without creating a node writer, object or packet. Process/target facts remain
// explicitly synthetic component inputs; SQL admission/start/cancellation are real.
func manualCancellationExecution(t *testing.T, ctx context.Context, f *capacitySQLFixture, policy policySourceAcceptedFixture, snapshot policySourceSnapshotAdmissionFixture, intents auditapp.CaptureOperationPublication, start bool) (*postgres.APIContextExecutions, executionapp.APIExecutionCheck, executionvalue.APIExecution) {
	t.Helper()
	s, accepted, admission := policy.Scenario, snapshot.Accepted, snapshot.Admission
	e := accepted.Expectation
	clock := func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
	if e.Snapshot == nil || e.Recording != nil {
		t.Fatal("not an admitted existing-source snapshot")
	}
	if _, err := intents.AcknowledgedCaptureIntent(ctx, accepted.CaptureID); err != nil {
		t.Fatal("audited exact snapshot intent", err)
	}
	guards := postgres.EffectTransactionGuards{Recovery: s.recovery.guard, Retention: s.retention.guard}
	hub := f.roles["hub-runtime"]
	executions, err := postgres.NewAPIContextExecutions(ctx, hub, admission.RootID, guards)
	if err != nil {
		t.Fatal(err)
	}
	current, err := postgres.NewAutomationAuthorities(ctx, hub, admission.RootID, policy.Authority.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	process := executionvalue.APIProcessBinding{InstallationID: policy.Authority.InstallationID, ClusterID: policy.Authority.ClusterID, IssuerEpoch: admission.Recovery.IssuerEpoch, NamespaceUID: custodyID(), AccountUID: custodyID(), PodUID: custodyID(), ProcessEpoch: custodyID(), StartupDigest: artifact.Digest{1}, ImageDigest: e.CollectorImageDigest}
	refresh := func() executionapp.APIExecutionCheck {
		t.Helper()
		f.refreshBase(t)
		now := clock()
		verified := authorization.PolicyExecutorIdentity(policy.Authority, now, now.Add(5*time.Second))
		projection, err := current.PolicyAutomationAuthority(ctx, policy.Authority, admission.Eligibility.Target)
		if err != nil {
			t.Fatal(err)
		}
		eligibility := authorization.PolicyContextEligibility(verified, policy.Authority, projection, admission.Eligibility.Target, clock())
		eligibility.DefaultAudience, err = captureapp.SnapshotAudience(admission.Plan.Input.Snapshot, eligibility.DefaultAudience)
		if err != nil || !eligibility.Eligible {
			t.Fatal("current source snapshot audience", err)
		}
		recovery, err := s.recovery.reader.RecoveryState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		work, err := executions.ReadAPIContextWork(ctx, accepted.CaptureID, verified, recovery)
		if err != nil {
			t.Fatal("retained source API work", err)
		}
		policies, err := s.retention.policies(ctx)
		if err != nil {
			t.Fatal(err)
		}
		input := admission.Plan.Input
		observed := *input.SnapshotSource
		now = clock()
		until := now.Add(5 * time.Second)
		observed.ObservedAt, observed.FreshUntil = now, until
		observed.Process.ObservedAt, observed.Process.FreshUntil = now, until
		observed.ReportedAt, observed.ReportFreshUntil = now, now.Add(15*time.Second)
		observed.State.ObservedAt, observed.State.FreshUntil = observed.ReportedAt, observed.ReportFreshUntil
		input.SnapshotSource = &observed
		input.Capability.ObservedAt, input.Capability.FreshUntil = now, until
		input.Retention, err = privacy.Resolve(policies, privacy.Input{Target: admission.Eligibility.Target, PrivacyClass: "potentialPersonalData", EvidenceType: "packetCapture", RequestedSeconds: e.RequestedAgeSeconds, AnchorAt: e.Registration.AnchorAt}, clock())
		if err != nil {
			t.Fatal(err)
		}
		plan, err := planning.CompileContext(input, clock())
		if err != nil || plan.ScopeDigest != e.PlanDigest {
			t.Fatal("same immutable source plan", err)
		}
		checked := clock()
		until = identity.Earlier(until, identity.Earlier(eligibility.ValidUntil, identity.Earlier(plan.ValidUntil, recovery.FreshUntil)))
		out := executionapp.APIExecutionCheck{Work: work, Plan: plan, Eligibility: eligibility, Recovery: recovery, Process: executionvalue.APIProcessObservation{Binding: process, CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}, CheckedAt: checked, ValidUntil: until}
		if admission.RecordingSave != nil {
			human := admission.RecordingSave.Initiator.VerifiedIdentity
			permissions, err := s.p.Permissions(ctx, admission.Eligibility.Target)
			if err != nil {
				t.Fatal("current manual initiator permission projection", err)
			}
			initiating := authorization.ContextEligibility(human, permissions, admission.Eligibility.Target, clock())
			if !initiating.Eligible {
				t.Fatal("current manual initiator rights", initiating.Reason)
			}
			out.Initiator = &initiating
			out.ValidUntil = identity.Earlier(out.ValidUntil, initiating.ValidUntil)
		}
		if !out.Valid(clock()) {
			t.Fatal("snapshot execution preflight invalid")
		}
		return out
	}
	check := refresh()
	if !start {
		return executions, check, executionvalue.APIExecution{}
	}
	execution, first, err := executions.PrepareAPIExecution(ctx, check)
	if err != nil || !first {
		t.Fatal("prepare original snapshot", first, err)
	}
	replay, again, err := executions.PrepareAPIExecution(ctx, check)
	if err != nil || again || replay != execution {
		t.Fatal("snapshot preparation replay", again, err)
	}
	execution, err = executions.BindAPIStart(ctx, check, execution, executionvalue.PreparedStart{ObjectUID: custodyID(), ResourceVersion: "1"})
	if err != nil {
		t.Fatal(err)
	}
	execution, err = executions.RecordAPIStart(ctx, check, execution, executionvalue.Disposition{ObjectUID: execution.ObjectUID, ResourceVersion: "2", Phase: executionvalue.StartCommitted, CommittedAt: clock(), MayStart: true, ValidUntil: execution.Binding.NotAfter})
	if err != nil {
		t.Fatal(err)
	}
	return executions, check, execution
}

func qualifyManualRecordingSaveCancellation(t *testing.T, ctx context.Context, f *capacitySQLFixture, admissions *postgres.ContextAdmissions, policy policySourceAcceptedFixture, source captureapp.PolicySourceAdmission, fresh captureapp.PolicySourceCheck, intents auditapp.CaptureOperationPublication) {
	t.Helper()
	baseline := readManualSaveCounters(t, ctx, f, policy)
	var originalSource []byte
	if err := f.admin.QueryRow(ctx, `SELECT to_jsonb(s) FROM policy_recording_source s WHERE root_id=$1 AND id=$2`, policy.Scenario.a.RootID, source.Permit.Binding.SourceID).Scan(&originalSource); err != nil {
		t.Fatal(err)
	}
	for _, started := range []bool{false, true} {
		name := "cancel-before-start"
		if started {
			name = "cancel-started-with-exact-join"
		}
		t.Run(name, func(t *testing.T) {
			snapshot := admitManualRecordingSaveFixture(t, ctx, f.roles["hub-runtime"], admissions, policy, source, fresh, min(policy.Compiled.Recorder.Action.MaxBytes, int64(artifact.RecordingNativeLimit)))
			executions, check, record := manualCancellationExecution(t, ctx, f, policy, snapshot, intents, started)
			afterAdmission := readManualSaveCounters(t, ctx, f, policy)
			var revision int64
			if err := f.admin.QueryRow(ctx, `SELECT progress_revision FROM context_capture WHERE root_id=$1 AND id=$2`, snapshot.Admission.RootID, snapshot.Accepted.CaptureID).Scan(&revision); err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			cancel := value.CancellationCheck{RootID: snapshot.Admission.RootID, Identity: snapshot.Admission.RecordingSave.Initiator.VerifiedIdentity, Recovery: check.Recovery, CheckedAt: now, ValidUntil: identity.Earlier(check.ValidUntil, now.Add(5*time.Second)), Request: value.CancellationRequest{CaptureID: snapshot.Accepted.CaptureID, ExpectedRevision: revision, IdempotencyKey: "cancel-original"}}
			work, err := executions.RequestCaptureCancellation(ctx, cancel)
			if err != nil || !work.Decision.Requested || work.Decision.Revision <= revision {
				t.Fatal("durable cancellation request", work.Decision, err)
			}
			replay, err := executions.RequestCaptureCancellation(ctx, cancel)
			if err != nil || replay.Decision.Revision != work.Decision.Revision || replay.Decision.Phase != work.Decision.Phase {
				t.Fatal("cancellation request replay changed original decision", replay.Decision, err)
			}
			if !started {
				if work.Decision.Phase != "Cancelled" || work.Snapshot != nil {
					t.Fatal("no-start fence claimed remote work", work)
				}
				if _, _, err := executions.PrepareAPIExecution(ctx, check); err == nil {
					t.Fatal("cancelled capture prepared after committed fence")
				}
				var count int
				if err := f.admin.QueryRow(ctx, `SELECT count(*) FROM context_execution WHERE root_id=$1 AND capture_id=$2`, cancel.RootID, cancel.Request.CaptureID).Scan(&count); err != nil || count != 0 {
					t.Fatal("no-start cancellation created an execution", count, err)
				}
			} else {
				if work.Decision.Phase != "Running" || work.Snapshot == nil || !work.Snapshot.Request.Equal(*snapshot.Accepted.Expectation.Snapshot) || work.Snapshot.WriterPodUID != record.Process.PodUID || work.Snapshot.WriterEpoch != record.Process.ProcessEpoch {
					t.Fatal("request pretended started writer joined", work)
				}
				ids, err := executions.StartedRecordings(ctx, time.Now().UTC(), 64)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, id := range ids {
					found = found || id == snapshot.Accepted.CaptureID
				}
				if !found {
					t.Fatal("cancellation lost existing collector polling")
				}
				// A cancelled-before-enqueue regional reply cannot remove the only path
				// which can later consume independently joined node/writer completion.
				failed := record
				failed.Phase = "captureFailed"
				failed.CompletedAt = time.Now().UTC().Truncate(time.Microsecond)
				pending, err := executions.RecordAPIOutcome(ctx, failed, check.Process)
				if err != nil || pending.Phase != "started" {
					t.Fatal("start error hid requested cancellation from collector", pending.Phase, err)
				}
				proof := artifact.SourceSnapshotCancellation{CaptureID: snapshot.Accepted.CaptureID, AttemptID: snapshot.Accepted.Expectation.Registration.Location.AttemptID, Request: *snapshot.Accepted.Expectation.Snapshot, AcceptedExpectationDigest: evidence.ContextExpectationDigest(snapshot.Accepted.Expectation), JoinedAt: time.Now().UTC().Truncate(time.Microsecond)}
				cancelled := record
				cancelled.Phase = "cancelled"
				cancelled.CompletedAt = proof.JoinedAt
				wrong := proof
				wrong.AttemptID = custodyID()
				if _, err := executions.RecordAPISnapshotCancellation(ctx, cancelled, wrong, check.Process, check.Recovery); err == nil {
					t.Fatal("foreign attempt cancellation proof accepted")
				}
				if _, err := executions.RecordAPIOutcome(ctx, cancelled, check.Process); err == nil {
					t.Fatal("generic outcome bypassed dedicated joined proof")
				}
				done, err := executions.RecordAPISnapshotCancellation(ctx, cancelled, proof, check.Process, check.Recovery)
				if err != nil || done.Phase != "cancelled" {
					t.Fatal("exact joined proof did not cancel", done.Phase, err)
				}
				again, err := executions.RecordAPISnapshotCancellation(ctx, cancelled, proof, check.Process, check.Recovery)
				if err != nil || !reflect.DeepEqual(again, done) {
					t.Fatal("exact joined proof replay changed execution", err)
				}
				final, err := executions.RequestCaptureCancellation(ctx, cancel)
				if err != nil || final.Decision.Phase != "Cancelled" || final.Snapshot != nil {
					t.Fatal("joined cancellation not projected", final.Decision, err)
				}
			}
			if got := readManualSaveCounters(t, ctx, f, policy); got != afterAdmission {
				t.Fatal("cancellation refunded or repeated policy spend", got, afterAdmission)
			}
		})
	}
	var finalSource []byte
	if err := f.admin.QueryRow(ctx, `SELECT to_jsonb(s) FROM policy_recording_source s WHERE root_id=$1 AND id=$2`, policy.Scenario.a.RootID, source.Permit.Binding.SourceID).Scan(&finalSource); err != nil || !bytes.Equal(originalSource, finalSource) {
		t.Fatal("capture cancellation changed original source lease, credit or lifecycle", err)
	}
	final := readManualSaveCounters(t, ctx, f, policy)
	if final.Executions != baseline.Executions+2 || final.Reservations != baseline.Reservations+2 || final.Observed != baseline.Observed || final.Occurrences != baseline.Occurrences || final.Shares != baseline.Shares {
		t.Fatal("two cancellation saves bypassed shared budget or invented detector/sharing", baseline, final)
	}
}
