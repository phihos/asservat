package postgres

import (
	"context"
	"errors"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/jackc/pgx/v5/pgtype"
)

// policyCaptureReservation exists only inside the original admission transaction.
// Its occurrence already spent one accepted execution at Tick; this transaction
// reserves output and optional grant spend, never that execution a second time.
type policyCaptureReservation struct {
	manual          *manualPolicyReservation
	processingLimit time.Time
	occurrence      custodydb.PolicyOccurrence
	grant           pgtype.UUID
	bytes           int64
	until           time.Time
}

func lockPolicyCaptureReservation(ctx context.Context, q *custodydb.Queries, trust custodydb.FleetCurrentTrust, a value.Admission, installation string) (*policyCaptureReservation, error) {
	inst, policy, isPolicy := authorization.PolicyExecutor(a.Plan.Input.Executor)
	if !isPolicy {
		return nil, nil
	}
	if inst != installation || a.RecordingSave == nil && !authorization.UUID(a.IdempotencyKey) {
		return nil, value.ErrDenied
	}
	source, err := q.LockPolicySource(ctx, custodydb.LockPolicySourceParams{RootID: id(a.RootID), PolicyUid: policy})
	if err != nil {
		return nil, err
	}
	snapshot, record, err := acceptedPolicyIn(ctx, q, a.RootID, installation, trust, source)
	if err != nil {
		return nil, err
	}
	target := a.Plan.Input.Target.Target()
	var occurrence custodydb.PolicyOccurrence
	var manual *manualPolicyReservation
	if a.RecordingSave != nil {
		manual, err = lockManualPolicySave(ctx, q, source, record, a)
		if err != nil {
			return nil, err
		}
	} else {
		occurrence, err = q.LockPolicyCaptureOccurrence(ctx, custodydb.LockPolicyCaptureOccurrenceParams{RootID: id(a.RootID), ID: id(a.IdempotencyKey)})
		if err != nil {
			return nil, err
		}
		if occurrence.PolicyUid != policy || occurrence.AcceptanceID != id(record.ID) || occurrence.ClusterID != id(target.ClusterID) || occurrence.WorkloadUid != target.WorkloadUID || occurrence.PodUid != target.PodUID || occurrence.Outcome.Valid || occurrence.ReservedCaptureID.Valid {
			return nil, value.ErrConflict
		}
	}
	// Generic preflight eligibility does not authorize a different action.
	// Bind the actual immutable plan before reserving either pool.
	action := authorization.PolicyContextAction
	if a.Plan.Input.Recorder != nil || a.Plan.Input.Snapshot != nil {
		action = "packetCapture"
	}
	if !slices.Contains(record.Authority.Actions, action) {
		return nil, value.ErrDenied
	}
	output := int64(artifact.MaxContextBytes)
	required, raw := false, false
	if a.Plan.Input.Recorder != nil {
		recording, _, err := planning.RecordingForContext(a.Plan)
		if err != nil {
			return nil, value.ErrInvalid
		}
		output, required = recording.MaxBytes, policyRecordingNeedsGrant(&recording)
		raw = recording.Filter != nil && planning.RawBytePredicate(recording.Filter.Expression)
	}
	if saved := a.Plan.Input.Snapshot; saved != nil {
		if saved.PolicyUID != policy || saved.ExecutionDigest != record.Authority.ScopeDigest || (manual == nil && (saved.TriggerKind != "policy" || !saved.Request.T0.Equal(occurrence.CreatedAt.Time))) || (manual != nil && saved.TriggerKind != "recordingSave") {
			return nil, value.ErrChanged
		}
		output, required = saved.Request.MaxBytes, saved.Request.RequireApproval
		if manual != nil {
			raw = planning.RawBytePredicate(a.RecordingSave.Policy.Recorder.Action.Filter)
			required = required || raw
		}
	}
	r := &policyCaptureReservation{occurrence: occurrence, manual: manual, processingLimit: record.Authority.NotAfter, bytes: output, until: snapshot.FreshUntil}
	if source.GrantAttachmentID.Valid {
		row, err := q.ReadPolicyGrantAttachment(ctx, custodydb.ReadPolicyGrantAttachmentParams{RootID: id(a.RootID), ID: source.GrantAttachmentID})
		if err != nil {
			return nil, err
		}
		attachment, err := policyGrantAttachmentFromRow(row)
		if err != nil || !attachment.Matches(a.RootID, record.ID, record.Authority, source.AuthoredGrantRef) {
			return nil, value.ErrDenied
		}
		gr, err := q.ReadGrantForUpdate(ctx, custodydb.ReadGrantForUpdateParams{RootID: id(a.RootID), ID: id(attachment.GrantID)})
		if err != nil {
			return nil, err
		}
		grant, err := grantFromRow(gr)
		if err != nil {
			return nil, err
		}
		now, err := q.CurrentTime(ctx)
		if err != nil {
			return nil, err
		}
		if err := authorization.CheckPolicyCapture(grant, record.Authority, target, output, now.Time); err != nil {
			if errors.Is(err, authorization.ErrPolicyGrantBudgetExhausted) {
				return nil, value.ErrCapacity
			}
			return nil, value.ErrDenied
		}
		if raw && (grant.Policy.Observation == nil || grant.Policy.Limits.MaxObservedBytes < 1) {
			return nil, value.ErrDenied
		}
		if grant.Policy.RecipeDigest != a.Plan.RecipeDigest || a.Plan.Input.Deadline.After(grant.PolicyNotAfter) {
			return nil, value.ErrDenied
		}
		r.grant = gr.ID
		r.processingLimit = identity.Earlier(r.processingLimit, grant.PolicyNotAfter)
		r.until = identity.Earlier(r.until, grant.PolicyNotAfter)
	} else if required || source.AuthoredGrantRef != "" {
		return nil, value.ErrDenied
	}
	if a.Plan.Input.Deadline.After(record.Authority.NotAfter) {
		return nil, value.ErrDenied
	}
	// Source freshness bounds this transaction, not the accepted capture lifetime.
	// The grant and accepted authority independently cap that original lifetime.
	return r, nil
}

func (r *policyCaptureReservation) spend(ctx context.Context, q *custodydb.Queries, root, capture string, a value.Admission) error {
	if r == nil {
		return nil
	}
	acceptanceID := r.occurrence.AcceptanceID
	if r.manual != nil {
		acceptanceID = r.manual.acceptanceID
	}
	n, err := q.SpendPolicyCollectedBytes(ctx, custodydb.SpendPolicyCollectedBytesParams{RootID: id(root), ID: acceptanceID, Bytes: r.bytes})
	if err != nil {
		return err
	}
	if n != 1 {
		return value.ErrCapacity
	}
	if r.grant.Valid {
		n, err = q.SpendPolicyGrantCapture(ctx, custodydb.SpendPolicyGrantCaptureParams{RootID: id(root), ID: r.grant, Bytes: r.bytes})
		if err != nil {
			return err
		}
		if n != 1 {
			return value.ErrCapacity
		}
	}
	if r.manual != nil {
		return r.manual.spend(ctx, q, root, capture, a, r.grant, r.bytes)
	}
	n, err = q.ReservePolicyOccurrenceOutput(ctx, custodydb.ReservePolicyOccurrenceOutputParams{RootID: id(root), ID: r.occurrence.ID, ReservedCaptureID: id(capture), GrantID: r.grant, ReservedBytes: r.bytes})
	if err != nil {
		return err
	}
	if n != 1 {
		return value.ErrConflict
	}
	return ctx.Err()
}

// Later effect checks keep the original charged grant, even after the policy
// points at a replacement grant. Current policy/delegation eligibility remains
// the caller's separate check; this cannot issue an execution permit.
type policyGrantReservation struct {
	PolicyUid             string
	AcceptanceID, GrantID pgtype.UUID
}

type policyCaptureGrantState struct {
	reservation policyGrantReservation
	grant       authorization.Grant
}

func currentPolicyCaptureGrant(ctx context.Context, q *custodydb.Queries, row custodydb.ContextCapture, accepted value.Accepted) error {
	_, err := lockCurrentPolicyCaptureGrant(ctx, q, row, accepted)
	return err
}

func lockCurrentPolicyCaptureGrant(ctx context.Context, q *custodydb.Queries, row custodydb.ContextCapture, accepted value.Accepted) (*policyCaptureGrantState, error) {
	var reservation policyGrantReservation
	if saved := accepted.Expectation.Snapshot; saved != nil && accepted.Expectation.Lifecycle != nil && accepted.Expectation.Lifecycle.TriggerKind == "recordingSave" {
		manual, err := q.ReadRecordingSaveReservation(ctx, custodydb.ReadRecordingSaveReservationParams{RootID: row.RootID, CaptureID: row.ID})
		if err != nil || manual.ReservedBytes != accepted.Expectation.Registration.NativeLimit || !manual.AcceptedAt.Time.Equal(accepted.CreatedAt) || !manual.ProcessingUntil.Time.Equal(accepted.Deadline) {
			return nil, value.ErrDenied
		}
		reservation = policyGrantReservation{PolicyUid: manual.PolicyUid, AcceptanceID: manual.AcceptanceID, GrantID: manual.GrantID}
	} else {
		occurrence, err := q.ReadPolicyCaptureReservation(ctx, custodydb.ReadPolicyCaptureReservationParams{RootID: row.RootID, ReservedCaptureID: row.ID})
		if err != nil {
			return nil, value.ErrDenied
		}
		reservation = policyGrantReservation{PolicyUid: occurrence.PolicyUid, AcceptanceID: occurrence.AcceptanceID, GrantID: occurrence.GrantID}
	}
	source, err := q.ReadPolicySourceRow(ctx, custodydb.ReadPolicySourceRowParams{RootID: row.RootID, PolicyUid: reservation.PolicyUid})
	if err != nil {
		return nil, err
	}
	now, err := q.CurrentTime(ctx)
	if err != nil {
		return nil, err
	}
	if source.ActiveID != reservation.AcceptanceID || source.Deleted || source.Suspended || !policySource(source).Valid(now.Time) {
		return nil, value.ErrDenied
	}
	if !reservation.GrantID.Valid {
		if policyRecordingNeedsGrant(accepted.Expectation.Recording) || accepted.Expectation.Snapshot != nil && accepted.Expectation.Snapshot.RequireApproval {
			return nil, value.ErrDenied
		}
		return nil, ctx.Err()
	}
	gr, err := q.ReadGrantForUpdate(ctx, custodydb.ReadGrantForUpdateParams{RootID: row.RootID, ID: reservation.GrantID})
	if err != nil {
		return nil, err
	}
	grant, err := grantFromRow(gr)
	if err != nil {
		return nil, err
	}
	now, err = q.CurrentTime(ctx)
	if err != nil {
		return nil, err
	}
	if grant.Policy == nil || gr.PolicyAcceptanceID != reservation.AcceptanceID ||
		grant.Policy.RecipeDigest != accepted.Expectation.RecipeDigest ||
		authorization.CheckPolicyGrantCurrent(grant, grant.Policy.Authority, grant.Policy.Workload(), now.Time) != nil ||
		accepted.Deadline.After(grant.PolicyNotAfter) {
		return nil, value.ErrDenied
	}
	return &policyCaptureGrantState{reservation: reservation, grant: grant}, ctx.Err()
}

// Raw sensitivity is separate from Recording.RequireApproval's immutable
// protected require-all setting. Do not rewrite that setting on replay.
func policyRecordingNeedsGrant(r *artifact.Recording) bool {
	return r != nil && (r.RequireApproval || r.Filter != nil && planning.RawBytePredicate(r.Filter.Expression))
}
