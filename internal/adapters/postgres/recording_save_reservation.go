package postgres

import (
	"context"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/capture"
	compiler "asservat.local/asservat/internal/application/planning"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"github.com/jackc/pgx/v5/pgtype"
)

func manualAdmissionShape(a value.Admission) bool {
	s := a.Plan.Input.Snapshot
	manual := s != nil && s.TriggerKind == "recordingSave"
	if !manual {
		return a.RecordingSave == nil
	}
	if a.RecordingSave == nil {
		return false
	}
	i := a.RecordingSave.Initiator
	scope, err := compiler.ReadContextScopeIdentity(a.Plan.CanonicalScope, a.Plan.ScopeDigest)
	return err == nil && scope.Requester != nil && *scope.Requester == i.Principal && scope.Actor == a.Plan.Input.Executor && i.Eligible && i.Target == a.Plan.Input.Target.Target() && i.VerifiedIdentity.Principal == i.Principal && i.IdentityRevision == i.VerifiedIdentity.Policy && slices.Contains(i.VerifiedIdentity.Scopes, "evidence:capture")
}

type manualPolicyReservation struct {
	policyUID                  string
	acceptanceID               pgtype.UUID
	acceptedAt, authorityUntil time.Time
	shared, own                time.Time
	interval                   time.Duration
}

// lockManualPolicySave validates the reviewed opt-in with the same pure scope
// compiler used at activation. It acquires the existing shared/own GCRA cells,
// without changing detector watermarks or inventing an occurrence.
func lockManualPolicySave(ctx context.Context, q *custodydb.Queries, source custodydb.PolicySource, record value.PolicyAcceptance, a value.Admission) (*manualPolicyReservation, error) {
	in := a.RecordingSave
	saved := a.Plan.Input.Snapshot
	if in == nil || saved == nil || saved.TriggerKind != "recordingSave" || !in.Policy.Valid() || !in.Policy.RecordingSaves || in.Policy.Recorder == nil || in.Policy.Recorder.Action.ExecutionMode != "ongoing" || !in.Initiator.Eligible || in.Initiator.Principal != a.Requester() || in.Initiator.Target != a.Plan.Input.Target.Target() {
		return nil, value.ErrDenied
	}
	p, authority := in.Policy, record.Authority
	if app.RecorderPolicyScopeDigest(source.PolicyUid, record.IntentVersion, policySource(source).CollectionDigest, p, authority.NamespaceUID, authority.WorkloadUID, authority.Delegation, authority.Owners, authority.Actions, authority.Limits) != authority.ScopeDigest {
		return nil, value.ErrChanged
	}
	// The exact protected record, not a caller-selected policy, fixes execution.
	if in.Authority.Executor != authority.Executor || in.Authority.ScopeDigest != authority.ScopeDigest || saved.ExecutionDigest != authority.ScopeDigest || saved.PolicyUID != authority.PolicyUID || saved.ActionID != p.Recorder.Action.ID || saved.Request.After != 0 || saved.Request.MaxBytes > p.Recorder.Action.MaxBytes {
		return nil, value.ErrDenied
	}
	if !manualPolicySaveFinalizeCurrent(p, a.Plan) {
		return nil, value.ErrDenied
	}
	before, e := time.ParseDuration(p.Recorder.Action.Before)
	if e != nil || saved.Request.Before <= 0 || saved.Request.Before > before {
		return nil, value.ErrDenied
	}
	scope, e := compiler.ReadContextScopeIdentity(a.Plan.CanonicalScope, a.Plan.ScopeDigest)
	if e != nil || scope.Requester == nil || *scope.Requester != in.Initiator.Principal || scope.Actor != authority.Executor {
		return nil, value.ErrDenied
	}
	now, e := q.CurrentTime(ctx)
	if e != nil {
		return nil, e
	}
	if !in.Initiator.VerifiedIdentity.Valid(now.Time) || !now.Time.Before(in.Initiator.ValidUntil) {
		return nil, value.ErrDenied
	}
	r := &manualPolicyReservation{policyUID: authority.PolicyUID, acceptanceID: id(record.ID), acceptedAt: now.Time.UTC(), authorityUntil: authority.NotAfter, interval: p.Interval}
	for _, cell := range []struct {
		policy   string
		at       *time.Time
		interval time.Duration
		burst    int
	}{{"", &r.shared, value.WorkloadTriggerInterval, value.WorkloadTriggerBurst}, {authority.PolicyUID, &r.own, p.Interval, p.Burst}} {
		stored, e := q.LockPolicyWindow(ctx, custodydb.LockPolicyWindowParams{RootID: id(a.RootID), ClusterID: id(authority.ClusterID), WorkloadUid: authority.WorkloadUID, PolicyUid: cell.policy, Tat: now})
		if e != nil {
			return nil, e
		}
		*cell.at = stored.Time
		if !admits(stored.Time, now.Time, cell.interval, cell.burst) {
			return nil, value.ErrCapacity
		}
	}
	return r, nil
}

func (r *manualPolicyReservation) spend(ctx context.Context, q *custodydb.Queries, root, capture string, a value.Admission, grant pgtype.UUID, bytes int64) error {
	n, err := q.SpendPolicyExecution(ctx, custodydb.SpendPolicyExecutionParams{RootID: id(root), ID: r.acceptanceID})
	if err != nil {
		return err
	}
	if n != 1 {
		return value.ErrCapacity
	}
	for _, cell := range []struct {
		policy   string
		at       time.Time
		interval time.Duration
	}{{"", r.shared, value.WorkloadTriggerInterval}, {r.policyUID, r.own, r.interval}} {
		if err = q.UpdatePolicyWindow(ctx, custodydb.UpdatePolicyWindowParams{RootID: id(root), ClusterID: id(a.Plan.Input.Target.Request.ClusterID), WorkloadUid: a.Plan.Input.Target.Request.Workload.UID, PolicyUid: cell.policy, Tat: ts(later(cell.at, r.acceptedAt).Add(cell.interval))}); err != nil {
			return err
		}
	}
	return q.InsertRecordingSaveReservation(ctx, custodydb.InsertRecordingSaveReservationParams{CaptureID: id(capture), RootID: id(root), PolicyUid: r.policyUID, AcceptanceID: r.acceptanceID, GrantID: grant, ReservedBytes: bytes, AcceptedAt: ts(r.acceptedAt), ProcessingUntil: ts(a.Plan.Input.Deadline)})
}

// The canonical reviewed timeout is bounded again against the independently
// locked policy definition, before admission clocks or charge effects.
func manualPolicySaveFinalizeCurrent(p value.RestartPolicy, plan planning.ContextPlan) bool {
	if p.Recorder == nil {
		return false
	}
	timeout, err := compiler.RecordingSaveFinalizeTimeout(plan.CanonicalScope, plan.ScopeDigest)
	action, actionErr := time.ParseDuration(p.Recorder.Action.Timeout)
	recipe, recipeErr := time.ParseDuration(p.Recorder.Composition.MaxDuration)
	return err == nil && actionErr == nil && recipeErr == nil && timeout > 0 && timeout <= min(action, recipe)
}
