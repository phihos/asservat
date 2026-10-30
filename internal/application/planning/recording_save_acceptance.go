package planning

import (
	"asservat.local/asservat/internal/domain/artifact"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
	"time"
)

// ReanchorRecordingSave is called only for first successful SQL admission,
// after exact replay lookup. The DB supplies t0; the authored scope stays fixed.
// Authority and grant limits are supplied independently by the locked policy.
func ReanchorRecordingSave(plan value.ContextPlan, registration artifact.Registration, t0, authorityUntil time.Time) (value.ContextPlan, artifact.Registration, error) {
	return reanchorRecordingSave(plan, registration, t0, authorityUntil, nil)
}

// ReanchorRecordingSaveGroup consumes only server-owned ingress bounds and an
// independently verified whole-group plan. Accepted replay never calls it.
func ReanchorRecordingSaveGroup(plan value.ContextPlan, registration artifact.Registration, t0, authorityUntil time.Time, bounds capture.GroupRequestBounds) (value.ContextPlan, artifact.Registration, error) {
	return reanchorRecordingSave(plan, registration, t0, authorityUntil, &bounds)
}

func reanchorRecordingSave(plan value.ContextPlan, registration artifact.Registration, t0, authorityUntil time.Time, bounds *capture.GroupRequestBounds) (value.ContextPlan, artifact.Registration, error) {
	bad := func() (value.ContextPlan, artifact.Registration, error) {
		return value.ContextPlan{}, artifact.Registration{}, value.ErrInvalid
	}
	s := plan.Input.Snapshot
	if s == nil || s.TriggerKind != "recordingSave" || t0.IsZero() || t0.Nanosecond()%1000 != 0 || !t0.Before(authorityUntil) || t0.Before(plan.CompiledAt) {
		return bad()
	}
	startWindow := 5 * time.Second
	if bounds != nil {
		parent, err := ReadContextScopeIdentity(plan.CanonicalScope, plan.ScopeDigest)
		if err != nil || s.Group == nil || !bounds.Valid(t0) || parent.Requester == nil || *parent.Requester != bounds.Requester || len(parent.Targets) < 2 || len(parent.Targets) > capture.MaxRecordingSaveGroupChildren {
			return bad()
		}
		if _, err := ReadRecordingSaveChildScopeIdentity(plan.CanonicalScope, plan.ScopeDigest, *s.Group, plan.Input.CaptureID); err != nil {
			return bad()
		}
		startWindow = identity.RecordingSaveRequestWindow
	}
	timeout, err := RecordingSaveFinalizeTimeout(plan.CanonicalScope, plan.ScopeDigest)
	if err != nil {
		return bad()
	}
	copy := plan
	copy.Input.Snapshot = s.Clone()
	copy.Input.Retention.Policies = append(plan.Input.Retention.Policies[:0:0], plan.Input.Retention.Policies...)
	request := &copy.Input.Snapshot.Request
	request.T0, request.IssuedAt = t0.UTC(), t0.UTC()
	anchor := artifact.SourceSnapshotAnchor(*request)
	retained := &copy.Input.Retention
	retained.AnchorAt = anchor
	retained.ExpiresAt = anchor.Add(time.Duration(min(retained.RequestedSeconds, retained.MaximumSeconds-retained.DeletionBudgetSeconds)) * time.Second)
	retained.DeleteBy = retained.ExpiresAt.Add(time.Duration(retained.DeletionBudgetSeconds) * time.Second)
	request.ProcessingUntil = identity.Earlier(t0.Add(timeout), identity.Earlier(authorityUntil, retained.ExpiresAt)).UTC()
	request.StartBy = identity.Earlier(t0.Add(startWindow), identity.Earlier(request.SourceHardUntil, request.ProcessingUntil.Add(-time.Microsecond))).UTC()
	if bounds != nil {
		request.StartBy = identity.Earlier(request.StartBy, bounds.Until).UTC()
	}
	copy.Input.Deadline = request.ProcessingUntil
	copy.ValidUntil = identity.Earlier(copy.ValidUntil, copy.Input.Deadline)
	registration.AnchorAt, registration.ExpiresAt, registration.DeleteBy = retained.AnchorAt, retained.ExpiresAt, retained.DeleteBy
	registration.WriteUntil = request.ProcessingUntil
	if !request.Valid() || registration.Validate() != nil || !VerifyFrozenContextPlan(copy) {
		return bad()
	}
	return copy, registration, nil
}
