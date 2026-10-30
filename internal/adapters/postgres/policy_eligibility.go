package postgres

import (
	"context"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// contextEligibilityIn re-evaluates context-collection eligibility after the
// caller's recovery and permission-root locks. A human is evaluated against
// the locked projection exactly as before. An accepted policy's executor
// (ADR-228) is evaluated through its current acknowledged acceptance and
// current team delegation instead: it has no scopes or groups of its own.
func contextEligibilityIn(ctx context.Context, q *custodydb.Queries, stream custodydb.PermissionStream, trust custodydb.FleetCurrentTrust, root, installation string, i identity.Identity, p authorization.Projection, target authorization.Target, now time.Time) authorization.CaptureEligibility {
	return contextEligibilityInWithPermissions(ctx, q, stream, trust, root, installation, i, p, target, now, nil)
}

func contextEligibilityInWithPermissions(ctx context.Context, q *custodydb.Queries, stream custodydb.PermissionStream, trust custodydb.FleetCurrentTrust, root, installation string, i identity.Identity, p authorization.Projection, target authorization.Target, now time.Time, facts *recordingGroupFacts) authorization.CaptureEligibility {
	inst, policy, ok := authorization.PolicyExecutor(i.Principal)
	if !ok {
		return authorization.ContextEligibility(i, p, target, now)
	}
	deny := authorization.CaptureEligibility{Result: authorization.Result{Reason: "AutomationUnavailable"}}
	if inst != installation {
		return deny
	}
	var snapshot authorization.AcceptedPolicySnapshot
	var err error
	if facts != nil {
		snapshot, err = facts.acceptedPolicy(ctx, q, stream, trust, root, installation, policy, target, now)
	} else {
		row, readErr := q.ReadPolicySourceRow(ctx, custodydb.ReadPolicySourceRowParams{RootID: id(root), PolicyUid: policy})
		if readErr != nil {
			return deny
		}
		snapshot, _, err = acceptedPolicyIn(ctx, q, root, installation, trust, row)
	}
	if err != nil {
		return deny
	}
	var current authorization.AutomationProjection
	if facts != nil {
		current, err = facts.automation(ctx, q, stream, installation, snapshot.Authority, target, p)
	} else {
		current, err = automationProjection(ctx, q, stream, installation, snapshot.Authority, target)
	}
	if err != nil {
		return deny
	}
	n, err := q.CurrentTime(ctx)
	if err != nil {
		return deny
	}
	out := authorization.PolicyContextEligibility(i, snapshot.Authority, current, target, n.Time)
	if out.Eligible {
		out.ValidUntil = identity.Earlier(out.ValidUntil, snapshot.SourceUntil)
		if !n.Time.Before(out.ValidUntil) {
			return deny
		}
	}
	return out
}
