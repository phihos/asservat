package capture

import (
	"context"
	"errors"
	"slices"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// RecorderGrants is the C-03 approval service (ADR-249) as the capture
// request path uses it: open one review request for a current sensitive
// plan, and check at every submission that an approved grant covers it.
type RecorderGrants interface {
	Request(context.Context, identities.CurrentIdentity, authapp.GrantRequestInput) (authorization.Grant, bool, error)
	Covering(context.Context, identities.CurrentIdentity, string, artifact.Digest, authorization.Target) (authorization.Grant, time.Time, error)
}

// ApprovalSettings reads the protected installation approval settings.
type ApprovalSettings interface {
	IdentityPolicy(context.Context, string) (identity.Policy, error)
}

// requireRecordingApproval reads the installation's REQ-SYS-002 switch for
// the caller's issuer. Without a configured reader the installation adds no
// requirement; a failing reader refuses the preview.
func (s ContextInvestigation) requireRecordingApproval(ctx context.Context, current identities.CurrentIdentity, actor identity.Principal) (bool, error) {
	issuer := actor.Issuer
	_, _, policy := authorization.PolicyExecutor(actor)
	if policy {
		// Only the package-private request-owned policy identity supplies accepted
		// issuer provenance. A token or policy-shaped principal cannot select it.
		accepted, ok := current.(interface {
			acceptedSettingsIssuer(context.Context) (string, error)
		})
		if !ok {
			return false, value.ErrUnavailable
		}
		var err error
		issuer, err = accepted.acceptedSettingsIssuer(ctx)
		if err != nil {
			return false, value.ErrUnavailable
		}
	}
	if s.Approvals == nil {
		if policy {
			return false, value.ErrUnavailable
		}
		return false, nil
	}
	p, err := s.Approvals.IdentityPolicy(ctx, issuer)
	if err != nil || p.Issuer != issuer || p.Validate(s.Now()) != nil {
		return false, value.ErrUnavailable
	}
	return p.RequireRecordingApproval, nil
}

// RequestWithResultAccess submits a reviewed packet/syscall preview with an
// optional same-human result-access instruction (REQ-INV-001). A pod-status
// preview needs no review and refuses the instruction.
func (s ContextInvestigation) RequestWithResultAccess(ctx context.Context, source identities.CurrentIdentity, previewID, key string, access *authorization.ResultAccess) (value.Accepted, error) {
	var zero value.Accepted
	if access == nil {
		return s.Request(ctx, source, previewID, key)
	}
	if !s.configured() || ctx == nil || source == nil || ctx.Err() != nil {
		return zero, value.ErrUnavailable
	}
	if !authorization.UUID(previewID) || !identity.Text(key, 128) {
		return zero, value.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := source.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return zero, value.ErrDenied
	}
	p, err := s.Previews.ReadContextPreview(ctx, s.RootID, previewID, i.Principal)
	if err != nil {
		return zero, err
	}
	p = p.Clone()
	if !ValidContextPreview(p) || p.ID != previewID || p.RootID != s.RootID || p.InstallationID != s.InstallationID || p.Actor != i.Principal {
		return zero, value.ErrDenied
	}
	if p.Intent.Composition == nil {
		return zero, value.ErrInvalid
	}
	if _, err := s.recorderRequest(ctx, source, p, key, access); err != nil {
		return zero, err
	}
	// ADR-248: the node recorder does not deliver results under a result-access
	// instruction yet.
	return zero, value.ErrRecorderUnavailable
}

// recorderRequest decides the approval gate of a reviewed packet/syscall
// submission (ADR-249). A plan without an approval requirement passes (nil).
// A plan that needs approval opens exactly one review request for its capture
// identity while the preview is current, and is refused with
// ApprovalRequired until an approved, current grant covers this exact plan
// for the requesting human; only then does it pass to the recorder check
// (ADR-248). A plan with REQ-AUT-006 observation limits (a raw byte
// predicate) stays RecorderUnavailable: the node recorder does not charge
// observation spend. Nothing is armed, reserved or charged here.
func (s ContextInvestigation) recorderRequest(ctx context.Context, source identities.CurrentIdentity, p value.ContextPreview, key string, access *authorization.ResultAccess) (authorization.Grant, error) {
	actions, approval, err := compiler.RecorderScopeSummary(p.CanonicalScope)
	if err != nil {
		return authorization.Grant{}, value.ErrUnavailable
	}
	required, err := s.requireRecordingApproval(ctx, source, p.Actor)
	if err != nil {
		return authorization.Grant{}, err
	}
	frozen := approval != nil && slices.ContainsFunc(approval.Reasons, func(r authorization.SensitiveReason) bool { return r.Code == "recordingApprovalRequired" })
	if required != frozen {
		return authorization.Grant{}, s.requestChanged("approval/settings")
	}
	if _, _, policy := authorization.PolicyExecutor(p.Actor); policy {
		if access != nil {
			return authorization.Grant{}, value.ErrInvalid
		}
		if approval != nil && approval.ObservationLimits != nil {
			return authorization.Grant{}, value.ErrRecorderUnavailable
		}
		// Team grant scope is the accepted policy, not this per-Pod manual preview.
		// The existing admission transaction locks and spends its actual attachment;
		// no human ad hoc request, grant timing refresh or new debit happens here.
		return authorization.Grant{}, nil
	}
	if approval == nil {
		if access != nil {
			return authorization.Grant{}, value.ErrInvalid
		}
		return authorization.Grant{}, nil
	}
	if s.Grants == nil {
		return authorization.Grant{}, authorization.ErrApprovalRequired
	}
	t := authorization.Target{ClusterID: p.Target.ClusterID, NamespaceUID: p.Target.Namespace.UID, WorkloadUID: p.Target.Workload.UID, PodUID: p.Target.PodUID}
	var wanted artifact.Digest
	if access != nil {
		wanted = authapp.ResultAccessDigest(p.CaptureID, p.ScopeDigest, authapp.NormalizeResultAccess(*access))
	}
	g, _, err := s.Grants.Covering(ctx, source, p.CaptureID, p.ScopeDigest, t)
	switch {
	case err == nil || errors.Is(err, authorization.ErrApprovalRequired) && g.ID != "":
		// An existing request binds its result access; another instruction
		// needs a fresh preview and review, never a silent replacement.
		if access != nil && g.ResultAccessDigest != wanted {
			return authorization.Grant{}, value.ErrConflict
		}
		if err != nil {
			return authorization.Grant{}, authorization.ApprovalPendingError{GrantID: g.ID}
		}
		if approval.ObservationLimits != nil {
			return authorization.Grant{}, value.ErrRecorderUnavailable
		}
		return g, nil
	case errors.Is(err, authorization.ErrApprovalRequired):
		// No request exists yet: only a current preview can open one.
	default:
		return authorization.Grant{}, err
	}
	if !p.Current(s.Now()) {
		return authorization.Grant{}, value.ErrPreviewExpired
	}
	review := authapp.GrantReview{Namespace: p.Target.Namespace.Name, WorkloadKind: p.Target.Workload.Kind, WorkloadName: p.Target.Workload.Name, PodName: p.Target.PodName, Deadline: p.Deadline}
	for _, a := range actions {
		review.Actions = append(review.Actions, authapp.GrantReviewAction{ActionID: a.ID, Kind: a.Kind, ExecutionMode: a.ExecutionMode, Before: a.Before, After: a.After, Filter: a.Filter, RingMaxAge: a.RingMaxAge,
			FilterDigest: a.FilterDigest, FilterInstructions: a.FilterInstructions, MaxBytes: a.MaxBytes, RingMaxBytes: a.RingMaxBytes, Sensitive: a.Sensitive})
	}
	if l := approval.ObservationLimits; l != nil {
		review.ObservationLimits = &authapp.GrantObservationLimits{MaxSessionSeconds: l.MaxSessionSeconds, MaxObservedBytes: l.MaxObservedBytes, MaxBytesPerSecond: l.MaxBytesPerSecond, MaxConcurrentSessions: l.MaxConcurrentSessions}
	}
	created, _, err := s.Grants.Request(ctx, source, authapp.GrantRequestInput{PreviewID: p.ID, CaptureID: p.CaptureID, Actor: p.Actor, Target: t, Scope: p.CanonicalScope, ExecutionDigest: p.ScopeDigest,
		DataClass: approval.DataClass, Reasons: approval.Reasons, Review: review, Lifetime: authorization.GrantDefaultLifetime, ResultAccess: access, IdempotencyKey: key})
	if err != nil {
		return authorization.Grant{}, err
	}
	return authorization.Grant{}, authorization.ApprovalPendingError{GrantID: created.ID}
}
