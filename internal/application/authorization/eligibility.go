// Package authorization coordinates current identity and permission projections.
package authorization

import (
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"time"
)

type ProjectionReader interface {
	Permissions(context.Context, value.Target) (value.Projection, error)
}
type AudienceReader interface {
	RetainedAudience(context.Context, string) (value.Retained, error)
}
type Request struct {
	Operation  value.Operation
	Target     value.Target
	ArtifactID string
}
type Evaluator struct {
	Identities  identities.Resolver
	Permissions ProjectionReader
	Evidence    AudienceReader
	Now         func() time.Time
}

// credentialIdentity preserves existing private bearer callers. Browser and MCP
// ingress use a bounded identity.CurrentIdentity constructed for their request.
type credentialIdentity struct {
	resolver identities.Resolver
	token    string
}

func (i credentialIdentity) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	if i.resolver == nil {
		return identity.Identity{}, identity.ErrUnavailable
	}
	return i.resolver.Resolve(ctx, i.token)
}

// Eligibility does not dispatch, persist an approval or disclose evidence. There
// is no public route until accepted scope, audit and the effect gates are wired.
func (s Evaluator) Eligibility(ctx context.Context, token string, r Request) value.Result {
	return s.EligibilityCurrent(ctx, credentialIdentity{s.Identities, token}, r)
}

// EligibilityCurrent uses the same policy evaluator for authenticated browser
// sessions and bearer requests. The source is a current request-owned port, not
// a caller-provided identity snapshot or a transport-specific policy engine.
func (s Evaluator) EligibilityCurrent(ctx context.Context, current identities.CurrentIdentity, r Request) value.Result {
	deny := func(reason string) value.Result { return value.Result{Reason: reason} }
	if current == nil || s.Permissions == nil || s.Now == nil {
		return deny("AuthorityUnavailable")
	}
	if !r.Operation.Valid() || !r.Target.Valid() || (r.Operation == value.CollectContext && r.ArtifactID != "") || (r.Operation != value.CollectContext && !value.UUID(r.ArtifactID)) {
		return deny("InvalidRequest")
	}
	if ctx.Err() != nil {
		return deny("AuthorityUnavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.Now()) {
		return deny("IdentityUnavailable")
	}
	p, err := s.Permissions.Permissions(ctx, r.Target)
	if err != nil {
		return deny("PermissionUnavailable")
	}
	if preliminary := value.ScopeEligibility(i, p, r.Operation, r.Target, s.Now()); !preliminary.Eligible {
		return preliminary
	}
	var retained *value.Retained
	if r.Operation != value.CollectContext {
		if s.Evidence == nil {
			return deny("EvidenceUnavailable")
		}
		e, err := s.Evidence.RetainedAudience(ctx, r.ArtifactID)
		if err != nil || e.ArtifactID != r.ArtifactID {
			return deny("EvidenceUnavailable")
		}
		retained = &e
	}
	fresh, err := current.ResolveIdentity(ctx)
	if err != nil || fresh.Principal != i.Principal || fresh.Policy != i.Policy || ctx.Err() != nil {
		return deny("AuthorityUnavailable")
	}
	fresh.ValidUntil = identity.Earlier(fresh.ValidUntil, i.ValidUntil)
	return value.Evaluate(fresh, p, r.Operation, r.Target, retained, s.Now())
}
