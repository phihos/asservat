package capture

import (
	"context"
	"sync"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// policyIdentity is the request-owned identity of one policy-triggered
// capture attempt (ADR-228). Every resolution re-reads the current accepted
// policy, so a revoked, replaced, expired or stale acceptance ends the
// attempt; the original deadline is never extended. It is not a token and
// no public request can construct it.
type policyIdentity struct {
	accepted authapp.AcceptedPolicyReader
	policy   authorization.AcceptedPolicyAuthority
	owner    context.Context
	until    time.Time
	now      func() time.Time
	cache    *policyIdentityCache
}

// policyIdentityCache keeps one current snapshot for at most one second, so
// the many identity checks of one capture attempt do not each repeat the
// acceptance read. A snapshot never outlives its own original bound.
type policyIdentityCache struct {
	mu       sync.Mutex
	read     time.Time
	snapshot authorization.AcceptedPolicySnapshot
}

const policyIdentityReuse = time.Second

var _ identities.CurrentIdentity = policyIdentity{}

func newPolicyIdentity(owner context.Context, accepted authapp.AcceptedPolicyReader, policy authorization.AcceptedPolicyAuthority, until time.Time, now func() time.Time) policyIdentity {
	return policyIdentity{accepted: accepted, policy: policy, owner: owner, until: until, now: now, cache: &policyIdentityCache{}}
}

func (p policyIdentity) ResolveIdentity(ctx context.Context) (identity.Identity, error) {
	if p.accepted == nil || p.now == nil || ctx == nil || ctx.Err() != nil || p.owner.Err() != nil || !p.now().Before(p.until) {
		return identity.Identity{}, value.ErrDenied
	}
	bounded, cancel := context.WithDeadline(ctx, p.until)
	defer cancel()
	stop := context.AfterFunc(p.owner, cancel)
	defer stop()
	p.cache.mu.Lock()
	defer p.cache.mu.Unlock()
	read, snapshot := p.cache.read, p.cache.snapshot
	if read.IsZero() || p.now().Sub(read) >= policyIdentityReuse || !p.now().Before(snapshot.SourceUntil) {
		read = p.now().UTC().Truncate(time.Microsecond)
		var err error
		snapshot, err = p.accepted.AcceptedPolicyAuthority(bounded, p.policy.PolicyUID)
		if err != nil || bounded.Err() != nil {
			p.cache.read = time.Time{}
			return identity.Identity{}, value.ErrDenied
		}
		p.cache.read, p.cache.snapshot = read, snapshot
	}
	a := snapshot.Authority
	if a.Executor != p.policy.Executor || a.ScopeDigest != p.policy.ScopeDigest || a.InstallationID != p.policy.InstallationID {
		return identity.Identity{}, value.ErrDenied
	}
	// Like a human request's token, the identity is bounded by the policy's
	// own validity and the attempt; recovery proofs are checked separately.
	i := authorization.PolicyExecutorIdentity(a, read, identity.Earlier(p.until, snapshot.SourceUntil))
	if !i.Valid(p.now()) {
		return identity.Identity{}, value.ErrDenied
	}
	return i, nil
}
