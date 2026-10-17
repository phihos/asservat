package kubernetes

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// Consumer-owned fixed-purpose port. Only the acknowledged private claim in
// PrepareProvider can authorize Issue; Check/Verify are observations, not effects.
type InitialProviderIssuer interface {
	Check(context.Context, time.Time) (contracts.InitialProviderParent, time.Time, error)
	Issue(context.Context, string, contracts.InitialProviderIssue, contracts.InitialProviderParent) (contracts.InitialProviderResponse, error)
	Verify(context.Context, string, contracts.InitialProviderIssue, contracts.InitialProviderParent, contracts.InitialProviderResponse) error
}

func (s *InitialPreparer) providerResponse(id string) (contracts.InitialProviderResponse, bool) {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	v, ok := s.providerResponses[id]
	return v, ok
}
func (s *InitialPreparer) keepProviderResponse(id string, v contracts.InitialProviderResponse) {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	if !s.requestClosed {
		if s.providerResponses == nil {
			s.providerResponses = map[string]contracts.InitialProviderResponse{}
		}
		if len(s.providerResponses) < 2 {
			s.providerResponses[id] = v
		}
	}
}
func sameProviderParent(a, b contracts.InitialProviderParent) bool {
	return a.Accessor == b.Accessor && a.IssuedAt.Equal(b.IssuedAt) && a.ExpiresAt.Equal(b.ExpiresAt)
}

// Account for both maximum positive replies and the final projection receipt
// before any provider POST; private progress cannot overflow after issuance.
func (s *InitialPreparer) providerStateFits(v contracts.InitialPreparationPrivateState) bool {
	raw, e := json.Marshal(v)
	if e != nil {
		return false
	}
	defer clear(raw)
	var full contracts.InitialPreparationPrivateState
	if json.Unmarshal(raw, &full) != nil || full.Providers == nil {
		return false
	}
	for n := 0; n < 2; n++ {
		i := &contracts.InitialProviderIssue{ID: "ffffffff-ffff-4fff-8fff-ffffffffffff", StartedAt: time.Date(9999, 1, 1, 0, 0, 0, 999999000, time.UTC), Until: time.Date(9999, 1, 1, 0, 0, 5, 999999000, time.UTC), ExpiresBefore: time.Date(9999, 1, 1, 0, 15, 0, 999999999, time.UTC), Response: &contracts.InitialProviderResponse{Token: strings.Repeat("x", contracts.InitialProviderTokenMaxBytes), Accessor: strings.Repeat("x", 128), IssuedAt: time.Date(9999, 1, 1, 0, 0, 1, 999999999, time.UTC), ExpiresAt: time.Date(9999, 1, 1, 0, 15, 0, 999999999, time.UTC)}}
		if n == 0 {
			full.Providers.Wrap = i
		} else {
			full.Providers.Unwrap = i
		}
	}
	full.Providers.Projection = &contracts.InitialPreparationSQLState{OperationID: "ffffffff-ffff-4fff-8fff-ffffffffffff", Secret: &contracts.WorkerObjectReference{Name: s.plan.Workload.Credentials, UID: "ffffffff-ffff-4fff-8fff-ffffffffffff"}}
	raw, e = json.Marshal(full)
	defer clear(raw)
	return e == nil && len(raw) <= contracts.InitialPreparationPrivateMaxBytes
}

// PrepareProvider freezes an exact original parent identity, then spends one
// issue claim. Unknown claim/POST replies never issue again. A positive response
// retained by this joined process may finish persistence after a lost CAS reply;
// another process needs the already persisted original response.
func (b *InitialPreparationCredentialBinder) PrepareProvider(ctx context.Context, purpose string, issuer InitialProviderIssuer) (_ contracts.InitialProviderResponse, _ time.Time, err error) {
	phase := "inputs"
	started := time.Now()
	var parentUntil, activeUntil time.Time
	if ctx != nil {
		parentUntil, _ = ctx.Deadline()
	}
	defer func() {
		if err != nil {
			err = initialPreparationProviderFailure{phase: phase, cause: err, started: started, parentUntil: parentUntil, activeUntil: activeUntil, finished: time.Now()}
		}
	}()
	var zero contracts.InitialProviderResponse
	if b == nil || ctx == nil || issuer == nil || !b.preparer.ProviderInputsEnabled() || purpose != "wrap" && purpose != "unwrap" {
		return zero, time.Time{}, cfg.ErrInvalid
	}
	s := b.preparer
	phase = "request-owner"
	ctx, joined, e := s.ownPodRequest(ctx)
	if e != nil {
		return zero, time.Time{}, e
	}
	defer joined()
	phase = "binding"
	_, binding, until, e := b.Bind(ctx)
	if e != nil {
		return zero, time.Time{}, e
	}
	activeUntil = until
	if !s.protection.observer.now().Before(binding.NotAfter) {
		return zero, time.Time{}, cfg.ErrUnavailable
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	phase = "material"
	material, e := s.readProviderMaterial(ctx)
	if e != nil {
		return zero, time.Time{}, e
	}
	if material.StorageUseUntil.Before(binding.NotAfter) {
		return zero, time.Time{}, cfg.ErrChanged
	}
	phase = "original-private-scope"
	root, _, e := s.originalPrivateScope(ctx)
	if e != nil {
		return zero, time.Time{}, e
	}
	phase = "private-state"
	private, state, e := s.readPrivate(ctx)
	if e != nil || state.RootUID != root.RootUID || state.SQL == nil || state.SQL.Secret == nil {
		return zero, time.Time{}, cfg.ErrChanged
	}
	phase = "provider-preflight"
	parent, providerUntil, e := issuer.Check(ctx, binding.NotAfter)
	until = identity.Earlier(until, providerUntil)
	activeUntil = until
	if e != nil {
		return zero, time.Time{}, cfg.ErrUnavailable
	}
	ctx, done := context.WithDeadline(ctx, until)
	defer done()
	if state.Providers == nil {
		phase = "parent-persist"
		next := state
		next.Providers = &contracts.InitialPreparationProviders{ProfileDigest: preparationDigest(*s.providers), Parent: parent}
		if !s.providerStateFits(next) {
			return zero, time.Time{}, cfg.ErrInvalid
		}
		if e = s.writePrivate(ctx, private, state, next, until); e != nil {
			return zero, time.Time{}, e
		}
		private, state, e = s.readPrivate(ctx)
		if e != nil {
			return zero, time.Time{}, e
		}
	}
	phase = "original-parent"
	if !sameProviderParent(state.Providers.Parent, parent) || state.Providers.ProfileDigest != preparationDigest(*s.providers) {
		return zero, time.Time{}, cfg.ErrChanged
	}
	issue := state.Providers.Wrap
	if purpose == "unwrap" {
		issue = state.Providers.Unwrap
		if state.Providers.Wrap == nil || state.Providers.Wrap.Response == nil {
			return zero, time.Time{}, cfg.ErrChanged
		}
	}
	fresh := false
	if issue == nil {
		phase = "issue-claim"
		id, e := prepUUID()
		if e != nil {
			return zero, time.Time{}, e
		}
		now := s.protection.observer.now().UTC().Truncate(time.Microsecond)
		claimUntil := until.UTC().Truncate(time.Microsecond)
		if !now.Before(claimUntil) || !claimUntil.Before(parent.ExpiresAt) {
			return zero, time.Time{}, cfg.ErrUnavailable
		}
		issue = &contracts.InitialProviderIssue{ID: id, StartedAt: now, Until: claimUntil, ExpiresBefore: parent.ExpiresAt}
		next := state
		p := *state.Providers
		next.Providers = &p
		if purpose == "wrap" {
			p.Wrap = issue
		} else {
			p.Unwrap = issue
		}
		if e = s.writePrivate(ctx, private, state, next, until); e != nil {
			return zero, time.Time{}, e
		}
		fresh = true
		private, state, e = s.readPrivate(ctx)
		if e != nil {
			return zero, time.Time{}, e
		}
	}
	response := issue.Response
	if response == nil {
		value, ok := s.providerResponse(issue.ID)
		if !ok && fresh {
			phase = "before-issue"
			if e = s.finish(ctx, until); e != nil {
				return zero, time.Time{}, e
			}
			phase = "provider-issue"
			value, e = issuer.Issue(ctx, purpose, *issue, parent)
			if e != nil {
				return zero, time.Time{}, cfg.ErrUnavailable
			}
			s.keepProviderResponse(issue.ID, value)
			ok = true
		}
		if !ok {
			phase = "original-response-unresolved"
			return zero, time.Time{}, cfg.ErrUnavailable
		}
		phase = "response-verify"
		if e = issuer.Verify(ctx, purpose, *issue, parent, value); e != nil {
			return zero, time.Time{}, cfg.ErrUnavailable
		}
		phase = "response-persist"
		next := state
		p := *state.Providers
		next.Providers = &p
		i := *issue
		i.Response = &value
		if purpose == "wrap" {
			p.Wrap = &i
		} else {
			p.Unwrap = &i
		}
		if e = s.writePrivate(ctx, private, state, next, until); e != nil {
			return zero, time.Time{}, e
		}
		response = &value
	} else {
		phase = "retained-response-verify"
		if e = issuer.Verify(ctx, purpose, *issue, parent, *response); e != nil {
			return zero, time.Time{}, cfg.ErrUnavailable
		}
	}
	phase = "final-workload"
	final, e := b.current.current(ctx, true)
	until = identity.Earlier(until, final)
	activeUntil = until
	if e != nil {
		return zero, time.Time{}, e
	}
	phase = "final-protection"
	if e = s.finish(ctx, until); e != nil {
		return zero, time.Time{}, e
	}
	return *response, until, nil
}
