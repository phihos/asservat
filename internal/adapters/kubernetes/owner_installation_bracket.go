package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// ownerBracket is one open installation bracket of the owner installation
// driver (ADR-316). Its opening proof is one complete native read of the
// protected root: handover proof with the phase-two guard, source guards and
// independent probes, administrator, owner account and Service, accepted
// configuration and both journals. Operations inside the bracket keep their
// own SQL locks, claims, CAS writes, journal re-reads, owner Deployment and
// accepted-configuration reads and deadlines; they no longer repeat the
// complete proof. The closing proof repeats it once after the last operation.
// The bracket never outlives the opening proof's original deadline.
type ownerBracket struct {
	root    *OwnerIdentityRoleRoot
	opening ownerIdentityOperationNative
	until   time.Time
}

type ownerBracketKey struct{}

// withOwnerBracket marks ctx for the bracket b; only the root's currently
// open bracket is honored.
func withOwnerBracket(ctx context.Context, b *ownerBracket) context.Context {
	return context.WithValue(ctx, ownerBracketKey{}, b)
}

// bracketOf returns the open bracket that ctx belongs to, or nil. Without one
// every reader performs its complete proof as before.
func (s *OwnerIdentityRoleRoot) bracketOf(ctx context.Context) *ownerBracket {
	if s == nil || ctx == nil {
		return nil
	}
	b, _ := ctx.Value(ownerBracketKey{}).(*ownerBracket)
	if b == nil || b.root != s {
		return nil
	}
	s.mu.Lock()
	open := s.bracket == b && !s.closed
	s.mu.Unlock()
	if !open || !s.resources.now().Before(b.until) {
		return nil
	}
	return b
}

// openOwnerBracket runs the opening proof and opens b. The bracket's
// deadline is the earliest of the five-second call, the handover proof, the
// source observation and its fleet administration; accepted configuration is
// re-read by every operation and bounds that operation only.
func (s *OwnerIdentityRoleRoot) openOwnerBracket(ctx context.Context, b *ownerBracket) (time.Time, error) {
	if s == nil || b == nil || b.root != s || ctx == nil || ctx.Err() != nil || s.input.OwnerLayout != contracts.OwnerProviderInstalledLayout {
		return time.Time{}, cfg.ErrInvalid
	}
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	err := s.withOwnerLifetime(call, func(owned context.Context) error {
		return s.bridge.withOperation(owned, func(current context.Context) error {
			first, err := s.readOwnerIdentityOperationNative(current, s.input.LayoutDigest, true)
			if err != nil {
				return err
			}
			if first.input != s.input {
				return cfg.ErrChanged
			}
			until := identity.Earlier(first.retained.until, identity.Earlier(first.source.proof.observation.FreshUntil, first.source.fleet.FreshUntil))
			if deadline, ok := current.Deadline(); ok {
				until = identity.Earlier(until, deadline)
			}
			if initialHandoverDeadline(current, s.resources.now, until) != nil {
				return cfg.ErrUnavailable
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.closed || s.bracket != nil {
				return cfg.ErrUnavailable
			}
			b.opening, b.until = first, until
			s.bracket = b
			return nil
		})
	})
	if err != nil {
		return time.Time{}, err
	}
	return b.until, nil
}

// endOwnerBracket closes b without a proof (failed operation or caller exit).
func (s *OwnerIdentityRoleRoot) endOwnerBracket(b *ownerBracket) {
	if s == nil || b == nil {
		return
	}
	s.mu.Lock()
	if s.bracket == b {
		s.bracket = nil
	}
	s.mu.Unlock()
}

// closeOwnerBracket is the closing proof: one complete native read after the
// bracket's last operation, within the opening proof's original deadline.
// Every original identity must still equal the opening proof; the resource
// journal may differ only in the owner identity and launch claims that the
// bracket's operations wrote.
func (s *OwnerIdentityRoleRoot) closeOwnerBracket(ctx context.Context, b *ownerBracket) error {
	if s == nil || b == nil || ctx == nil || ctx.Err() != nil {
		return cfg.ErrUnavailable
	}
	s.mu.Lock()
	open := s.bracket == b
	s.bracket = nil
	s.mu.Unlock()
	if !open {
		return cfg.ErrUnavailable
	}
	return s.withOwnerLifetime(ctx, func(owned context.Context) error {
		return s.bridge.withOperation(owned, func(current context.Context) error {
			last, err := s.readOwnerIdentityOperationNative(current, s.input.LayoutDigest, true)
			if err != nil {
				return ownerOperationUnavailable(ownerRootFinalNative, err)
			}
			if last.missing || last.roles.UID != s.operationRootUID {
				return ownerOperationError(ownerCurrentRoles, cfg.ErrUnavailable)
			}
			if !ownerBracketResourcesFixed(b.opening.retained.resources, last.retained.resources) {
				return ownerOperationError(ownerOriginalResources, cfg.ErrUnavailable)
			}
			expected := b.opening
			expected.retained.resources = last.retained.resources
			if check := ownerIdentityOperationOriginalDifference(expected, last); check != ownerOperationNoFailure {
				return ownerOperationError(check, cfg.ErrUnavailable)
			}
			if initialHandoverDeadline(current, s.resources.now, identity.Earlier(b.until, last.until)) != nil {
				return ownerOperationError(ownerRootFinalDeadline, cfg.ErrUnavailable)
			}
			return nil
		})
	})
}

// ownerBracketResourcesFixed reports whether the resource journal kept its
// identity and every field except the owner identity and launch claims.
func ownerBracketResourcesFixed(opening, current contracts.InitialRuntimeResourceSnapshot) bool {
	if current.UID != opening.UID {
		return false
	}
	state := current.State
	state.OwnerIdentity, state.OwnerLaunch = opening.State.OwnerIdentity, opening.State.OwnerLaunch
	return equalJSON(state, opening.State)
}

// readOwnerBracketJournals is the bracket's per-operation journal read: the
// exact bridge journal, the resource journal between two phase-policy reads
// and its fixed inventory. It replaces the complete handover proof inside a
// bracket and accepts any resource version whose fixed fields are unchanged;
// each operation's own expectations and CAS writes still apply.
func (s *OwnerIdentityRoleRoot) readOwnerBracketJournals(ctx context.Context, b *ownerBracket) (initialRuntimeRetainedResources, error) {
	var zero initialRuntimeRetainedResources
	opening := b.opening.retained
	bridge, _, err := s.bridge.read(ctx)
	if err != nil || bridge.UID != opening.bridge.UID || bridge.ResourceVersion != opening.bridge.ResourceVersion || !equalJSON(bridge.State, opening.bridge.State) {
		return zero, cfg.ErrChanged
	}
	before, phase, err := s.bridge.phasePolicy(ctx, bridge.State)
	if err != nil || phase != 2 {
		return zero, cfg.ErrChanged
	}
	current, object, err := s.resources.read(ctx)
	if err != nil || !ownerBracketResourcesFixed(opening.resources, current) {
		return zero, cfg.ErrChanged
	}
	inventory, err := s.resources.inventory(current.State)
	if err != nil || !equalJSON(inventory.BridgeAdministration, s.bridge.administration) {
		return zero, cfg.ErrChanged
	}
	after, lastPhase, err := s.bridge.phasePolicy(ctx, bridge.State)
	if err != nil || lastPhase != 2 || before.Generation != after.Generation || !equalJSON(before.Spec, after.Spec) {
		return zero, cfg.ErrChanged
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return zero, cfg.ErrUnavailable
	}
	until := identity.Earlier(deadline, identity.Earlier(b.until, identity.Earlier(bridge.ValidUntil, current.ValidUntil)))
	if initialHandoverDeadline(ctx, s.resources.now, until) != nil {
		return zero, cfg.ErrUnavailable
	}
	bridge.ValidUntil, current.ValidUntil = until, until
	return initialRuntimeRetainedResources{bridge: bridge, resources: current, object: object, until: until, policy: after}, nil
}

// readOwnerBracketNative replaces readOwnerIdentityOperationNative inside a
// bracket. It re-reads the journals, the owner Deployment, the accepted
// configuration and the role journal; source, guards, probes, administrator,
// owner account and Service come from the opening proof.
func (s *OwnerIdentityRoleRoot) readOwnerBracketNative(ctx context.Context, b *ownerBracket, withRoles bool) (ownerIdentityOperationNative, error) {
	var zero ownerIdentityOperationNative
	deadline, ok := ctx.Deadline()
	if !ok {
		return zero, cfg.ErrInvalid
	}
	until := identity.Earlier(deadline, b.until)
	call, stop := context.WithDeadline(ctx, until)
	defer stop()
	retained, err := s.readOwnerBracketJournals(call, b)
	if err != nil {
		return zero, ownerOperationError(ownerNativeRetained, err)
	}
	until = identity.Earlier(until, retained.until)
	input, err := s.inputFromResources(retained.resources, s.input.LayoutDigest)
	if err != nil || input != s.input || !retained.resources.State.CreatedAt.Equal(s.resourceCreatedAt) || !retained.resources.State.Until.Equal(s.resourceUntil) {
		return zero, ownerOperationError(ownerNativeOriginalInput, cfg.ErrChanged)
	}
	for _, claim := range retained.resources.State.Objects {
		if claim.Receipt == nil {
			return zero, ownerOperationError(ownerNativeReceipt, cfg.ErrChanged)
		}
	}
	source := b.opening.source
	if !ownerIdentityOriginalConfiguration(s.resources, retained.resources.State, source.owner) {
		return zero, ownerOperationError(ownerNativeOriginalConfiguration, cfg.ErrChanged)
	}
	reader := &OwnerEndpoints{client: s.bridge.source.client, pool: source.owner.Pool}
	deployment, err := ownerResource[apps.Deployment](reader, call, "/apis/apps/v1/namespaces/"+s.input.Namespace.Name+"/deployments/"+s.input.Deployment.Name, "apps/v1", "Deployment")
	if err != nil {
		return zero, ownerOperationError(ownerCurrentDeploymentRead, err)
	}
	if err = s.ownerIdentityOperationDeployment(call, deployment, retained.resources.State, s.input); err != nil {
		return zero, ownerOperationError(ownerNativeDeployment, err)
	}
	source.ownerDeployment = deployment
	accepted, err := s.accepted.ReadOwnerConfiguration(call)
	until = identity.Earlier(until, accepted.FreshUntil)
	switch {
	case err != nil:
		return zero, ownerOperationError(ownerNativeAcceptedRead, cfg.ErrUnavailable)
	case !accepted.Valid(s.resources.now()):
		return zero, ownerOperationError(ownerNativeAcceptedValid, cfg.ErrUnavailable)
	case !accepted.Configuration.Equal(source.owner) || !accepted.Configuration.Equal(b.opening.accepted.Configuration):
		return zero, ownerOperationError(ownerNativeAcceptedEqual, cfg.ErrUnavailable)
	case !ownerIdentityOriginalConfiguration(s.resources, retained.resources.State, accepted.Configuration):
		return zero, ownerOperationError(ownerNativeAcceptedOriginal, cfg.ErrUnavailable)
	case initialHandoverDeadline(call, s.resources.now, until) != nil:
		return zero, ownerOperationError(ownerNativeAcceptedDeadline, cfg.ErrUnavailable)
	}
	out := ownerIdentityOperationNative{retained: retained, source: source, input: input, accepted: accepted, account: b.opening.account, service: b.opening.service, until: until}
	if withRoles {
		bounded, end := context.WithDeadline(call, until)
		defer end()
		if out.roles, out.object, out.missing, err = s.readOwnerIdentityRolesJournal(bounded, until); err != nil {
			return zero, err
		}
	}
	if initialHandoverDeadline(call, s.resources.now, until) != nil {
		return zero, ownerOperationError(ownerNativeFinalDeadline, cfg.ErrUnavailable)
	}
	return out, nil
}

// readOwnerIdentityRolesJournal reads the private role journal under this
// root's pinned UID and pending original state.
func (s *OwnerIdentityRoleRoot) readOwnerIdentityRolesJournal(ctx context.Context, until time.Time) (contracts.OwnerIdentityRoleSnapshot, *core.Secret, bool, error) {
	var roles contracts.OwnerIdentityRoleSnapshot
	raw, err := s.bridge.source.client.api.Get().AbsPath(s.path() + "/" + s.name()).MaxRetries(0).DoRaw(ctx)
	defer clear(raw)
	if apierrors.IsNotFound(err) {
		if s.operationRootUID != "" {
			return roles, nil, false, cfg.ErrChanged
		}
		return roles, nil, true, nil
	}
	if err != nil {
		return roles, nil, false, err
	}
	roles, object, err := s.decode(raw, until)
	if err != nil {
		return roles, nil, false, err
	}
	if s.operationRootUID != "" && roles.UID != s.operationRootUID || s.pendingOperationRoot != nil && !equalJSON(roles.State, *s.pendingOperationRoot) {
		return contracts.OwnerIdentityRoleSnapshot{}, nil, false, cfg.ErrChanged
	}
	return roles, object, false, nil
}
