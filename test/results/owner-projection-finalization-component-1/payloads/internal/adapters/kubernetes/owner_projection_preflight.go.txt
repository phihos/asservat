package kubernetes

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
)

// This private prefix is not an admitted owner operation or a current native
// proof. The original root owns it; one bridge callback may finish its actual
// reads. A copy, foreign context or second completion cannot select any material.
type ownerProjectionPreflight struct {
	self     *ownerProjectionPreflight
	root     *OwnerIdentityRoleRoot
	ctx      context.Context
	used     *atomic.Bool
	retained initialRuntimeRetainedResources
	source   *ownerProjectionSourcePrefix
	account  core.ServiceAccount
	service  core.Service
	until    time.Time
}
type ownerProjectionPreflightKey struct{}

// The projection's fixed continuation is the only consumer of this boundary.
// Other fresh callers retain providerOperation and its complete preflight.
// Provider observation has already completed; no extra work overlaps it here.
func (s *ProviderOwnerProjection) projectionOperation(ctx context.Context, proof ownerIdentityProviderObservation, launch, inspect, executionOnly bool) (OwnerProjectionAdvance, error) {
	var out OwnerProjectionAdvance
	if s == nil || s.projection == nil || s.projection.root == nil || ctx == nil || ctx.Err() != nil {
		return out, cfg.ErrUnavailable
	}
	p := s.projection
	root := p.root
	if root.bridge == nil || root.resources == nil || root.accepted == nil || root.input.OwnerLayout != contracts.OwnerProviderInstalledLayout || root.operationRootUID == "" || !p.providerCheckValid(ctx, proof) {
		return out, cfg.ErrUnavailable
	}
	effects, ok := root.bridge.effects.(fleetapp.InitialRuntimeOwnerBridgeEffects)
	if !ok {
		return out, cfg.ErrUnavailable
	}
	err := root.withOwnerLifetime(ctx, func(call context.Context) error {
		return root.bridge.withOperation(call, func(current context.Context) error {
			prefix, err := p.readProjectionPreflight(current, proof)
			if err != nil {
				native, _ := err.(*ownerOperationDiagnostic)
				return &ownerProjectionDiagnostic{check: projectionCheckInitialNative, cause: cfg.ErrUnavailable, native: projectionNativeCodes(native)}
			}
			bounded, stop := context.WithDeadline(current, prefix.until)
			defer stop()
			bounded = context.WithValue(bounded, ownerProjectionPreflightKey{}, prefix)
			prefix.ctx = bounded
			return effects.WithInitialRuntimeOwnerBridge(bounded, prefix.source.fleet, func(locked context.Context) error {
				first, err := prefix.complete(locked, proof)
				if err != nil {
					// These are actual post-lock comparisons. Preserve changed versus
					// unavailable; only the pre-lock prefix is normalized above.
					return err
				}
				live, cancel := context.WithDeadline(locked, first.until)
				defer cancel()
				out, err = s.advanceAdmitted(live, first, proof, launch, inspect, executionOnly)
				return err
			})
		})
	})
	if err != nil {
		return OwnerProjectionAdvance{}, err
	}
	return out, nil
}

// C12/B13/H7/S15/W3/T6 before the bridge in the conflict-free graph. All
// retained-input and original-object checks precede SQL locking; no password
// journal or completed source proof exists at this point.
func (s *OwnerIdentityProjection) readProjectionPreflight(ctx context.Context, proof ownerIdentityProviderObservation) (*ownerProjectionPreflight, error) {
	var zero *ownerProjectionPreflight
	root := s.root
	if root == nil || root.operationRootUID == "" || ctx == nil || ctx.Err() != nil || !s.providerCheckValid(ctx, proof) {
		return zero, cfg.ErrUnavailable
	}
	until, ok := ctx.Deadline()
	if !ok {
		return zero, cfg.ErrUnavailable
	}
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	var retained initialRuntimeRetainedResources
	var source *ownerProjectionSourcePrefix
	var failures [2]error
	var joined sync.WaitGroup
	joined.Add(2)
	go func() {
		defer joined.Done()
		retained, failures[0] = root.bridge.readRetainedOriginalResources(call, root.resources)
		if failures[0] != nil {
			cancel()
		}
	}()
	go func() {
		defer joined.Done()
		source, failures[1] = root.bridge.source.readOwnerProjectionSourcePrefix(call)
		if failures[1] != nil {
			cancel()
		}
	}()
	joined.Wait()
	for i, err := range failures {
		if err != nil {
			check := ownerNativeRetained
			if i == 1 {
				check = ownerNativeSource
			}
			return zero, ownerOperationError(check, err)
		}
	}
	until = identity.Earlier(until, identity.Earlier(proof.until, identity.Earlier(retained.until, source.until)))
	bounded, narrow := context.WithDeadline(call, until)
	defer narrow()
	if initialHandoverDeadline(bounded, root.resources.now, until) != nil {
		return zero, ownerOperationError(ownerNativeInitialDeadline, cfg.ErrUnavailable)
	}
	input, err := root.inputFromResources(retained.resources, root.input.LayoutDigest)
	if err != nil || input.OwnerLayout != contracts.OwnerProviderInstalledLayout {
		return zero, ownerOperationError(ownerNativeInput, cfg.ErrChanged)
	}
	for _, claim := range retained.resources.State.Objects {
		if claim.Receipt == nil {
			return zero, ownerOperationError(ownerNativeReceipt, cfg.ErrChanged)
		}
	}
	if input != root.input || !retained.resources.State.CreatedAt.Equal(root.resourceCreatedAt) || !retained.resources.State.Until.Equal(root.resourceUntil) {
		return zero, ownerOperationError(ownerNativeOriginalInput, cfg.ErrChanged)
	}
	if !ownerIdentityOriginalConfiguration(root.resources, retained.resources.State, source.owner) || !proof.configuration.Equal(source.owner) {
		return zero, ownerOperationError(ownerNativeOriginalConfiguration, cfg.ErrChanged)
	}
	if err = root.ownerIdentityOperationDeployment(bounded, source.ownerDeployment, retained.resources.State, input); err != nil {
		return zero, ownerOperationError(ownerNativeDeployment, err)
	}
	reader := &OwnerEndpoints{client: root.bridge.source.client, pool: source.owner.Pool}
	account, err := ownerResource[core.ServiceAccount](reader, bounded, "/api/v1/namespaces/"+input.Namespace.Name+"/serviceaccounts/"+input.ServiceAccount.Name, "v1", "ServiceAccount")
	if err != nil {
		return zero, ownerOperationError(ownerNativeAccountRead, err)
	}
	if err = root.ownerIdentityOperationOriginalObject(bounded, account, retained.resources.State, 0); err != nil {
		return zero, ownerOperationError(ownerNativeAccountOriginal, err)
	}
	service, err := ownerResource[core.Service](reader, bounded, "/api/v1/namespaces/"+input.Namespace.Name+"/services/"+source.owner.Pool.Service, "v1", "Service")
	if err != nil {
		return zero, ownerOperationError(ownerNativeServiceRead, err)
	}
	if err = root.ownerIdentityOperationOriginalObject(bounded, service, retained.resources.State, 12); err != nil {
		return zero, ownerOperationError(ownerNativeServiceOriginal, err)
	}
	if !s.providerCheckValid(bounded, proof) || initialHandoverDeadline(bounded, root.resources.now, until) != nil {
		return zero, ownerOperationError(ownerNativeFinalDeadline, cfg.ErrUnavailable)
	}
	out := &ownerProjectionPreflight{root: root, used: &atomic.Bool{}, retained: retained, source: source, account: account, service: service, until: until}
	out.self = out
	return out, nil
}

// Actual remaining source reads plus C4 journals, owner objects/administrator
// and all four probe bindings run after bridge acquisition. The final namespace
// is last among native public reads. Only completed protection and the short
// accepted SQL read permit the first fixed private role-journal GET.
func (s *ownerProjectionPreflight) complete(ctx context.Context, proof ownerIdentityProviderObservation) (ownerIdentityOperationNative, error) {
	var zero ownerIdentityOperationNative
	if s == nil || s.self != s || s.root == nil || s.source == nil || s.used == nil || s.ctx == nil || ctx == nil || ctx.Value(ownerProjectionPreflightKey{}) != s || s.ctx.Err() != nil || ctx.Err() != nil {
		return zero, cfg.ErrUnavailable
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(s.until) || !s.used.CompareAndSwap(false, true) {
		return zero, cfg.ErrUnavailable
	}
	root := s.root
	root.mu.Lock()
	owned := !root.closed && root.busy && root.ownerOperation == nil && root.ctx != nil && root.ctx.Err() == nil
	root.mu.Unlock()
	if !owned || root.operationRootUID == "" || initialHandoverDeadline(ctx, root.resources.now, s.until) != nil {
		return zero, cfg.ErrUnavailable
	}
	call, stop := context.WithDeadline(ctx, identity.Earlier(deadline, s.until))
	defer stop()
	// Recheck the complete actual tail without constructing a proof marker yet.
	tail, err := s.source.readTail(call)
	if err != nil {
		return zero, ownerOperationError(ownerNativeSource, err)
	}
	until := identity.Earlier(deadline, identity.Earlier(s.until, tail.until))
	call, narrow := context.WithDeadline(call, until)
	defer narrow()
	retained, err := root.readOwnerIdentityOperationJournals(call, s.retained, s.retained.resources)
	if err != nil {
		return zero, ownerOperationError(ownerNativeRetained, err)
	}
	until = identity.Earlier(until, retained.until)
	call, narrowed := context.WithDeadline(call, until)
	defer narrowed()
	administrator, err := root.bridge.source.configurationWorkerAdministrator(call)
	if err != nil {
		return zero, ownerOperationError(ownerNativeSource, err)
	}
	if !equalJSON(administrator, s.source.administrator) {
		return zero, ownerOperationError(ownerNativeSource, cfg.ErrChanged)
	}
	reader := &OwnerEndpoints{client: root.bridge.source.client, pool: s.source.owner.Pool}
	deployment, err := ownerResource[apps.Deployment](reader, call, "/apis/apps/v1/namespaces/"+root.input.Namespace.Name+"/deployments/"+root.input.Deployment.Name, "apps/v1", "Deployment")
	if err != nil {
		return zero, ownerOperationError(ownerNativeDeployment, err)
	}
	if err = root.ownerIdentityOperationDeployment(call, deployment, retained.resources.State, root.input); err != nil {
		return zero, ownerOperationError(ownerNativeDeployment, err)
	}
	account, err := ownerResource[core.ServiceAccount](reader, call, "/api/v1/namespaces/"+root.input.Namespace.Name+"/serviceaccounts/"+root.input.ServiceAccount.Name, "v1", "ServiceAccount")
	if err != nil {
		return zero, ownerOperationError(ownerNativeAccountRead, err)
	}
	if !equalJSON(account, s.account) || root.ownerIdentityOperationOriginalObject(call, account, retained.resources.State, 0) != nil {
		return zero, ownerOperationError(ownerNativeAccountOriginal, cfg.ErrChanged)
	}
	service, err := ownerResource[core.Service](reader, call, "/api/v1/namespaces/"+root.input.Namespace.Name+"/services/"+s.service.Name, "v1", "Service")
	if err != nil {
		return zero, ownerOperationError(ownerNativeServiceRead, err)
	}
	if !equalJSON(service, s.service) || root.ownerIdentityOperationOriginalObject(call, service, retained.resources.State, 12) != nil {
		return zero, ownerOperationError(ownerNativeServiceOriginal, cfg.ErrChanged)
	}
	if err = root.ownerIdentityOperationProbes(call, account, tail.account); err != nil {
		return zero, ownerOperationError(ownerNativeProbes, err)
	}
	source, err := s.source.finish(call, tail)
	if err != nil {
		return zero, ownerOperationError(ownerNativeSource, err)
	}
	source.ownerDeployment = deployment
	until = identity.Earlier(until, source.proof.observation.FreshUntil)
	call, finalBound := context.WithDeadline(call, until)
	defer finalBound()
	accepted, err := root.accepted.ReadOwnerConfiguration(call)
	until = identity.Earlier(until, accepted.FreshUntil)
	if err != nil {
		return zero, ownerOperationError(ownerNativeAcceptedRead, cfg.ErrUnavailable)
	}
	if !accepted.Valid(root.resources.now()) {
		return zero, ownerOperationError(ownerNativeAcceptedValid, cfg.ErrUnavailable)
	}
	if !accepted.Configuration.Equal(source.owner) || !accepted.Configuration.Equal(proof.configuration) {
		return zero, ownerOperationError(ownerNativeAcceptedEqual, cfg.ErrUnavailable)
	}
	if !ownerIdentityOriginalConfiguration(root.resources, retained.resources.State, accepted.Configuration) {
		return zero, ownerOperationError(ownerNativeAcceptedOriginal, cfg.ErrUnavailable)
	}
	if initialHandoverDeadline(call, root.resources.now, until) != nil {
		return zero, ownerOperationError(ownerNativeAcceptedDeadline, cfg.ErrUnavailable)
	}
	bounded, end := context.WithDeadline(call, until)
	defer end()
	// This is the first private selection, moved behind the bridge. Preserve
	// the old initial-native error normalization without retaining client errors.
	raw, err := root.bridge.source.client.api.Get().AbsPath(root.path() + "/" + root.name()).MaxRetries(0).DoRaw(bounded)
	defer clear(raw)
	if err != nil {
		return zero, &ownerProjectionDiagnostic{check: projectionCheckInitialNative, cause: cfg.ErrUnavailable}
	}
	roles, object, err := root.decode(raw, until)
	if err != nil {
		return zero, &ownerProjectionDiagnostic{check: projectionCheckInitialNative, cause: cfg.ErrUnavailable}
	}
	if roles.UID != root.operationRootUID || root.pendingOperationRoot != nil && !equalJSON(roles.State, *root.pendingOperationRoot) {
		return zero, &ownerProjectionDiagnostic{check: projectionCheckInitialNative, cause: cfg.ErrUnavailable}
	}
	if initialHandoverDeadline(bounded, root.resources.now, until) != nil {
		return zero, ownerOperationError(ownerNativeFinalDeadline, cfg.ErrUnavailable)
	}
	return ownerIdentityOperationNative{retained: retained, source: source, input: root.input, accepted: accepted, account: account, service: service, roles: roles, object: object, until: until}, nil
}
