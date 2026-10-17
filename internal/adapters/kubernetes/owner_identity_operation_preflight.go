package kubernetes

import (
	"context"

	fleetapp "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// providerOperation keeps the same joined root/resource/bridge/source ownership
// through one original phase. Only the first read-only native bracket moves
// before recovery/activation SQL locks. The current comparison after those
// locks and every caller's independent final bracket remain mandatory.
// Neither callback is a public port, cached proof or selectable runtime option.
func (s *OwnerIdentityRoleRoot) providerOperation(ctx context.Context, withRoles bool, preflight func(context.Context) (ownerIdentityOperationNative, error), run func(context.Context, ownerIdentityOperationNative) error) error {
	if s == nil || s.bridge == nil || s.resources == nil || s.resources.ownerLayout != contracts.OwnerProviderInstalledLayout || ctx == nil || ctx.Err() != nil || preflight == nil || run == nil {
		return cfg.ErrUnavailable
	}
	effects, ok := s.bridge.effects.(fleetapp.InitialRuntimeOwnerBridgeEffects)
	if !ok {
		return cfg.ErrUnavailable
	} // No silent fallback to a weaker bridge.
	return s.withOwnerLifetime(ctx, func(call context.Context) error {
		return s.bridge.withOperation(call, func(current context.Context) error {
			first, err := preflight(current)
			if err != nil {
				return err
			}
			if first.input != s.input || initialHandoverDeadline(current, s.resources.now, first.until) != nil {
				return cfg.ErrUnavailable
			}
			bounded, stop := context.WithDeadline(current, first.until)
			defer stop()
			return effects.WithInitialRuntimeOwnerBridge(bounded, first.source.fleet, func(locked context.Context) error {
				// No native proof is reissued here. Compare current actual source,
				// guards, namespace, administrator, original objects and journals
				// after lock acquisition while retaining the first proof interval.
				// The accepted owner read keeps its separate short transaction, so
				// its owner-head SHARE is never held across the final native graph.
				after, err := s.readOwnerIdentityOperationCurrentScope(locked, first, first.retained.resources, first.roles, withRoles, withRoles && first.missing)
				if err != nil {
					return err
				}
				if !ownerIdentityOperationOriginalsEqual(first, after) {
					return cfg.ErrChanged
				}
				until := identity.Earlier(first.until, after.until)
				if initialHandoverDeadline(locked, s.resources.now, until) != nil {
					return cfg.ErrUnavailable
				}
				first.until = until
				if withRoles && !first.missing {
					first.roles.ValidUntil = identity.Earlier(first.roles.ValidUntil, until)
				}
				live, cancel := context.WithDeadline(locked, until)
				defer cancel()
				return run(live, first)
			})
		})
	})
}
