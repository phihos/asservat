package kubernetes

import (
	"context"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// InitialRuntimeBridgeHistory recognizes only the positively acknowledged final
// bridge. Its constructor holds no SQL administrator/effect facet. It permits
// the existing SELECT-only initial history reader to remain diagnostic during
// later recovery/suspension; it cannot complete a pending bridge or revive any
// installation credential. The original no-bridge history path is unchanged.
type InitialRuntimeBridgeHistory struct{ bridge *InitialRuntimeBridge }

var _ app.InitialInstallationReadAuthority = (*InitialRuntimeBridgeHistory)(nil)

func NewInitialRuntimeBridgeHistory(ctx context.Context, preparer *InitialPreparer, source *ConfigurationRoleSource, record audit.InitialInstallation, receipt audit.Receipt, administration cfg.InitialRuntimeBridgeAdministration) (*InitialRuntimeBridgeHistory, error) {
	b, err := newInitialRuntimeBridge(ctx, preparer, source, nil, record, receipt, administration)
	if err != nil {
		return nil, err
	}
	out := &InitialRuntimeBridgeHistory{bridge: b}
	if _, err = out.CheckInitialInstallationRead(ctx, record.Scope, record.Claim.PlanDigest); err != nil {
		out.Close()
		return nil, err
	}
	return out, nil
}
func (h *InitialRuntimeBridgeHistory) Close() {
	if h != nil && h.bridge != nil {
		h.bridge.Close()
	}
}
func (h *InitialRuntimeBridgeHistory) Scope() (fleet.InstallationWitnessScope, artifact.Digest) {
	if h == nil || h.bridge == nil {
		return fleet.InstallationWitnessScope{}, artifact.Digest{}
	}
	return h.bridge.record.Scope, h.bridge.record.Claim.PlanDigest
}
func (h *InitialRuntimeBridgeHistory) CheckInitialInstallationRead(ctx context.Context, scope fleet.InstallationWitnessScope, plan artifact.Digest) (time.Time, error) {
	if h == nil || h.bridge == nil || ctx == nil || scope != h.bridge.record.Scope || plan != h.bridge.record.Claim.PlanDigest {
		return time.Time{}, cfg.ErrInvalid
	}
	var until time.Time
	err := h.bridge.withOperation(ctx, func(call context.Context) error {
		b := h.bridge
		if e := b.preparer.creator.administrator(call); e != nil {
			return e
		}
		if _, _, e := b.preparer.protection.current(call); e != nil {
			return e
		}
		snapshot, _, e := b.read(call)
		if e != nil {
			return e
		}
		if snapshot.State.Retained == nil || snapshot.State.Retained.Receipt == nil {
			return cfg.ErrUnavailable
		}
		_, phase, e := b.phasePolicy(call, snapshot.State)
		if e != nil || phase != 2 {
			return cfg.ErrChanged
		}
		_, w, c, bound, e := b.preparer.currentHandoverWithFinal(call, b.guards[2])
		if e != nil {
			return e
		}
		if w.RootUID != b.rootUID || !equalJSON(c, b.initial) {
			return cfg.ErrChanged
		}
		until = identity.Earlier(snapshot.ValidUntil, bound)
		call, end := context.WithDeadline(call, until)
		defer end()
		// Qualify actual negative enforcement and exact current source identities,
		// without requiring an allowing source value, live issuer roots or readiness.
		// A suspended source remains useful diagnostic history, never an effect proof.
		before, e := b.source.configurationRoleGuardVersions(call)
		if e != nil {
			return e
		}
		if e = b.currentProbeAccounts(call); e != nil {
			return e
		}
		if e = b.source.protection.prove(call, b.source.client.now()); e != nil {
			return e
		}
		for _, g := range []*configMapProtection{b.source.fleet.protection.configMapProtection, b.source.owner.protection.configMapProtection} {
			_, first, e := b.source.client.installationConfig(call, g.plan.SourceName, b.sourceUID(g.plan.SourceName))
			if e != nil {
				return e
			}
			if e = g.prove(call); e != nil {
				return e
			}
			_, last, e := b.source.client.installationConfig(call, g.plan.SourceName, b.sourceUID(g.plan.SourceName))
			if e != nil || last != first {
				return cfg.ErrChanged
			}
		}
		after, e := b.source.configurationRoleGuardVersions(call)
		if e != nil || before != after {
			return cfg.ErrChanged
		}
		last, _, e := b.read(call)
		if e != nil || last.UID != snapshot.UID || !equalJSON(last.State, snapshot.State) {
			return cfg.ErrChanged
		}
		_, phase, e = b.phasePolicy(call, snapshot.State)
		if e != nil || phase != 2 {
			return cfg.ErrChanged
		}
		return initialHandoverDeadline(call, b.source.client.now, until)
	})
	if err != nil {
		return time.Time{}, err
	}
	return until, nil
}
func (b *InitialRuntimeBridge) sourceUID(name string) string {
	if name == b.source.input.FleetSource.Name {
		return b.source.input.FleetSource.UID
	}
	if name == b.source.input.OwnerSource.Name {
		return b.source.input.OwnerSource.UID
	}
	return ""
}
