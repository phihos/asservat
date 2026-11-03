package bootstrap

import (
	"asservat.local/asservat/internal/adapters/packets"
	captureapp "asservat.local/asservat/internal/application/capture"
	planningapp "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
	"asservat.local/asservat/internal/transport/conversion"
	"context"
	"encoding/json"
	"time"
)

// Shared inert lifecycle compilation for the accepted-source reader and this
// unmerged native candidate. It grants no source/manual acquisition authority.
func recordingSavePolicyCompiler(filters planningapp.FilterCompiler, profiles captureapp.CatalogProfiles) captureapp.PolicyRecorderCompiler {
	return func(ctx context.Context, scope targets.Request, raw json.RawMessage) ([]planvalue.PolicyRecorderConfiguration, error) {
		var wire contracts.CaptureComposition
		if err := json.Unmarshal(raw, &wire); err != nil {
			return nil, err
		}
		composition, err := conversion.CompositionFromWire(wire)
		if err != nil || composition == nil {
			return nil, planvalue.ErrInvalid
		}
		var refs []planvalue.ProfileRef
		for _, component := range composition.Components {
			if component.Profile.Catalog != "builtin" {
				refs = append(refs, component.Profile)
			}
		}
		if len(refs) > 0 {
			// Scope comes from the operation's current workload observation or
			// accepted authority, never a caller-authored namespace UID/Pod.
			if ctx == nil || ctx.Err() != nil || profiles == nil || !authorization.UUID(scope.ClusterID) || !identity.Text(scope.Namespace.Name, 63) || !identity.Text(scope.Namespace.UID, 64) || !identity.Text(scope.Workload.UID, 64) || scope.PodUID != "" || scope.PodName != "" {
				return nil, planvalue.ErrInvalid
			}
			composition.Resolved, err = profiles.ReadCatalogProfiles(ctx, targets.PodResolution{Request: scope}, refs)
			if err != nil {
				return nil, err
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		all, err := planningapp.CompileOngoingPolicyRecorders(*composition, filters)
		if err != nil {
			return nil, err
		}
		for _, cfg := range all {
			if cfg.Filter != nil && planningapp.RawBytePredicate(cfg.Action.Filter) && packets.CheckPrefixProgram(cfg.Filter.Program) != nil {
				return nil, planvalue.ErrInvalid
			}
		}
		return all, nil
	}
}

// packetSourceCompositionReady is the single trusted acquisition decision for
// this unmerged native candidate. Collection capability alone or a caller's
// nested RecordingSaveEnabled value is insufficient. No observation is created.
func packetSourceCompositionReady(c PublicContextOperationsConfig, s PublicContextOperationServices) bool {
	r, i := s.ongoingSources, s.Investigation
	if !c.CollectionEnabled || r == nil || r.Ledger == nil || r.Dispatcher == nil || r.Observer == nil || r.Recovery == nil || r.Retention == nil || r.Settings == nil || r.Now == nil || r.NewID == nil || i.RecordingPolicies == nil || i.PolicyAccepted == nil || i.RecordingSources == nil || i.RecordingGroups == nil || i.Approvals == nil {
		return false
	}
	_, snapshots := i.Targets.(captureapp.SourceSnapshotGroupTargets)
	_, single := i.Targets.(captureapp.SourceSnapshotTargets)
	return snapshots && single
}

// Bind the existing source-purpose services only after protected identity
// settings are available. This constructs no worker, watch or provider client.
func (p *publicContext) packetSourceRuntime(now func() time.Time, newID func() string) *captureapp.PolicySourceRuntime {
	if p == nil || p.policySources == nil || p.sourceDispatch.Router == nil || p.sourceDispatch.Signer == nil || p.sourceDispatch.Now == nil {
		return nil
	}
	observer, ok := p.investigation.Targets.(captureapp.OngoingRecorderObserver)
	if !ok {
		return nil
	}
	return &captureapp.PolicySourceRuntime{Ledger: p.policySources, Dispatcher: p.sourceDispatch, Observer: observer, Recovery: p.investigation.Recovery, Retention: p.investigation.Retention, Settings: p.investigation.Approvals, Storage: p.investigation.Storage, Refresh: p.investigation.Refresh, Now: now, NewID: newID}
}
