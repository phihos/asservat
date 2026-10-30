package bootstrap

import (
	"asservat.local/asservat/internal/adapters/packets"
	captureapp "asservat.local/asservat/internal/application/capture"
	planningapp "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/transport/conversion"
	"encoding/json"
	"time"
)

// Shared inert lifecycle compilation for the accepted-source reader and this
// unmerged native candidate. It grants no source/manual acquisition authority.
func recordingSavePolicyCompiler(filters planningapp.FilterCompiler) captureapp.PolicyRecorderCompiler {
	return func(raw json.RawMessage) (planvalue.PolicyRecorderConfiguration, error) {
		var wire contracts.CaptureComposition
		if err := json.Unmarshal(raw, &wire); err != nil {
			return planvalue.PolicyRecorderConfiguration{}, err
		}
		composition, err := conversion.CompositionFromWire(wire)
		if err != nil || composition == nil {
			return planvalue.PolicyRecorderConfiguration{}, planvalue.ErrInvalid
		}
		cfg, err := planningapp.CompileOngoingPolicyRecorder(*composition, filters)
		if err != nil {
			return cfg, err
		}
		if cfg.Filter != nil && planningapp.RawBytePredicate(cfg.Action.Filter) && packets.CheckPrefixProgram(cfg.Filter.Program) != nil {
			return planvalue.PolicyRecorderConfiguration{}, planvalue.ErrInvalid
		}
		return cfg, nil
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
	return &captureapp.PolicySourceRuntime{Ledger: p.policySources, Dispatcher: p.sourceDispatch, Observer: observer, Recovery: p.investigation.Recovery, Retention: p.investigation.Retention, Settings: p.investigation.Approvals, Now: now, NewID: newID}
}
