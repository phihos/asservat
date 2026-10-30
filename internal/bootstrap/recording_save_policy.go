package bootstrap

import (
	"asservat.local/asservat/internal/adapters/packets"
	captureapp "asservat.local/asservat/internal/application/capture"
	planningapp "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/transport/conversion"
	"encoding/json"
)

// The private reader verifies an already accepted ongoing definition. It does
// not widen the public activation compiler or enable source/manual acquisition.
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
