package authorization

import (
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/planning"
	"slices"
)

// PolicyLogsGrantRecorder reads the exact accepted finite action. Raw output
// classification does not itself require acquisition approval; this validates
// a grant only when the compiled action or configured policy requires one.
func PolicyLogsGrantRecorder(g value.Grant) (planning.PolicyRecorderConfiguration, error) {
	var zero planning.PolicyRecorderConfiguration
	if g.Kind != value.GrantPolicy || g.Policy == nil || !slices.Equal(g.Policy.Authority.Actions, []string{"logs"}) || g.ExecutionDigest != g.Policy.Authority.ScopeDigest || g.DataClass != "raw" || g.ResultAccess != nil || g.Policy.Observation != nil || g.Policy.MaxStartsPerExecution != 0 || g.Policy.Limits.MaxObservedBytes != 0 || g.Policy.Limits.MaxObservedEvents != 0 {
		return zero, value.ErrGrantScope
	}
	p, err := acceptedRecorderPolicy(g.Scope, g.Policy.Authority, g.Policy.RecipeDigest)
	if err != nil || p.RecordingSaves || len(p.MoreRecorders) != 0 || p.Recorder.Action.Kind != "logs" || p.Recorder.Action.ExecutionMode != "onTrigger" || p.Recorder.Action.LogStream != "both" || p.Recorder.ProfileEndpoint != nil {
		return zero, value.ErrGrantScope
	}
	for _, code := range append([]string{"policyCollection"}, p.Recorder.Action.Sensitive...) {
		if !slices.Contains(g.Reasons, value.SensitiveReason{ActionID: p.Recorder.Action.ID, Code: code}) {
			return zero, value.ErrGrantScope
		}
	}
	return *p.Recorder, nil
}
func PolicyLogsGrantScopeValid(g value.Grant) bool {
	if g.Kind != value.GrantPolicy || g.Policy == nil || !slices.Contains(g.Policy.Authority.Actions, "logs") {
		return true
	}
	_, err := PolicyLogsGrantRecorder(g)
	return err == nil
}
