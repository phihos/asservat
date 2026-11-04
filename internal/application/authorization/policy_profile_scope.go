package authorization

import (
	"slices"

	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/planning"
)

// PolicyProfileGrantRecorder reads the complete reviewed recurring scope. The
// accepted digest binds all parent bytes; a recipe digest alone cannot bind
// the stable endpoint definition or the accepted profile provenance. Current
// policy, approval phase and conservative budget checks remain the consumer's.
func PolicyProfileGrantRecorder(g value.Grant) (planning.PolicyRecorderConfiguration, error) {
	var zero planning.PolicyRecorderConfiguration
	if g.Kind != value.GrantPolicy || g.Policy == nil || !slices.Equal(g.Policy.Authority.Actions, []string{"profile"}) || g.ExecutionDigest != g.Policy.Authority.ScopeDigest ||
		g.DataClass != "raw" || g.ResultAccess != nil || g.Policy.Observation != nil || g.Policy.MaxStartsPerExecution != 0 || g.Policy.Limits.MaxObservedBytes != 0 || g.Policy.Limits.MaxObservedEvents != 0 {
		return zero, value.ErrGrantScope
	}
	p, err := acceptedRecorderPolicy(g.Scope, g.Policy.Authority, g.Policy.RecipeDigest)
	if err != nil || p.RecordingSaves || len(p.MoreRecorders) != 0 || p.Recorder.Action.Kind != "profile" || p.Recorder.Action.ExecutionMode != "onTrigger" || p.Recorder.ProfileEndpoint == nil || !p.Recorder.ProfileEndpoint.Valid() {
		return zero, value.ErrGrantScope
	}
	r := *p.Recorder
	for _, code := range []string{"policyCollection", planning.ReasonLiveProfile} {
		if !slices.Contains(g.Reasons, value.SensitiveReason{ActionID: r.Action.ID, Code: code}) {
			return zero, value.ErrGrantScope
		}
	}
	return r, nil
}

// PolicyProfileGrantScopeValid preserves historical non-profile grant decoding.
// New profile grants must satisfy the complete stored parent contract at both
// request construction and SQL readback, including before attachment/effects.
func PolicyProfileGrantScopeValid(g value.Grant) bool {
	if g.Kind != value.GrantPolicy || g.Policy == nil || !slices.Contains(g.Policy.Authority.Actions, "profile") {
		return true
	}
	_, err := PolicyProfileGrantRecorder(g)
	return err == nil
}
