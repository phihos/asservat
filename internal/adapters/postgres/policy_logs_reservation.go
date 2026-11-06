package postgres

import (
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"reflect"
	"slices"
	"time"
)

func policyLogsAcquisitionMatches(g authorization.Grant, l *artifact.LogCapture, recipe artifact.Digest) bool {
	parent, err := authapp.PolicyLogsGrantRecorder(g)
	if err != nil || l == nil || !l.Valid() || recipe != parent.RecipeDigest {
		return false
	}
	child, err := planning.LogsContextFor(l)
	// Resolved catalogs are intentionally not persisted in either composition;
	// current API execution reloads/recompiles them before matching the plan.
	if err != nil || !reflect.DeepEqual(parent.Composition, child.Composition) {
		return false
	}
	before, be := time.ParseDuration(parent.Action.Before)
	after, ae := time.ParseDuration(parent.Action.After)
	timeout, te := time.ParseDuration(parent.Action.Timeout)
	return be == nil && ae == nil && te == nil && l.TimeoutMillis == timeout.Milliseconds() && l.ActionID == parent.Action.ID && l.BeforeMillis == before.Milliseconds() && l.AfterMillis == after.Milliseconds() && l.Streams == "combined" && l.MaxNativeBytes == parent.Action.MaxBytes
}
func policyLogsPlanMatches(g authorization.Grant, plan planvalue.ContextPlan) bool {
	l, _, err := planning.LogsForContext(plan)
	if err != nil || !policyLogsAcquisitionMatches(g, &l, plan.RecipeDigest) {
		return false
	}
	parent, err := authapp.PolicyLogsGrantRecorder(g)
	child, ce := planning.LogsPlanForContext(plan)
	if err != nil || ce != nil || len(child.Actions) != 1 || len(child.Profiles) != 1 || child.Profiles[0] != parent.Profile {
		return false
	}
	actual := child.Actions[0]
	actual.Sensitive = slices.DeleteFunc(slices.Clone(actual.Sensitive), func(code string) bool { return code == planvalue.ReasonRecordingApproval })
	if !slices.Equal(parent.Action.Sensitive, actual.Sensitive) {
		return false
	}
	// Empty and nil reason slices encode the same reason set.
	actual.Sensitive = parent.Action.Sensitive
	return reflect.DeepEqual(parent.Action, actual)
}
