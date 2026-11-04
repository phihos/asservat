package postgres

import (
	"reflect"
	"slices"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	planvalue "asservat.local/asservat/internal/domain/planning"
)

// A profile policy approves a stable endpoint definition and binding. The
// immutable child keeps the real triggering Pod and concrete endpoint; neither
// its recipe hash alone nor a matching source name covers a different route.
func policyProfileAcquisitionMatches(g authorization.Grant, acquisition *artifact.GoProfileAcquisition, recipe artifact.Digest) bool {
	parent, err := authapp.PolicyProfileGrantRecorder(g)
	if err != nil || acquisition == nil || !acquisition.Valid() || recipe != parent.RecipeDigest {
		return false
	}
	child, err := planning.ProfileContextFor(acquisition)
	if err != nil || len(child.Endpoints) != 1 || !reflect.DeepEqual(parent.Composition, child.Composition) || !parent.ProfileEndpoint.Matches(child.Endpoints[0]) {
		return false
	}
	target, authority := child.Endpoints[0].Request.Target, g.Policy.Authority
	if target.ClusterID != authority.ClusterID || target.Namespace.UID != authority.NamespaceUID || target.Workload.UID != authority.WorkloadUID {
		return false
	}
	a := parent.Action
	duration := time.Duration(0)
	if a.Duration != "" {
		duration, err = time.ParseDuration(a.Duration)
		if err != nil {
			return false
		}
	}
	timeout, err := time.ParseDuration(a.Timeout)
	return err == nil && acquisition.SourceRef == parent.ProfileEndpoint.SourceRef && acquisition.Type == a.ProfileType && acquisition.Mode == a.ProfileMode && acquisition.ForceGC == a.ForceGC && acquisition.DurationMillis == duration.Milliseconds() && acquisition.TimeoutMillis == timeout.Milliseconds() && acquisition.MaxBytes == a.MaxBytes
}

func policyProfilePlanMatches(g authorization.Grant, plan planvalue.ContextPlan) bool {
	acquisition, _, err := planning.ProfileForContext(plan)
	if err != nil || !policyProfileAcquisitionMatches(g, &acquisition, plan.RecipeDigest) {
		return false
	}
	parent, err := authapp.PolicyProfileGrantRecorder(g)
	child, planErr := planning.ProfilePlanForContext(plan)
	if err != nil || planErr != nil || len(child.Actions) != 1 || len(child.Profiles) != 1 || child.Profiles[0] != parent.Profile {
		return false
	}
	actual := child.Actions[0]
	actual.EndpointDigest = "" // This digest includes the child's actual Pod/route.
	// The protected require-all setting adds a review reason, not a different
	// acquisition. Profiles already require the raw recurring grant above. Keep
	// its frozen child scope intact and compare all collection-sensitive reasons.
	actual.Sensitive = slices.DeleteFunc(slices.Clone(actual.Sensitive), func(code string) bool { return code == planvalue.ReasonRecordingApproval })
	return reflect.DeepEqual(parent.Action, actual)
}
