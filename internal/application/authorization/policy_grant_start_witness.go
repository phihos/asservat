package authorization

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"slices"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	capture "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// PolicyGrantStartsPerExecution reads only the existing hash-pinned accepted
// recorder scope. The one implemented source action contributes at most one
// snapshot per selected Pod, capped by the existing sixteen-source operation.
// It returns zero for legacy units rather than silently migrating old grants.
func PolicyGrantStartsPerExecution(scope []byte, a value.AcceptedPolicyAuthority, recipe artifact.Digest) (int, error) {
	if len(scope) < 2 || len(scope) > value.GrantMaxScopeBytes || sha256.Sum256(scope) != a.ScopeDigest {
		return 0, value.ErrGrantScope
	}
	var accepted struct {
		Format, SourceUID         string
		IntentVersion             int64
		Collection                artifact.Digest
		Policy                    capture.RestartPolicy
		NamespaceUID, WorkloadUID string
		Delegation                identity.Revision
		Owners                    []artifact.AudienceAssignment
		Actions                   []string
		Limits                    value.AutomationLimits
	}
	decoder := json.NewDecoder(bytes.NewReader(scope))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&accepted) != nil {
		return 0, value.ErrGrantScope
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return 0, value.ErrGrantScope
	}
	p := accepted.Policy
	if accepted.Format != "policy-scope/recorder/v1" || accepted.SourceUID != a.PolicyUID || accepted.IntentVersion < 1 || accepted.Collection == (artifact.Digest{}) || accepted.NamespaceUID != a.NamespaceUID || accepted.WorkloadUID != a.WorkloadUID || accepted.Delegation != a.Delegation || accepted.Limits != a.Limits || !slices.Equal(accepted.Owners, a.Owners) || !slices.Equal(accepted.Actions, a.Actions) || p.ClusterID != a.ClusterID || !p.Valid() || p.Recorder == nil || p.Recorder.RecipeDigest != recipe {
		return 0, value.ErrGrantScope
	}
	if !p.RecordingSaves || p.Recorder.Action.ExecutionMode != "ongoing" || p.IncidentPods < 2 {
		return 0, nil
	}
	return min(p.IncidentPods, capture.MaxRecordingSaveGroupChildren), nil
}

// BindReviewedPolicyGrantStarts is called both by the request producer and the
// SQL decoder. No public input can choose the fanout or supply its witness.
func BindReviewedPolicyGrantStarts(g value.Grant) (value.Grant, error) {
	if g.Policy == nil || g.Policy.MaxStartsPerExecution == 0 {
		return g, nil
	}
	starts, err := PolicyGrantStartsPerExecution(g.Scope, g.Policy.Authority, g.Policy.RecipeDigest)
	if err != nil || starts != g.Policy.MaxStartsPerExecution || starts < 2 {
		return value.Grant{}, value.ErrGrantScope
	}
	bound, ok := value.BindPolicyGrantStartWitness(g, g.Scope, starts)
	if !ok {
		return value.Grant{}, value.ErrGrantScope
	}
	return bound, nil
}
