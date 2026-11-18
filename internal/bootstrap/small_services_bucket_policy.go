package bootstrap

import (
	"encoding/json"
	"maps"
	"strings"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	core "k8s.io/api/core/v1"
)

// compiledIAMData keeps previous regional bucket statements from the hook's
// own desired Secret. The old process enforces them until the new IAM config
// loads. Bucket setup independently refuses replacement of foreign statements.
func compiledIAMData(compiled providerconfig.CompiledSeaweedStorage, evidence string, previous []byte) (map[string][]byte, error) {
	if len(previous) != 0 {
		var previousPolicies map[string]json.RawMessage
		if json.Unmarshal(previous, &previousPolicies) != nil {
			return nil, secretsFailure("InvalidObjectStoreBucketPolicies")
		}
		type policy struct {
			Version   string
			Statement []json.RawMessage
		}
		var old, next policy
		// An oversized previous policy could only have been desired: the
		// provider refused it. Keep setup's comparison against the live policy.
		if oldEvidence := previousPolicies[evidence]; len(oldEvidence) != 0 && len(oldEvidence) <= seaweedBucketPolicyBytes {
			if json.Unmarshal(oldEvidence, &old) != nil || old.Version != "2012-10-17" ||
				json.Unmarshal(compiled.Policies[evidence], &next) != nil || next.Version != old.Version {
				return nil, secretsFailure("InvalidObjectStoreBucketPolicies")
			}
			added := false
			for _, statement := range old.Statement {
				if previousRegionalStatement(statement) {
					next.Statement = append(next.Statement, statement)
					added = true
				}
			}
			if added {
				raw, err := json.Marshal(next)
				if err != nil {
					return nil, secretsFailure("InvalidObjectStoreBucketPolicies")
				}
				compiled.Policies = maps.Clone(compiled.Policies)
				compiled.Policies[evidence] = raw
			}
		}
	}
	policies, err := json.Marshal(compiled.Policies)
	if err != nil {
		return nil, secretsFailure("InvalidObjectStoreBucketPolicies")
	}
	if len(compiled.Config)+len(policies) > core.MaxSecretSize {
		return nil, secretsFailure("ObjectStoreIAMExceedsKubernetesSecretSize")
	}
	return map[string][]byte{providerconfig.SeaweedConfigKey: compiled.Config, SeaweedBucketPoliciesKey: policies}, nil
}

func previousRegionalStatement(raw json.RawMessage) bool {
	var s struct {
		Principal map[string]string
	}
	if json.Unmarshal(raw, &s) != nil || len(s.Principal) != 1 {
		return false
	}
	for _, purpose := range contracts.RemoteObjectStorePrincipals() {
		id, ok := strings.CutPrefix(s.Principal["AWS"], "arn:aws:iam::000000000000:user/asservat-"+purpose+"-")
		if ok && authorization.UUID(id) {
			return true
		}
	}
	return false
}
