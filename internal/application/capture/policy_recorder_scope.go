package capture

import (
	"crypto/sha256"
	"encoding/json"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// RecorderPolicyScope binds accepted collection intent rather than mutable
// control metadata. The SQL intent version advances on observed collection
// change/revert or a missed generation; grantRef and pause never reissue policy
// authority. Legacy pod-status scope bytes remain under RestartScopeDigest.
func RecorderPolicyScope(sourceUID string, intentVersion int64, collection artifact.Digest, p value.RestartPolicy, namespaceUID, workloadUID string, delegation identity.Revision, owners []artifact.AudienceAssignment, actions []string, limits authorization.AutomationLimits) []byte {
	if !identity.Text(sourceUID, 64) || intentVersion < 1 || collection == (artifact.Digest{}) || p.Recorder == nil || !p.Valid() || !identity.Text(namespaceUID, 64) || !identity.Text(workloadUID, 64) || !delegation.Valid() {
		return nil
	}
	b, err := json.Marshal(struct {
		Format, SourceUID         string
		IntentVersion             int64
		Collection                artifact.Digest
		Policy                    value.RestartPolicy
		NamespaceUID, WorkloadUID string
		Delegation                identity.Revision
		Owners                    []artifact.AudienceAssignment
		Actions                   []string
		Limits                    authorization.AutomationLimits
	}{"policy-scope/recorder/v1", sourceUID, intentVersion, collection, p, namespaceUID, workloadUID, delegation, owners, actions, limits})
	if err != nil || len(b) > authorization.GrantMaxScopeBytes {
		return nil
	}
	return b
}

func RecorderPolicyScopeDigest(sourceUID string, intentVersion int64, collection artifact.Digest, p value.RestartPolicy, namespaceUID, workloadUID string, delegation identity.Revision, owners []artifact.AudienceAssignment, actions []string, limits authorization.AutomationLimits) artifact.Digest {
	b := RecorderPolicyScope(sourceUID, intentVersion, collection, p, namespaceUID, workloadUID, delegation, owners, actions, limits)
	if b == nil {
		return artifact.Digest{}
	}
	return sha256.Sum256(b)
}
