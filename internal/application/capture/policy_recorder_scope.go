package capture

import (
	"crypto/sha256"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// recorderCollection contains collection fields only. Sharing and grantRef
// remain separately authorized controls; adding another control to RestartPolicy
// cannot silently change the collection approval or reissue its spend pool.
// Field names/order and optional tags preserve existing unshared scope bytes.
type recorderCollection struct {
	ClusterID, Namespace, WorkloadKind, WorkloadName string
	Reasons                                          []string
	ExitCodes                                        []int32
	Interval                                         time.Duration
	Burst                                            int
	RetentionSeconds                                 int64
	ObservedPods                                     int
	Detector                                         string                                `json:",omitempty"`
	ProbeType                                        string                                `json:",omitempty"`
	MinimumFailures                                  int                                   `json:",omitempty"`
	ProbeWindow                                      time.Duration                         `json:",omitempty"`
	AlertLabels                                      map[string]string                     `json:",omitempty"`
	Log                                              *targets.LogMatch                     `json:",omitempty"`
	Resource                                         *targets.ResourceCondition            `json:",omitempty"`
	Recorder                                         *planning.PolicyRecorderConfiguration `json:",omitempty"`
}

func recorderCollectionOf(p value.RestartPolicy) recorderCollection {
	return recorderCollection{ClusterID: p.ClusterID, Namespace: p.Namespace, WorkloadKind: p.WorkloadKind, WorkloadName: p.WorkloadName, Reasons: p.Reasons, ExitCodes: p.ExitCodes, Interval: p.Interval, Burst: p.Burst, RetentionSeconds: p.RetentionSeconds, ObservedPods: p.ObservedPods, Detector: p.Detector, ProbeType: p.ProbeType, MinimumFailures: p.MinimumFailures, ProbeWindow: p.ProbeWindow, AlertLabels: p.AlertLabels, Log: p.Log, Resource: p.Resource, Recorder: p.Recorder}
}

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
		Policy                    recorderCollection
		NamespaceUID, WorkloadUID string
		Delegation                identity.Revision
		Owners                    []artifact.AudienceAssignment
		Actions                   []string
		Limits                    authorization.AutomationLimits
	}{"policy-scope/recorder/v1", sourceUID, intentVersion, collection, recorderCollectionOf(p), namespaceUID, workloadUID, delegation, owners, actions, limits})
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
