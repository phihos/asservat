package planning

import (
	"bytes"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
)

// ContextScopeIdentity is historical routing/ownership only. It cannot grant
// current collection or disclose a record without an independent current check.
type ContextScopeIdentity struct {
	Actor          identity.Principal
	Target         authorization.Target
	CaptureID      string
	ExecutionClass artifact.ContextExecutionClass
	Deadline       time.Time
}

// ReadContextScopeIdentity accepts only the exact canonical private compiler
// shape. Unknown/duplicate fields, alternate formatting and changed digests fail.
func ReadContextScopeIdentity(b []byte, want artifact.Digest) (ContextScopeIdentity, error) {
	var zero ContextScopeIdentity
	if len(b) == 0 || len(b) > 65536 || want == (artifact.Digest{}) {
		return zero, value.ErrInvalid
	}
	if bytes.Contains(b, []byte(`"schemaVersion":"`+value.RecorderPlanVersion+`"`)) {
		return readRecorderScopeIdentity(b, want)
	}
	var s scope
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil {
		return zero, value.ErrInvalid
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		return zero, value.ErrInvalid
	}
	encoded, digest, err := canonical(encoded)
	if err != nil || digest != want || !bytes.Equal(encoded, b) || s.Version != "collection-scope/v1" || s.Collection.Kind != "DebugCapture" || s.Collection.Spec.Recipe.Name != ContextRecipeName || s.Collection.Spec.Recipe.Digest != hexDigest(RecipeDigest()) || len(s.Pods) != 1 {
		return zero, value.ErrInvalid
	}
	out := ContextScopeIdentity{Actor: identity.Principal{Issuer: s.Executor.Issuer, Subject: s.Executor.Subject, ClientID: s.Executor.ClientID, Kind: identity.Kind(s.Executor.Kind)}, Target: authorization.Target{ClusterID: s.Source.ClusterID, NamespaceUID: s.Source.NamespaceUID, WorkloadUID: s.Collection.Spec.Target.Workload.UID, PodUID: s.Pods[0].PodUID}, CaptureID: s.Source.ResourceUID, ExecutionClass: s.Pods[0].ExecutionClass}
	out.Deadline, err = time.Parse(time.RFC3339Nano, s.Collection.Spec.Deadline)
	if err != nil || !out.Actor.Valid() || !out.Target.Valid() || !authorization.UUID(out.CaptureID) || !out.ExecutionClass.Valid() || out.Deadline.Nanosecond()%1000 != 0 {
		return zero, value.ErrInvalid
	}
	return out, nil
}

// readRecorderScopeIdentity is ReadContextScopeIdentity for an accepted
// recorder plan (ADR-248): only acceptance nodeRecorder, always the API class.
func readRecorderScopeIdentity(b []byte, want artifact.Digest) (ContextScopeIdentity, error) {
	var zero ContextScopeIdentity
	var s recorderScope
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil {
		return zero, value.ErrInvalid
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		return zero, value.ErrInvalid
	}
	encoded, digest, err := canonical(encoded)
	if err != nil || digest != want || !bytes.Equal(encoded, b) || s.Version != value.RecorderPlanVersion || s.Interim != "nodeRecorder" {
		return zero, value.ErrInvalid
	}
	out := ContextScopeIdentity{Actor: identity.Principal{Issuer: s.Executor.Issuer, Subject: s.Executor.Subject, ClientID: s.Executor.ClientID, Kind: identity.Kind(s.Executor.Kind)}, Target: authorization.Target{ClusterID: s.Source.ClusterID, NamespaceUID: s.Source.NamespaceUID, WorkloadUID: s.Target.Workload.UID, PodUID: s.Target.PodUID}, CaptureID: s.Source.ResourceUID, ExecutionClass: artifact.ContextAPIExecution}
	out.Deadline, err = time.Parse(time.RFC3339Nano, s.Deadline)
	if err != nil || !out.Actor.Valid() || !out.Target.Valid() || !authorization.UUID(out.CaptureID) || out.Deadline.Nanosecond()%1000 != 0 {
		return zero, value.ErrInvalid
	}
	return out, nil
}
