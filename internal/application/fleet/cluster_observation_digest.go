package fleet

import (
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"maps"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
)

// ClusterObservationRequestDigest owns the closed semantic request digest used by both sides of the
// observation conversation. Its canonical v1 bytes are deliberately identical
// to the existing wire contract, including key order and omitted zero optional
// selectors. Validation/current authority remains separate from hashing.
func ClusterObservationRequestDigest(r value.ClusterObservationRequest) (artifact.Digest, error) {
	type namespace struct {
		Name string `json:"name"`
		UID  string `json:"uid"`
	}
	type workload struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
		UID  string `json:"uid"`
	}
	wire := struct {
		Format      string            `json:"format"`
		RequestID   string            `json:"requestId"`
		Challenge   string            `json:"challenge"`
		RootID      string            `json:"rootId"`
		ClusterID   string            `json:"clusterId"`
		Purpose     string            `json:"purpose"`
		RequestedAt string            `json:"requestedAt"`
		NotAfter    string            `json:"notAfter"`
		Namespace   *namespace        `json:"namespace,omitempty"`
		Workload    *workload         `json:"workload,omitempty"`
		Kind        string            `json:"kind,omitempty"`
		Keys        []string          `json:"keys,omitempty"`
		Annotations []string          `json:"annotationKeys,omitempty"`
		Selector    map[string]string `json:"selector,omitempty"`
		Continue    string            `json:"continue,omitempty"`
	}{Format: "cluster-observation/v1", RequestID: r.ID, Challenge: r.Challenge, RootID: r.RootID, ClusterID: r.ClusterID, Purpose: string(r.Purpose), RequestedAt: r.RequestedAt.UTC().Format(time.RFC3339Nano), NotAfter: r.NotAfter.UTC().Format(time.RFC3339Nano), Kind: r.Kind, Keys: slices.Clone(r.Keys), Annotations: slices.Clone(r.AnnotationKeys), Selector: maps.Clone(r.Selector), Continue: r.Continue}
	if r.Namespace != (cfg.NamespaceRef{}) {
		wire.Namespace = &namespace{r.Namespace.Name, r.Namespace.UID}
	}
	if r.Workload != (cfg.WorkloadRef{}) {
		wire.Workload = &workload{r.Workload.Kind, r.Workload.Name, r.Workload.UID}
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		return artifact.Digest{}, value.ErrInvalid
	}
	canonical := jsontext.Value(raw)
	if canonical.Canonicalize() != nil || len(canonical) > 192<<10 {
		return artifact.Digest{}, value.ErrInvalid
	}
	h := sha256.New()
	h.Write([]byte("asservat-cluster-observation-request/v1\x00"))
	h.Write(canonical)
	var out artifact.Digest
	copy(out[:], h.Sum(nil))
	return out, nil
}
