package presentation

import "time"

// Existing-artifact review keeps each target; there is no representative
// collection target and no new acquisition attached to this grant.
type grantRawTarget struct {
	ClusterID    string `json:"cluster_id"`
	NamespaceUID string `json:"namespace_uid"`
	WorkloadUID  string `json:"workload_uid"`
	PodUID       string `json:"pod_uid"`
	Namespace    string `json:"namespace,omitempty"`
	WorkloadKind string `json:"workload_kind,omitempty"`
	WorkloadName string `json:"workload_name,omitempty"`
	PodName      string `json:"pod_name,omitempty"`
}
type grantRawArtifact struct {
	ArtifactID      string         `json:"artifact_id"`
	CaptureID       string         `json:"capture_id"`
	ActionID        string         `json:"action_id"`
	Digest          string         `json:"digest"`
	ExecutionDigest string         `json:"execution_digest"`
	NativeType      string         `json:"native_type"`
	NativeBytes     int64          `json:"native_bytes"`
	ExpiresAt       time.Time      `json:"expires_at"`
	Target          grantRawTarget `json:"target"`
}
type grantRawAccessData struct {
	CaseID         string             `json:"case_id"`
	Reason         string             `json:"reason"`
	Operations     []string           `json:"operations"`
	MaxBytes       int64              `json:"max_bytes"`
	MaxOperations  int64              `json:"max_operations"`
	NotAfter       time.Time          `json:"not_after"`
	ArtifactCount  int                `json:"artifact_count"`
	BytesUsed      int64              `json:"bytes_used"`
	OperationsUsed int64              `json:"operations_used"`
	Artifacts      []grantRawArtifact `json:"artifacts,omitempty"`
}
