package integration

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// The storage read still requires a complete whole-Pod target even though its
// binding is shared by the exact workload. This is explicitly synthetic Pod
// provenance; it neither selects a real Pod nor grants capture authority.
func capacityNativeStorageTarget(cluster string, namespace cfg.NamespaceRef, workload cfg.WorkloadRef) authorization.Target {
	return capacityNativeTarget(cluster, namespace, workload, time.Now().UTC()).Target()
}

func TestCapacityNativeStorageTarget(t *testing.T) {
	cluster := custodyID()
	namespace := cfg.NamespaceRef{Name: "applications", UID: custodyID()}
	workload := cfg.WorkloadRef{Kind: "Deployment", Name: "first", UID: custodyID()}
	target := capacityNativeStorageTarget(cluster, namespace, workload)
	if !target.Valid() || target.ClusterID != cluster || target.NamespaceUID != namespace.UID || target.WorkloadUID != workload.UID || target.PodUID == "" {
		t.Fatal("native storage assertion does not reach its SQL fence with a complete original target")
	}
	incomplete := target
	incomplete.PodUID = ""
	if incomplete.Valid() {
		t.Fatal("missing Pod identity became a valid storage-read request")
	}
}
