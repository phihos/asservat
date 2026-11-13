package contracts

import (
	"crypto/sha256"
	"strings"
)

// ConfigMapSourceDigest is the deterministic protection digest persisted for
// a Helm-rendered source ConfigMap (protection_digest columns, owner
// configuration observations). Kubernetes RBAC protects the object; the
// digest names it and attests no admission guard.
func ConfigMapSourceDigest(clusterID, namespace, name string) [32]byte {
	return sha256.Sum256([]byte(strings.Join([]string{"asservat-configmap-source/v2", clusterID, namespace, name}, "\x00")))
}

// WorkloadSourceDigest is the same deterministic digest for a Helm-rendered
// workload (owner workload protection, capacity qualification).
func WorkloadSourceDigest(clusterID, namespace, name string) [32]byte {
	return sha256.Sum256([]byte(strings.Join([]string{"asservat-workload-source/v2", clusterID, namespace, name}, "\x00")))
}

// NamespaceSourceDigest is the deterministic digest of a protected namespace
// (capacity namespace qualification).
func NamespaceSourceDigest(clusterID, namespace string) [32]byte {
	return sha256.Sum256([]byte(strings.Join([]string{"asservat-namespace-source/v2", clusterID, namespace}, "\x00")))
}
