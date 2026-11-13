package contracts

import (
	"crypto/sha256"
	"encoding/binary"
)

// Deterministic protection digests of Helm-rendered objects (field map
// "Persisted digest and OID couplings"). Kubernetes RBAC protects the object;
// a digest only names it: sha256 over the kind's format string, the cluster
// ID, the namespace and the object name, each length-prefixed. Every
// component computes them with these functions only.
const (
	configMapSourceFormat = "asservat-configmap-source/v3"
	workloadSourceFormat  = "asservat-workload-source/v3"
	namespaceSourceFormat = "asservat-namespace-source/v3"
)

func sourceDigest(parts ...string) [32]byte {
	h := sha256.New()
	for _, v := range parts {
		_ = binary.Write(h, binary.BigEndian, uint32(len(v)))
		_, _ = h.Write([]byte(v))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ConfigMapSourceDigest names a source ConfigMap (protection_digest
// columns, owner configuration observations).
func ConfigMapSourceDigest(clusterID, namespace, name string) [32]byte {
	return sourceDigest(configMapSourceFormat, clusterID, namespace, name)
}

// WorkloadSourceDigest names a hub or connector Deployment (owner workload
// protection, federation owner pools, capacity qualification).
func WorkloadSourceDigest(clusterID, namespace, name string) [32]byte {
	return sourceDigest(workloadSourceFormat, clusterID, namespace, name)
}

// NamespaceSourceDigest names a protected namespace (capacity namespace
// qualification and its guard); the object name is the namespace itself.
func NamespaceSourceDigest(clusterID, namespace string) [32]byte {
	return sourceDigest(namespaceSourceFormat, clusterID, namespace, namespace)
}
