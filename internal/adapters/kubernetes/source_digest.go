package kubernetes

import (
	"crypto/sha256"

	"asservat.local/asservat/internal/domain/artifact"
)

// ConfigMapSourceDigest is the stable protection digest of one configuration
// ConfigMap (Helm-native installation, field map "Persisted digest and OID
// couplings" 1). It names the object only; no admission pin enters it.
func ConfigMapSourceDigest(clusterID, namespace, name string) artifact.Digest {
	return namedDigest("asservat-configmap-source/v2", clusterID, namespace, name)
}

// WorkloadProtectionDigest is the stable protection digest of one hub or
// connector Deployment (field map coupling 2).
func WorkloadProtectionDigest(clusterID, namespace, deployment string) artifact.Digest {
	return namedDigest("asservat-workload-protection/v2", clusterID, namespace, deployment)
}

func namedDigest(format string, parts ...string) artifact.Digest {
	h := sha256.New()
	h.Write([]byte(format))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	var out artifact.Digest
	copy(out[:], h.Sum(nil))
	return out
}
