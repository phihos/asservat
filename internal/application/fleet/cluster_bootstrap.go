package fleet

import (
	"crypto/ed25519"
	"encoding/json"

	"asservat.local/asservat/internal/domain/artifact"

	value "asservat.local/asservat/internal/domain/fleet"
)

// ADR-193 bootstrap signing, like ADR-168: purpose || 0 || 32-byte TLS
// exporter || canonical JSON. The pending generation-1 key signs, so the
// claim proves possession of the key the hub will activate.
func clusterBootstrapMessage(r value.ClusterBootstrapRequest, exporter []byte) ([]byte, error) {
	if !r.Valid() || len(exporter) != 32 {
		return nil, value.ErrClusterCredentialDenied
	}
	body, err := json.Marshal(r)
	if err != nil {
		return nil, value.ErrClusterCredentialDenied
	}
	out := append([]byte(value.ClusterBootstrapPurpose), 0)
	out = append(out, exporter...)
	return append(out, body...), nil
}

func SignClusterBootstrapRequest(key ed25519.PrivateKey, r value.ClusterBootstrapRequest, exporter []byte) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, value.ErrClusterCredentialDenied
	}
	message, err := clusterBootstrapMessage(r, exporter)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, message), nil
}

func VerifyClusterBootstrapRequest(public []byte, r value.ClusterBootstrapRequest, signature, exporter []byte) bool {
	message, err := clusterBootstrapMessage(r, exporter)
	return err == nil && len(public) == ed25519.PublicKeySize && len(signature) == ed25519.SignatureSize && ed25519.Verify(public, message, signature)
}

// ClusterBootstrapProof checks a bootstrap opening (ADR-193): the CSR's
// Ed25519 key with its SPKI digest, and the domain-separated secret digest.
type ClusterBootstrapProof interface {
	BootstrapKey(csr []byte) (ed25519.PublicKey, artifact.Digest, error)
	BootstrapSecretDigest(installation, bootstrap, secret string) (artifact.Digest, error)
}
