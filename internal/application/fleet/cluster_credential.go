package fleet

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
)

// ADR-168 signing: purpose || 0 || 32-byte TLS exporter || canonical JSON.
// Struct field order makes the JSON deterministic; the exporter binds one TLS
// connection, so a captured signature cannot be replayed on another.
func clusterCredentialMessage(r value.ClusterCredentialRequest, exporter []byte) ([]byte, error) {
	if !r.Valid() || len(exporter) != 32 {
		return nil, value.ErrClusterCredentialDenied
	}
	body, err := json.Marshal(r)
	if err != nil {
		return nil, value.ErrClusterCredentialDenied
	}
	out := append([]byte(value.ClusterCredentialPurpose), 0)
	out = append(out, exporter...)
	return append(out, body...), nil
}

func SignClusterCredentialRequest(key ed25519.PrivateKey, r value.ClusterCredentialRequest, exporter []byte) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, value.ErrClusterCredentialDenied
	}
	message, err := clusterCredentialMessage(r, exporter)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, message), nil
}

func VerifyClusterCredentialRequest(public []byte, r value.ClusterCredentialRequest, signature, exporter []byte) bool {
	message, err := clusterCredentialMessage(r, exporter)
	return err == nil && len(public) == ed25519.PublicKeySize && len(signature) == ed25519.SignatureSize && ed25519.Verify(public, message, signature)
}

func ClusterKeyDigest(public []byte) artifact.Digest {
	return sha256.Sum256(public)
}

// ClusterCredentialDecider runs inside the store's transaction, after the
// lineage row lock, with the database clock.
type ClusterCredentialDecider func(l value.ClusterCredentialLineage, signer, current *value.ClusterCredential, now time.Time) (value.ClusterDecision, error)

// ClusterCredentialStore persists decisions atomically and commits a fork
// fence before reporting it. Enrollment is the audited administrator path.
type ClusterCredentialStore interface {
	Decide(context.Context, value.ClusterCredentialRequest, ClusterCredentialDecider) (value.ClusterCredentialPresentation, error)
}

// ClusterCredentialVerifier is the hub's possession check. A presentation is
// an input to ADR-126/153 admission, never a permit by itself.
type ClusterCredentialVerifier struct {
	Store ClusterCredentialStore
}

func (v ClusterCredentialVerifier) Present(ctx context.Context, r value.ClusterCredentialRequest, signature, exporter []byte) (value.ClusterCredentialPresentation, error) {
	if v.Store == nil || ctx == nil || !r.Valid() || len(exporter) != 32 {
		return value.ClusterCredentialPresentation{}, value.ErrClusterCredentialDenied
	}
	var next artifact.Digest
	if r.Operation == value.ClusterRotation {
		next = ClusterKeyDigest(r.NextKey)
	}
	return v.Store.Decide(ctx, r, func(l value.ClusterCredentialLineage, signer, current *value.ClusterCredential, now time.Time) (value.ClusterDecision, error) {
		if signer == nil {
			return value.ClusterDecision{}, value.ErrClusterCredentialDenied
		}
		return value.DecideClusterCredential(l, signer, current, r, VerifyClusterCredentialRequest(signer.PublicKey, r, signature, exporter), next, now)
	})
}
