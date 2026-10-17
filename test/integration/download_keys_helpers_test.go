package integration

import (
	"asservat.local/asservat/internal/application/evidence"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
)

func localDownloadKeys(t *testing.T, installation string) (authorization.KeyScope, *kms.LocalKeyBackend, *kms.LocalOperations) {
	t.Helper()
	material := make([]byte, 32)
	if _, err := rand.Read(material); err != nil {
		t.Fatal(err)
	}
	defer clear(material)
	scope := authorization.KeyScope{InstallationID: installation, Purpose: "artifact", KeyID: "fixture"}
	payload, err := json.Marshal(map[string]any{"format": "asservat-local-keys/v1", "installationID": installation, "purpose": "artifact", "keyID": scope.KeyID, "activeVersion": 1, "keys": []any{map[string]any{"version": 1, "material": material}}})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	keys, err := kms.NewLocalKeyBackend(kms.LocalKeyScope{InstallationID: installation, Purpose: "artifact", KeyID: scope.KeyID}, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	backend, err := kms.NewLocalOperations(scope, 0, nil, bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	return scope, keys, backend
}
func keyPeerForTest(t *testing.T, f *keyTLSFixture, role string) authorization.KeyPeer {
	t.Helper()
	transport := f.clients[role].Transport.(*http.Transport)
	leaf, err := x509.ParseCertificate(transport.TLSClientConfig.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	path := strings.Split(leaf.URIs[0].Path, "/")
	return authorization.KeyPeer{InstallationID: f.scope.InstallationID, PeerID: path[3], Role: role, Certificate: artifact.Digest(sha256.Sum256(leaf.Raw)), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}
}

// Explicitly synthetic dispatch/token observations for the SQL-only suite.
// Real TokenReview/pod identity qualification is in the context fixture.
type fixtureDownloadPeerProofs struct{ Lifetime time.Duration }

func (f fixtureDownloadPeerProofs) ReadDownloadPeerProof(_ context.Context, session string, p authorization.KeyPeer) (authorization.KeyWorkerProof, error) {
	now := time.Now().UTC()
	life := f.Lifetime
	if life == 0 {
		life = 5 * time.Second
	}
	until := now.Add(life)
	if p.NotAfter.Before(until) {
		until = p.NotAfter
	}
	return authorization.KeyWorkerProof{Binding: authorization.KeyWorkerBinding{InstallationID: p.InstallationID, DownloadID: session, ClusterID: p.InstallationID, Namespace: "synthetic-workers", NamespaceUID: "fixture-namespace", ServiceAccount: "acquisition", ServiceAccountUID: "fixture-account", Job: "download", JobUID: "fixture-job", Pod: "download-pod", PodUID: p.PeerID, JobSpec: artifact.Digest{11}, PodSpec: artifact.Digest{12}}, Peer: p, TokenDigest: artifact.Digest{91}, ObservedAt: now, FreshUntil: until}, nil
}
func fixtureAttestedDownloadGrants(ledger evidence.DownloadKeyBindingLedger) *evidence.AttestedDownloadKeyGrants {
	return &evidence.AttestedDownloadKeyGrants{Proofs: fixtureDownloadPeerProofs{}, Ledger: ledger, Now: time.Now}
}
