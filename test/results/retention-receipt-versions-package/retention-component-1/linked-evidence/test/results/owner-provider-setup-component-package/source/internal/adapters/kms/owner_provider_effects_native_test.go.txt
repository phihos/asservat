package kms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
)

// This extends only the explicitly selected native provider component fixture.
// Actual Kubernetes/Bao authenticate and perform each effect. The current
// installation proof, pool, recovery and already-spent permits are synthetic;
// this does not qualify accepted installed authority or runtime supervision.
func (f *ownerProviderNativeFixture) leasedEffects(t *testing.T) {
	t.Helper()
	rootReply := f.admin(http.MethodGet, f.input.KeyService.PKIMount+"/cert/ca", nil, 200)
	data, ok := rootReply["data"].(map[string]any)
	if !ok {
		t.Fatal("actual fixture issuer data")
	}
	rootPEM, ok := data["certificate"].(string)
	if !ok {
		t.Fatal("actual fixture issuer certificate")
	}
	block, rest := pem.Decode([]byte(rootPEM))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("actual fixture issuer PEM")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(rootPEM)) {
		t.Fatal("actual fixture issuer roots")
	}
	pool := value.OwnerPool{InstallationID: f.input.InstallationID, ClusterID: f.input.ClusterID, IssuerEpoch: uuid.NewString(), Namespace: f.namespace, NamespaceUID: f.input.Namespace.UID, Service: "owner", ServiceUID: uuid.NewString(), Deployment: "owner", DeploymentUID: uuid.NewString(), ServiceAccount: f.owner.Name, AccountUID: string(f.owner.UID), Port: 8443, NativePort: 9444, NativeBootstrap: value.OwnerBootstrapProfile}
	binding := value.OwnerBinding{InstallationID: pool.InstallationID, ClusterID: pool.ClusterID, IssuerEpoch: pool.IssuerEpoch, PodUID: string(f.pod.UID), ProcessEpoch: uuid.NewString()}
	f.setupInspection(t, pool, [][]byte{block.Bytes})
	proof := func(ctx context.Context) (time.Time, error) { return time.Now().Add(5 * time.Second), ctx.Err() }
	jwt := func(ctx context.Context) ([]byte, error) { return bytes.Clone(f.jwt), ctx.Err() }
	effects, err := newOwnerProviderEffects(f.ctx, f.input, f.recipe.Profile, pool, roots, jwt, proof, f.http, 2, time.Now)
	if err != nil {
		t.Fatal("actual provider effect composition", err)
	}
	t.Cleanup(func() {
		if e := effects.close(context.Background()); e != nil {
			t.Error("leased provider effects cleanup", e)
		}
	})
	if _, err = effects.seal.Seal(f.ctx, []byte("synthetic-keyset"), []byte("binding")); err == nil {
		t.Fatal("uninitialized native effect authenticated itself")
	}
	slots := []*ownerProviderLifetime{effects.lifetimes.auditWrap, effects.lifetimes.auditUnwrap, effects.lifetimes.serverSign, effects.lifetimes.clientSign}
	retirementTokens := make([][]byte, len(slots))
	defer func() {
		for _, token := range retirementTokens {
			clear(token)
		}
	}()
	for i, slot := range slots {
		if e := slot.refresh(f.ctx); e != nil {
			t.Fatal("actual lifetime login", i, e)
		}
		slot.mu.Lock()
		if slot.current != nil {
			retirementTokens[i] = bytes.Clone(slot.current.value.token)
		}
		slot.mu.Unlock()
		if len(retirementTokens[i]) == 0 {
			t.Fatal("missing acknowledged provider credential", i)
		}
	}
	plain, bound := []byte("synthetic-native-owner-keyset"), []byte("synthetic-original-binding")
	sealed, err := effects.seal.Seal(f.ctx, plain, bound)
	if err != nil {
		t.Fatal("leased maintained Transit encryption", err)
	}
	opened, err := effects.open.Open(f.ctx, sealed, bound)
	if err != nil || !bytes.Equal(opened, plain) {
		clear(opened)
		t.Fatal("leased maintained Transit decryption", err)
	}
	clear(opened)
	if _, err = effects.open.Open(f.ctx, sealed, []byte("changed-binding")); err == nil {
		t.Fatal("native binding mismatch accepted")
	}
	for _, entry := range []struct {
		usage  string
		issuer *OwnerCertificateIssuer
	}{{"server", effects.server}, {"client", effects.client}} {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if e != nil {
			t.Fatal(e)
		}
		keyDigest, e := mtls.EnrollmentKey(csr)
		if e != nil {
			t.Fatal(e)
		}
		now := time.Now().UTC()
		epoch, end, e := value.OwnerCertificateWindow(now)
		if e != nil {
			t.Fatal(e)
		}
		configuration := value.OwnerConfiguration{Pool: pool, Revision: identity.Revision{UID: uuid.NewString(), Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{block.Bytes}}
		permit := value.OwnerCertificatePermit{ID: uuid.NewString(), Binding: binding, Usage: entry.usage, PublicKeyDigest: keyDigest, EnrollmentAudit: artifact.Digest{3}, Configuration: value.OwnerConfigurationObservation{Configuration: configuration, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Recovery: value.RecoveryState{InstallationID: pool.InstallationID, IssuerEpoch: pool.IssuerEpoch, Revision: identity.Revision{UID: uuid.NewString(), Generation: 1, Digest: artifact.Digest{4}}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Epoch: epoch, Ordinal: 1, CheckedAt: now, SignBefore: now.Add(5 * time.Second), CertificateNotAfter: end}
		issued, e := entry.issuer.SignOwnerCertificate(f.ctx, permit, csr)
		if e != nil || !permit.Matches(issued) {
			t.Fatal("leased maintained issuer did not verify actual certificate", entry.usage, e)
		}
		if !issued.Certificate.NotAfter.Equal(end) {
			t.Fatal("provider extended certificate interval")
		}
	}
	if err = effects.close(f.ctx); err != nil {
		t.Fatal("joined native effects retirement", err)
	}
	for i, token := range retirementTokens {
		call, cancel := context.WithTimeout(f.ctx, 5*time.Second)
		r, e := http.NewRequestWithContext(call, http.MethodGet, f.input.KeyService.Endpoint+"/v1/auth/token/lookup-self", nil)
		if e != nil {
			cancel()
			t.Fatal(e)
		}
		r.Header.Set("X-Vault-Token", string(token))
		response, e := f.http.Do(r)
		if e != nil {
			cancel()
			t.Fatal("retirement lookup unavailable", i)
		}
		status := response.StatusCode
		_ = response.Body.Close()
		cancel()
		if status != http.StatusForbidden {
			t.Fatal("retired credential remains accepted", i, status)
		}
	}
	if _, err = effects.seal.Seal(f.ctx, plain, bound); err == nil {
		t.Fatal("closed effects remain usable")
	}
	t.Log("Actual leased Transit binding roundtrip, two purpose-separated verified PKI certificates and four observed self-revocations pass; installation authority remains synthetic.")
}
