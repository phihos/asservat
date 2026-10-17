//go:build ignore

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// Run with the exact six helper source files named by the native harness.
// This tests the actual fixture issuer, not a copied implementation. Authority
// is synthetic; no SQL, Kubernetes, provider or native-route result is claimed.
func fixtureConnectorPermit(t *testing.T, usage string) (fixtureIssuer, value.ConnectorCredentialPermit, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	n := time.Now().UTC()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: n.Add(-time.Hour), NotAfter: n.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := mtls.EnrollmentKey(csr)
	if err != nil {
		t.Fatal(err)
	}
	const id = "44444444-4444-4444-8444-444444444444"
	binding := value.PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: value.ConnectorPeer}
	process := value.ConnectorProcessIdentity{Binding: binding, PodUID: id, ProcessEpoch: id}
	// More than two seconds have already elapsed in the ORIGINAL five-second
	// interval, as can happen before signing on the retained native limiter.
	// Do not sleep, reset the product clock or change the signing deadline.
	checked := time.Now().UTC().Truncate(time.Microsecond).Add(-3 * time.Second)
	end := checked.Add(5 * time.Second)
	profile := value.ConnectorCredentialProfile{RootID: id, Binding: binding, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{3}}, ProtectionDigest: artifact.Digest{4}, ServerName: "connector.example.invalid", Deployment: value.ConnectorDeployment{Namespace: "connector", NamespaceUID: id, ServiceAccount: "connector", AccountUID: id, Deployment: "connector", DeploymentUID: id, ServingSlots: 2, RetainedProcesses: 8}, ClientIssuerRoots: [][]byte{der}, ServerIssuerRoots: [][]byte{der}}
	configuration := value.ConnectorCredentialObservation{Backing: value.ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{31}, SourceDigest: artifact.Digest{32}}, Profile: profile, ObservedAt: checked, FreshUntil: end}
	admitted := value.ConnectorCredentialProcess{Binding: binding, Attested: &process, ClientKeyDigest: artifact.Digest{1}, ServerKeyDigest: artifact.Digest{2}, ClaimedAt: checked.Add(-time.Minute), RunUntil: checked.Add(2 * time.Hour)}
	admitted.InitialCertificateNotAfter = admitted.ClaimedAt.Add(value.ConnectorCertificatePeriod).UTC().Truncate(time.Second)
	if usage == "client" {
		admitted.ClientKeyDigest = digest
	} else {
		admitted.ServerKeyDigest = digest
	}
	proof := value.ConnectorProcessProof{Process: process, Configuration: configuration, Pod: "connector-pod", ReplicaSet: "connector-rs", ReplicaSetUID: id, ClientKeyDigest: admitted.ClientKeyDigest, ServerKeyDigest: admitted.ServerKeyDigest, TokenDigest: artifact.Digest{5}, WorkloadDigest: artifact.Digest{6}, ProtectionDigest: artifact.Digest{7}, ObservedAt: checked, FreshUntil: end}
	epoch, leafEnd, err := admitted.Window(checked)
	if err != nil {
		t.Fatal("original process window", err)
	}
	permit := value.ConnectorCredentialPermit{ID: id, Process: admitted, Usage: usage, Configuration: configuration, ProcessProof: &proof, Recovery: value.RecoveryState{InstallationID: id, IssuerEpoch: id, Revision: profile.Revision, ObservedAt: checked, FreshUntil: end}, IntentDigest: artifact.Digest{8}, Epoch: epoch, Ordinal: 1, CheckedAt: checked, SignBefore: end, CertificateNotAfter: leafEnd}
	if !permit.Valid(time.Now()) || !permit.WellFormed() || time.Since(checked) <= 2*time.Second {
		t.Fatal("aged still-live original permit setup failed")
	}
	caInput := fixtureCA{DER: der, PKCS8: private}
	return fixtureIssuer{client: caInput, server: caInput}, permit, csr
}

func TestNativeFixtureConnectorIssuerOriginalSigningInstant(t *testing.T) {
	for _, usage := range []string{"client", "server"} {
		t.Run(usage, func(t *testing.T) {
			issuer, permit, csr := fixtureConnectorPermit(t, usage)
			ctx, cancel := context.WithDeadline(context.Background(), permit.SignBefore)
			defer cancel()
			originalEnd, _ := ctx.Deadline()
			issued, err := issuer.SignConnectorCredential(ctx, permit, csr)
			if err != nil {
				t.Fatal("actual fixture signing failed before verification", err)
			}
			leaf, err := x509.ParseCertificate(issued.DER)
			if err != nil {
				t.Fatal("actual signed leaf parse", err)
			}
			verifier, err := mtls.NewConnectorCredentialVerifier(permit.Configuration.Profile, time.Now)
			if err != nil {
				t.Fatal("unchanged verifier constructor", err)
			}
			checked, verifyErr := verifier.CheckConnectorCredentialCurrent(permit, csr, issued.DER, issued.ChainDER, permit.Configuration)
			if !permit.Valid(time.Now()) || ctx.Err() != nil {
				t.Fatal("original permit expired; signing-instant regression not reached")
			}
			t.Logf("issuer original-age=%s remaining=%s leaf-after-original=%t domain-matches=%t verified=%t", time.Since(permit.CheckedAt), time.Until(originalEnd), leaf.NotBefore.After(permit.CheckedAt), permit.Matches(issued), verifyErr == nil)
			if leaf.NotBefore.After(permit.CheckedAt) || !permit.Matches(issued) || verifyErr != nil || !permit.Matches(checked) {
				t.Fatal("BEFORE-FIXTURE-ISSUER-ORIGINAL-INSTANT: delayed signing did not retain original checked instant")
			}
			if !leaf.NotBefore.Equal(permit.CheckedAt.UTC().Truncate(time.Second).Add(-time.Second)) || !leaf.NotAfter.Equal(permit.CertificateNotAfter) || !issued.Certificate.NotBefore.Equal(leaf.NotBefore) || !issued.Certificate.NotAfter.Equal(leaf.NotAfter) {
				t.Fatal("signed DER facts or original certificate interval changed")
			}
			if currentEnd, _ := ctx.Deadline(); !currentEnd.Equal(originalEnd) || !permit.SignBefore.Equal(originalEnd) {
				t.Fatal("original signing bound changed")
			}
		})
	}
}

func TestNativeFixtureConnectorIssuerStillRejectsExpiredOrCancelled(t *testing.T) {
	for _, mode := range []string{"expired", "cancelled", "wrong-key"} {
		t.Run(mode, func(t *testing.T) {
			issuer, permit, csr := fixtureConnectorPermit(t, "client")
			ctx, cancel := context.WithDeadline(context.Background(), permit.SignBefore)
			defer cancel()
			switch mode {
			case "expired":
				permit.SignBefore = time.Now().Add(-time.Microsecond)
			case "cancelled":
				cancel()
			case "wrong-key":
				permit.Process.ClientKeyDigest = artifact.Digest{23}
				permit.ProcessProof.ClientKeyDigest = permit.Process.ClientKeyDigest
			}
			out, err := issuer.SignConnectorCredential(ctx, permit, csr)
			if err == nil || len(out.DER) != 0 {
				t.Fatal("fixture issuer admitted invalid original signing attempt")
			}
		})
	}
}
