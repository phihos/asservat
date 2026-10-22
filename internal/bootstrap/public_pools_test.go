package bootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
)

// ADR-180: Public is optional, requires Native and an exact origin, and must
// leave cold governor slots beside the owner pools.
func TestOwnerPublicInputsRequireNativeOriginAndBudget(t *testing.T) {
	for _, mode := range []string{"valid", "no-native", "origin-path", "http-origin", "format", "owner-connections", "same-settings", "audit-transit", "no-provider-roots", "browser-root", "native-port", "per-identity"} {
		t.Run(mode, func(t *testing.T) {
			in, dir, c := nativeInputFixture(t)
			c.Public = &contracts.OwnerPublicDeployment{Format: contracts.OwnerPublicDeploymentFormat, Origin: "https://asservat.example.test",
				BrowserRootID: runtimeID, BrowserSettings: contracts.WorkerObjectReference{Name: "browser-settings", UID: runtimeID}, IdentitySettings: contracts.WorkerObjectReference{Name: "identity-settings", UID: runtimeID},
				BrowserAudience: "asservat-api", ProviderRoots: c.Kubernetes.Roots, SessionTransit: contracts.OwnerPublicTransit{Mount: "browser-transit", Key: "sessions"},
				Port: 8443, Version: "v1", OperationConcurrency: 8, MCPPerIdentity: 2, DownloadConcurrency: 4, DownloadsPerIdentity: 2, DownloadMaxSeconds: 3600}
			switch mode {
			case "same-settings":
				c.Public.IdentitySettings.Name = c.Public.BrowserSettings.Name
			case "audit-transit":
				c.Public.SessionTransit.Mount = c.KeyService.AuditMount
			case "no-provider-roots":
				c.Public.ProviderRoots = nil
			case "native-port":
				c.Public.Port = contracts.OwnerInstalledNativePort
			case "per-identity":
				c.Public.DownloadsPerIdentity = c.Public.DownloadConcurrency + 1
			case "browser-root":
				c.Public.BrowserRootID = "not-a-uuid"
			case "no-native":
				c.Native = nil
			case "origin-path":
				c.Public.Origin += "/console"
			case "http-origin":
				c.Public.Origin = "http://asservat.example.test"
			case "format":
				c.Public.Format = "asservat-owner-public/v0"
			case "owner-connections":
				c.Postgres.MaxConnections = 4
			}
			writeOwnerJSON(t, dir, "deployment.json", c)
			_, e := readOwnerInputs(context.Background(), in.files)
			if (mode == "valid") != (e == nil) {
				t.Fatal("public input decision", mode, e)
			}
		})
	}
}

func publicManifestFixture(c contracts.OwnerDeployment) contracts.PublicRuntimeCredentialManifest {
	return contracts.PublicRuntimeCredentialManifest{Format: contracts.PublicRuntimeCredentialManifestFormat, Input: contracts.PublicRuntimeRoles{InstallationID: c.InstallationID, ClusterID: c.ClusterID, Namespace: c.Namespace, OwnerConfigurationUID: c.ConfigurationUID, LayoutDigest: postgres.PublicRuntimeRoleLayoutDigest()}}
}

func TestPublicRuntimeManifestBindsTheOwnerInstallation(t *testing.T) {
	in, dir, c := ownerInputFixture(t)
	ctx := context.Background()
	if _, e := readPublicRuntimeManifest(ctx, in, in.providerInputs); e == nil {
		t.Fatal("missing manifest accepted")
	}
	writeOwnerJSON(t, dir, contracts.PublicRuntimeCredentialManifestFile, publicManifestFixture(c))
	if _, e := readPublicRuntimeManifest(ctx, in, in.providerInputs); e != nil {
		t.Fatal("exact manifest", e)
	}
	foreign := publicManifestFixture(c)
	foreign.Input.OwnerConfigurationUID = "10000000-0000-4000-8000-0000000000aa"
	writeOwnerJSON(t, dir, contracts.PublicRuntimeCredentialManifestFile, foreign)
	if _, e := readPublicRuntimeManifest(ctx, in, in.providerInputs); e == nil {
		t.Fatal("manifest of another owner configuration accepted")
	}
}

// Pools refuse unknown and hub-worker purposes and another purpose's login
// before any connection; a pool that cannot prove its credential is closed.
func TestPublicPoolsOpenOnlyVerifiedOwnPurposeLogins(t *testing.T) {
	in, dir, c := ownerInputFixture(t)
	governor, e := postgres.NewSQLConnectionGovernor(contracts.SQLConnectionsPerHubReplica, len(hubAPIHotPurposes))
	if e != nil {
		t.Fatal(e)
	}
	p := &publicPools{in: in.providerInputs, manifest: publicManifestFixture(c), governor: governor}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	name, _ := postgres.PublicRuntimeRoleName(c.InstallationID, "capture-preview")
	other, _ := postgres.PublicRuntimeRoleName(c.InstallationID, "hub-metadata-read")
	for _, purpose := range []string{"unknown", "browser-settings", "browser-cleanup"} {
		writeOwnerJSON(t, dir, "sql-public-"+purpose+".json", contracts.OwnerSQLCredential{Username: name, Password: "synthetic"})
		if _, e := p.open(ctx, purpose); e == nil {
			t.Fatal("purpose outside hub-api accepted", purpose)
		}
	}
	writeOwnerJSON(t, dir, "sql-public-capture-preview.json", contracts.OwnerSQLCredential{Username: other, Password: "synthetic"})
	if _, e := p.open(ctx, "capture-preview"); e == nil {
		t.Fatal("another purpose's login accepted")
	}
	writeOwnerJSON(t, dir, "sql-public-capture-preview.json", contracts.OwnerSQLCredential{Username: name, Password: "synthetic"})
	if _, e := p.open(ctx, "capture-preview"); e == nil || len(p.pools) != 0 {
		t.Fatal("unverified credential became a pool")
	}
	p.Close()
	if _, e := p.open(ctx, "capture-preview"); e == nil {
		t.Fatal("closed pools reopened")
	}
}

// The public listener serves the mounted pair and follows a rotated file.
func TestPublicCertificateFollowsTheMountedPair(t *testing.T) {
	in, dir, _ := ownerInputFixture(t)
	c := &publicCertificate{inputs: in.providerInputs}
	if _, e := c.get(nil); e == nil {
		t.Fatal("missing pair served")
	}
	write := func(name string) *x509.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{name}}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		kb, _ := x509.MarshalECPrivateKey(key)
		if os.WriteFile(filepath.Join(dir, contracts.OwnerPublicTLSCertificate), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600) != nil || os.WriteFile(filepath.Join(dir, contracts.OwnerPublicTLSKey), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0600) != nil {
			t.Fatal("write pair")
		}
		cert, _ := x509.ParseCertificate(der)
		return cert
	}
	first := write("first.example.test")
	got, e := c.get(nil)
	if e != nil || !bytes.Equal(got.Certificate[0], first.Raw) {
		t.Fatal("first pair", e)
	}
	second := write("second.example.test")
	got, e = c.get(nil)
	if e != nil || !bytes.Equal(got.Certificate[0], second.Raw) {
		t.Fatal("rotated pair not served", e)
	}
}
