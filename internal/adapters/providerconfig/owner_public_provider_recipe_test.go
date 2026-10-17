package providerconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"github.com/google/uuid"
)

// ADR-182: the public recipe is pure, separately versioned from the identity
// recipe, bound to it, and changes with every public provider target.
func TestOwnerPublicProviderRecipeIsBoundAndSeparate(t *testing.T) {
	now := time.Now()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	roots := [][]byte{der}
	in := contracts.OwnerDeployment{Format: contracts.OwnerDeploymentFormat, InstallationID: uuid.NewString(), ClusterID: uuid.NewString(), Namespace: contracts.WorkerObjectReference{Name: "original-hub", UID: uuid.NewString()}, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: "https://kubernetes.invalid", Roots: roots}, Postgres: contracts.OwnerPostgresEndpoint{Host: "postgres.invalid", Port: 5432, Database: "asservat", Roots: roots, MaxConnections: 1}, AuditStore: contracts.OwnerAuditStore{Endpoint: "https://audit.invalid", Roots: roots, Bucket: "audit", Region: "test"}, KeyService: contracts.OwnerKeyService{Endpoint: "https://keys.invalid", Roots: roots, AuditMount: "transit", AuditKey: "audit", PKIMount: "pki", ServerRole: "server", ClientRole: "client"}}
	account := contracts.WorkerObjectReference{Name: "owner", UID: uuid.NewString()}
	identity, err := OwnerProviderRecipeFor(in, "owner-auth", "auth_kubernetes_original", account, contracts.WorkerObjectReference{Name: "audit", UID: uuid.NewString()}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = OwnerPublicProviderRecipeFor(in, identity.Profile, now); err == nil {
		t.Fatal("public recipe without a Public section")
	}
	in.Public = &contracts.OwnerPublicDeployment{SessionTransit: contracts.OwnerPublicTransit{Mount: "browser-transit", Key: "sessions"}, WorkSigning: contracts.OwnerPublicSigning{Mount: "work-transit", Name: "work"}, WorkerPKI: contracts.OwnerPublicWorkerPKI{Mount: "worker-pki", Role: "worker"}}
	roles, digest, err := OwnerPublicProviderRecipeFor(in, identity.Profile, now)
	if err != nil || len(digest) != 64 {
		t.Fatal("public recipe", err)
	}
	for i, r := range roles {
		if r.Purpose != OwnerPublicProviderPurposes[i] || !strings.HasPrefix(r.Name, "asservat-owner-public-") || len(r.Name) > 128 {
			t.Fatal("public role", r.Purpose, r.Name)
		}
		for _, owned := range identity.Roles {
			if owned.Name == r.Name {
				t.Fatal("public role reuses an identity role", r.Name)
			}
		}
	}
	if !strings.Contains(string(roles[2].Policy), "work-transit/sign/work") || !strings.Contains(string(roles[3].Policy), "worker-pki/sign/worker") {
		t.Fatal("public purpose paths")
	}
	in.Public.ProviderRecipeSHA256 = digest
	if ValidateOwnerPublicProviderRecipe(in, identity.Profile, now) != nil {
		t.Fatal("exact public recipe refused")
	}
	again, err := OwnerProviderRecipeFor(in, "owner-auth", "auth_kubernetes_original", account, identity.Profile.AuditCredentials, now)
	if err != nil || again.Profile != identity.Profile {
		t.Fatal("public section changed the identity recipe")
	}
	changed := *in.Public
	changed.WorkerPKI.Role = "other"
	in.Public = &changed
	if ValidateOwnerPublicProviderRecipe(in, identity.Profile, now) == nil {
		t.Fatal("changed worker PKI role kept the public recipe")
	}
	foreign := identity.Profile
	foreign.RecipeSHA256 = strings.Repeat("0", 64)
	if _, _, err = OwnerPublicProviderRecipeFor(in, foreign, now); err == nil {
		t.Fatal("public recipe over a foreign identity recipe")
	}
}
