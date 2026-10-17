package providerconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"github.com/google/uuid"
)

// ADR-193 step 4: one create/read KV role under the installation prefix,
// bound to the identity recipe, pinned by digest and changed by its inputs.
func TestOwnerFleetProviderRecipeIsNarrowAndPinned(t *testing.T) {
	now := time.Now()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	roots := [][]byte{der}
	in := contracts.OwnerDeployment{Format: contracts.OwnerDeploymentFormat, InstallationID: uuid.NewString(), ClusterID: uuid.NewString(), Namespace: contracts.WorkerObjectReference{Name: "original-hub", UID: uuid.NewString()}, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: "https://kubernetes.invalid", Roots: roots}, Postgres: contracts.OwnerPostgresEndpoint{Host: "postgres.invalid", Port: 5432, Database: "asservat", Roots: roots, MaxConnections: 1}, AuditStore: contracts.OwnerAuditStore{Endpoint: "https://audit.invalid", Roots: roots, Bucket: "audit", Region: "test"}, KeyService: contracts.OwnerKeyService{Endpoint: "https://keys.invalid", Roots: roots, AuditMount: "transit", AuditKey: "audit", PKIMount: "pki", ServerRole: "server", ClientRole: "client"}}
	identity, err := OwnerProviderRecipeFor(in, "owner-auth", "auth_kubernetes_original", contracts.WorkerObjectReference{Name: "owner", UID: uuid.NewString()}, contracts.WorkerObjectReference{Name: "audit", UID: uuid.NewString()}, now)
	if err != nil {
		t.Fatal(err)
	}
	in.Public = &contracts.OwnerPublicDeployment{}
	if _, _, err = OwnerFleetProviderRecipeFor(in, identity.Profile, now); err == nil {
		t.Fatal("fleet recipe without a Fleet section")
	}
	in.Public.Fleet = &contracts.OwnerFleetIssuance{ChannelMount: "fleet-kv", DeliveryProfile: "regional-installer"}
	role, digest, err := OwnerFleetProviderRecipeFor(in, identity.Profile, now)
	if err != nil || len(digest) != 64 || role.Purpose != OwnerFleetProviderPurpose || !strings.HasPrefix(role.Name, "asservat-owner-fleet-") {
		t.Fatal("fleet recipe", err)
	}
	var acl ownerProviderACL
	if json.Unmarshal(role.Policy, &acl) != nil || len(acl.Path) != 4 {
		t.Fatal("fleet ACL shape")
	}
	rule, ok := acl.Path["fleet-kv/data/connector/"+in.InstallationID+"/*"]
	if !ok || strings.Join(rule.Capabilities, ",") != "create,read" {
		t.Fatal("fleet ACL is not create/read on the installation prefix", acl.Path)
	}
	in.Public.Fleet.ProviderRecipeSHA256 = digest
	if ValidateOwnerFleetProviderRecipe(in, identity.Profile, now) != nil {
		t.Fatal("pinned recipe refused")
	}
	in.Public.Fleet.DeliveryProfile = "other-profile"
	if ValidateOwnerFleetProviderRecipe(in, identity.Profile, now) == nil {
		t.Fatal("changed delivery profile kept the pin")
	}
	in.Public.Fleet.ChannelMount = "fleet/kv"
	if _, _, err = OwnerFleetProviderRecipeFor(in, identity.Profile, now); err == nil {
		t.Fatal("unsafe mount name accepted")
	}
}
