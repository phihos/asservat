package providerconfig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

// ADR-205 decision 6: the hub-worker signs context deletion records with an
// Ed25519 Transit key through its audit-wrap purpose.

// deterministicConfigurationFixture is configurationProviderRecipeFixture with
// a fixed time and a deterministic Ed25519 root, so that recipe and artifact
// bytes can be pinned across changes.
func deterministicConfigurationFixture(t *testing.T) (contracts.HubWorkerDeployment, contracts.ConfigurationProviderSelection, contracts.WorkerObjectReference, time.Time) {
	t.Helper()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	cert := &x509.Certificate{SerialNumber: big.NewInt(205), NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(nil, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	roots := [][]byte{der}
	id := func(n string) string { return "10000000-0000-4000-8000-00000000000" + n }
	prefix := "asservat-" + strings.ReplaceAll(id("1"), "-", "")
	in := contracts.HubWorkerDeployment{Format: contracts.HubWorkerDeploymentFormat, InstallationID: id("1"), ClusterID: id("2"),
		Namespace:   contracts.WorkerObjectReference{Name: "original-hub", UID: id("3")},
		FleetSource: contracts.WorkerObjectReference{Name: "fleet", UID: id("4")}, OwnerSource: contracts.WorkerObjectReference{Name: prefix + "-owner-source", UID: id("5")},
		Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: "https://kubernetes.example", Roots: roots},
		Postgres:   contracts.OwnerPostgresEndpoint{Host: "database.example", Port: 5432, Database: "asservat", MaxConnections: 1, Roots: roots},
		AuditStore: contracts.OwnerAuditStore{Endpoint: "https://audit.example", Region: "test", Bucket: "audit", Roots: roots},
		KeyService: contracts.ConfigurationKeyService{Endpoint: "https://bao.example", Roots: roots, AuditMount: "audit", AuditKey: "configuration"}}
	selection := contracts.ConfigurationProviderSelection{AuthMount: "configuration-auth", AuthMountAccessor: "auth_kubernetes_original", AuditCredentials: contracts.WorkerObjectReference{Name: prefix + "-worker-providers", UID: id("6")}}
	return in, selection, contracts.WorkerObjectReference{Name: prefix + "-worker", UID: id("7")}, now
}

func hexSHA256(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func deletionSigningFixture(installation string) contracts.OwnerPublicTransit {
	return contracts.OwnerPublicTransit{Mount: "audit", Key: contracts.ContextDeletionSigningKeyName(installation)}
}

// Without the signing key, the recipe digest, both policies and both setup
// artifacts are byte-for-byte the values computed before ADR-205 (pinned
// from the parent commit with this deterministic fixture), with and without
// the ADR-204 worker configuration audit key.
func TestConfigurationProviderBytesUnchangedWithoutDeletionSigning(t *testing.T) {
	in, selection, account, now := deterministicConfigurationFixture(t)
	for _, c := range []struct {
		worker                   contracts.OwnerPublicTransit
		recipe, wrap, unwrap, v3 string
		legacy                   string
	}{
		{contracts.OwnerPublicTransit{}, "1abf528a464dbe78eba2cfa99947178aa89a09f9161c39b3ed9fbe8083b743ba", "d1401d769753873e1f8f38e1f9eb7c2c57b0c6c9eda019c6611ad130de8c2e53",
			"a59d7b4e1b685f7feda1a6519ef5d69429408d5fa7d8ffcba87e78261dcab321", "6daa32e89be933cf4b688d462ef47bd696289c84054af28d86f8f8be30af68fd", "cb27e075e4e18c0fbe5e659f087c94d2d45e4abacc112c95947634a29c60e48b"},
		{contracts.OwnerPublicTransit{Mount: "audit", Key: contracts.WorkerConfigurationAuditKeyName(in.InstallationID)}, "b409af1f2640cf9dac267610ea477f53605c675dbf9b87c654d9ded9645a706a", "3ad93dc2d52ed0ff2370514826bf5e5ef6054a75c7befc667354928525937123",
			"8396b514558c1c2f12dc8956a84cb599f1a29034e5b57a7fda946430d6651d5b", "45927f7dece3408f284d2364f35c3ab32f503c2c215a17cafd6df88fb4d7d5c0", ""},
	} {
		s := selection
		s.WorkerConfigurationAudit = c.worker
		r, err := ConfigurationProviderRecipeFor(in, s, account, now)
		if err != nil {
			t.Fatal(err)
		}
		if r.Profile.RecipeSHA256 != c.recipe || hexSHA256(r.Roles[0].Policy) != c.wrap || hexSHA256(r.Roles[1].Policy) != c.unwrap {
			t.Fatal("recipe or policy changed without a deletion signing key", c.worker.Key)
		}
		raw, err := json.Marshal(r.Profile)
		if err != nil || bytes.Contains(raw, []byte("contextDeletionSigning")) {
			t.Fatal("zero deletion signing key serialized")
		}
	}
}

func TestConfigurationProviderRecipeLetsOnlyAuditWrapSignDeletions(t *testing.T) {
	in, selection, account, now := configurationProviderRecipeFixture(t)
	signing := deletionSigningFixture(in.InstallationID)
	for _, worker := range []contracts.OwnerPublicTransit{{}, workerAuditFixture} {
		s := selection
		s.WorkerConfigurationAudit = worker
		base, err := ConfigurationProviderRecipeFor(in, s, account, now)
		if err != nil {
			t.Fatal(err)
		}
		s.ContextDeletionSigning = signing
		r, err := ConfigurationProviderRecipeFor(in, s, account, now)
		if err != nil || ValidateConfigurationProviderAuthentication(in, r.Profile, now) != nil || r.Profile.ContextDeletionSigning != signing || r.Profile.WorkerConfigurationAudit != worker {
			t.Fatal("recipe with a deletion signing key failed", err)
		}
		if r.Profile.RecipeSHA256 == base.Profile.RecipeSHA256 {
			t.Fatal("digest does not bind the deletion signing key")
		}
		for i := range r.Roles {
			if r.Roles[i].Name != base.Roles[i].Name || !bytes.Equal(r.Roles[i].Role, base.Roles[i].Role) {
				t.Fatal("deletion signing changed a login")
			}
		}
		// audit-wrap gains exactly the sign path; audit-unwrap is unchanged.
		want := append(configurationPolicyPaths(t, base.Roles[0]), "audit/sign/"+signing.Key)
		slices.Sort(want)
		if got := configurationPolicyPaths(t, r.Roles[0]); !slices.Equal(got, want) {
			t.Fatal("audit-wrap policy is not its base plus the sign path", got)
		}
		if !bytes.Equal(r.Roles[1].Policy, base.Roles[1].Policy) {
			t.Fatal("audit-unwrap gained a deletion signing path")
		}
		for name, change := range map[string]func(*contracts.ConfigurationProviderAuthentication){
			"added": func(p *contracts.ConfigurationProviderAuthentication) {
				*p = base.Profile
				p.ContextDeletionSigning = signing
			},
			"removed": func(p *contracts.ConfigurationProviderAuthentication) {
				p.ContextDeletionSigning = contracts.OwnerPublicTransit{}
			},
			"key":   func(p *contracts.ConfigurationProviderAuthentication) { p.ContextDeletionSigning.Key = "other" },
			"mount": func(p *contracts.ConfigurationProviderAuthentication) { p.ContextDeletionSigning.Mount = "other" },
		} {
			p := r.Profile
			change(&p)
			if ValidateConfigurationProviderAuthentication(in, p, now) == nil {
				t.Fatal("profile accepted with a changed deletion signing key", name)
			}
		}
	}
	for name, s := range map[string]contracts.ConfigurationProviderSelection{
		"configuration-key": {ContextDeletionSigning: contracts.OwnerPublicTransit{Mount: in.KeyService.AuditMount, Key: in.KeyService.AuditKey}},
		"other-name":        {ContextDeletionSigning: contracts.OwnerPublicTransit{Mount: "audit", Key: "deletion"}},
		"other-mount":       {ContextDeletionSigning: contracts.OwnerPublicTransit{Mount: "other-audit", Key: signing.Key}},
		"mount-only":        {ContextDeletionSigning: contracts.OwnerPublicTransit{Mount: "audit"}},
		"key-only":          {ContextDeletionSigning: contracts.OwnerPublicTransit{Key: signing.Key}},
		"sys":               {ContextDeletionSigning: contracts.OwnerPublicTransit{Mount: "sys", Key: signing.Key}},
		"worker-key":        {WorkerConfigurationAudit: signing, ContextDeletionSigning: signing},
	} {
		s.AuthMount, s.AuthMountAccessor, s.AuditCredentials = selection.AuthMount, selection.AuthMountAccessor, selection.AuditCredentials
		if _, err := ConfigurationProviderRecipeFor(in, s, account, now); err == nil {
			t.Fatal("invalid deletion signing key accepted", name)
		}
	}
}

// signingKeyResponse is Transit's read of an Ed25519 key with the given
// public keys by version.
func signingKeyResponse(t *testing.T, name string, latest int, keys map[int]ed25519.PublicKey) map[string]json.RawMessage {
	t.Helper()
	versions := map[string]any{}
	for v, k := range keys {
		versions[strconv.Itoa(v)] = map[string]any{"name": "ed25519", "public_key": base64.StdEncoding.EncodeToString(k), "creation_time": "2026-10-18T00:00:00Z", "certificate_chain": ""}
	}
	return setupMap(t, map[string]any{"name": name, "type": "ed25519", "derived": false, "exportable": false, "allow_plaintext_backup": false, "deletion_allowed": false,
		"supports_signing": true, "supports_encryption": false, "supports_decryption": false, "latest_version": latest, "min_decryption_version": 1, "min_encryption_version": 0, "keys": versions})
}
