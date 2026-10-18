package providerconfig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
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
		{contracts.OwnerPublicTransit{}, "250e2db6ad380be5398c3e12ef7ad6d5d834df96b967d916912cf50ba16033a0", "d1401d769753873e1f8f38e1f9eb7c2c57b0c6c9eda019c6611ad130de8c2e53",
			"a59d7b4e1b685f7feda1a6519ef5d69429408d5fa7d8ffcba87e78261dcab321", "6daa32e89be933cf4b688d462ef47bd696289c84054af28d86f8f8be30af68fd", "cb27e075e4e18c0fbe5e659f087c94d2d45e4abacc112c95947634a29c60e48b"},
		{contracts.OwnerPublicTransit{Mount: "audit", Key: contracts.WorkerConfigurationAuditKeyName(in.InstallationID)}, "ebe401670c853087478ded250b2a05d0518ab927a78068e9c34a589bc2989b19", "3ad93dc2d52ed0ff2370514826bf5e5ef6054a75c7befc667354928525937123",
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
		b, err := ConfigurationProviderPairSetupArtifact(in, s, account, contracts.HubWorkerProviderInstalledLayout, now)
		if err != nil || hexSHA256(b) != c.v3 || bytes.Contains(b, []byte("context-deletion")) || bytes.Contains(b, []byte("/sign/")) {
			t.Fatal("installed artifact changed without a deletion signing key", err)
		}
		b, err = ConfigurationProviderSetupArtifact(in, s, account, now)
		if c.legacy != "" && (err != nil || hexSHA256(b) != c.legacy) || c.legacy == "" && err == nil {
			t.Fatal("legacy artifact changed without a deletion signing key", err)
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

func TestConfigurationPairArtifactCreatesDeletionSigningKeyAndPrefix(t *testing.T) {
	in, selection, account, now := configurationProviderRecipeFixture(t)
	signing := deletionSigningFixture(in.InstallationID)
	for _, worker := range []contracts.OwnerPublicTransit{{}, workerAuditFixture} {
		s := selection
		s.WorkerConfigurationAudit = worker
		before, err := ConfigurationProviderPairSetupArtifact(in, s, account, contracts.HubWorkerProviderInstalledLayout, now)
		if err != nil {
			t.Fatal(err)
		}
		s.ContextDeletionSigning = signing
		r, err := ConfigurationProviderRecipeFor(in, s, account, now)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ConfigurationProviderPairSetupArtifact(in, s, account, contracts.HubWorkerProviderInstalledLayout, now)
		if err != nil {
			t.Fatal(err)
		}
		type artifact struct {
			Apply        []configurationProviderSetupRequest `json:"apply"`
			Inspect      []string                            `json:"inspect"`
			AuditStorage struct {
				Prefixes   []string `json:"prefixes"`
				Operations []string `json:"operations"`
			} `json:"auditStorage"`
		}
		var v, old artifact
		if json.Unmarshal(b, &v) != nil || json.Unmarshal(before, &old) != nil || len(v.Apply) != len(old.Apply)+1 {
			t.Fatal("artifact shape", len(v.Apply), len(old.Apply))
		}
		var policy struct {
			Policy string `json:"policy"`
		}
		if json.Unmarshal(v.Apply[0].Body, &policy) != nil || policy.Policy != string(r.Roles[0].Policy) || !bytes.Equal(v.Apply[2].Body, old.Apply[2].Body) {
			t.Fatal("artifact policies are not the extended recipe")
		}
		key := v.Apply[len(v.Apply)-1]
		body, err := ownerProviderCanonical(configurationSigningKey)
		if err != nil || key.Method != "POST" || key.Path != "audit/keys/"+signing.Key || !bytes.Equal(key.Body, body) || !strings.Contains(string(body), `"type":"ed25519"`) || !strings.Contains(string(body), `"exportable":false`) || !strings.Contains(string(body), `"allow_plaintext_backup":false`) {
			t.Fatal("deletion signing key is not created exactly", key.Path, string(key.Body))
		}
		if !slices.Equal(v.Inspect, append(old.Inspect, "audit/keys/"+signing.Key)) {
			t.Fatal("inspection does not name the deletion signing key", v.Inspect)
		}
		if !slices.Equal(v.AuditStorage.Prefixes, append(old.AuditStorage.Prefixes, "context-deletion/v1/")) || !slices.Equal(v.AuditStorage.Operations, old.AuditStorage.Operations) {
			t.Fatal("audit storage lacks the context deletion prefix", v.AuditStorage.Prefixes)
		}
		for _, request := range v.Apply {
			if !setupApplyPath(request.Path) {
				t.Fatal("applier refuses", request.Path)
			}
		}
		if _, err := setupInspectionPolicy(v.Inspect); err != nil {
			t.Fatal("inspection policy", err)
		}
	}
	s := selection
	s.ContextDeletionSigning = signing
	if _, err := ConfigurationProviderSetupArtifact(in, s, account, now); err == nil {
		t.Fatal("legacy artifact accepted a deletion signing key")
	}
	r, err := ConfigurationProviderRecipeFor(in, s, account, now)
	if err != nil {
		t.Fatal(err)
	}
	in.ProviderAuthentication = &r.Profile
	in.ProviderInputs = &contracts.ConfigurationWorkerInputProvenance{OperationID: "70000000-0000-4000-8000-000000000001"}
	in.Activation = &contracts.HubWorkerRuntimeActivation{WorkerLayout: contracts.HubWorkerProviderInstalledLayout}
	if _, err := ConfigurationProviderInstalledSetupArtifact(in, s, account, now); err != nil {
		t.Fatal("installed artifact", err)
	}
	if _, err := ConfigurationProviderInstalledSetupArtifact(in, selection, account, now); err == nil {
		t.Fatal("installed artifact dropped the profile's deletion signing key")
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

func configurationDeletionSigningSetupFixture(t *testing.T, worker contracts.OwnerPublicTransit, keys map[int]ed25519.PublicKey, latest int) (*setupFixture, contracts.HubWorkerDeployment, ConfigurationProviderRecipe) {
	t.Helper()
	f, in, base := configurationSetupFixture(t)
	signing := deletionSigningFixture(in.InstallationID)
	selection := contracts.ConfigurationProviderSelection{AuthMount: base.Profile.AuthMount, AuthMountAccessor: base.Profile.AuthMountAccessor, AuditCredentials: base.Profile.AuditCredentials, WorkerConfigurationAudit: worker, ContextDeletionSigning: signing}
	recipe, err := ConfigurationProviderRecipeFor(in, selection, base.Profile.ServiceAccount, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range recipe.Roles {
		f.responses["sys/policies/acl/"+role.Name] = setupMap(t, map[string]any{"name": role.Name, "policy": string(role.Policy)})
	}
	if worker != (contracts.OwnerPublicTransit{}) {
		f.responses[worker.Mount+"/keys/"+worker.Key] = setupMap(t, map[string]any{
			"name": worker.Key, "type": "aes256-gcm96", "derived": false, "exportable": false,
			"allow_plaintext_backup": false, "deletion_allowed": false, "supports_encryption": true, "supports_decryption": true,
			"latest_version": 1, "min_decryption_version": 1, "min_encryption_version": 0,
		})
	}
	f.responses[signing.Mount+"/keys/"+signing.Key] = signingKeyResponse(t, signing.Key, latest, keys)
	return f, in, recipe
}

func TestConfigurationSetupRecordsDeletionSigningPublicKeys(t *testing.T) {
	first, _, _ := ed25519.GenerateKey(nil)
	second, _, _ := ed25519.GenerateKey(nil)
	for _, worker := range []contracts.OwnerPublicTransit{{}, workerAuditFixture} {
		f, in, recipe := configurationDeletionSigningSetupFixture(t, worker, map[int]ed25519.PublicKey{1: first, 2: second}, 2)
		reads := int32(9)
		if worker != (contracts.OwnerPublicTransit{}) {
			reads = 10
		}
		check, err := f.reader.VerifyConfiguration(context.Background(), in, recipe.Profile)
		if err != nil || !check.Matches(in, recipe.Profile, time.Now()) || f.requests.Load() != reads {
			t.Fatal("deletion signing readback failed", err, f.requests.Load())
		}
		got, ok := check.ContextDeletionSigning()
		if !ok || got.Mount != "audit" || got.Key != contracts.ContextDeletionSigningKeyName(in.InstallationID) || got.Version != 2 || len(got.PublicKeys) != 2 || !bytes.Equal(got.PublicKeys[1], first) || !bytes.Equal(got.PublicKeys[2], second) {
			t.Fatal("readback did not record the signing key's versions", got)
		}
		got.PublicKeys[2][0] ^= 1
		delete(got.PublicKeys, 1)
		if again, _ := check.ContextDeletionSigning(); len(again.PublicKeys) != 2 || !bytes.Equal(again.PublicKeys[2], second) {
			t.Fatal("readback shares its observed keys")
		}
	}
	// Without the key, the readback makes exactly the earlier requests and
	// records nothing.
	f, in, recipe := configurationSetupFixture(t)
	check, err := f.reader.VerifyConfiguration(context.Background(), in, recipe.Profile)
	if err != nil || f.requests.Load() != 8 {
		t.Fatal("base readback changed", err, f.requests.Load())
	}
	if _, ok := check.ContextDeletionSigning(); ok {
		t.Fatal("base readback recorded a deletion signing key")
	}
	for _, mode := range []string{"base-policy", "aes-key", "exportable", "deletable", "other-name", "latest-missing", "future-version", "zero-version", "short-key", "bad-base64", "too-many", "missing-key"} {
		t.Run(mode, func(t *testing.T) {
			keys, latest := map[int]ed25519.PublicKey{1: first}, 1
			switch mode {
			case "latest-missing":
				latest = 2
			case "future-version":
				keys[2] = second
			case "zero-version":
				keys[0] = second
			case "short-key":
				keys[1] = first[:16]
			case "too-many":
				latest = 33
				for v := 1; v <= 33; v++ {
					keys[v] = first
				}
			}
			f, in, recipe := configurationDeletionSigningSetupFixture(t, contracts.OwnerPublicTransit{}, keys, latest)
			signing := recipe.Profile.ContextDeletionSigning
			key := f.responses[signing.Mount+"/keys/"+signing.Key]
			switch mode {
			case "base-policy":
				// A provider still holding audit-wrap's policy without the sign path.
				p := recipe.Profile
				base, err := ConfigurationProviderRecipeFor(in, contracts.ConfigurationProviderSelection{AuthMount: p.AuthMount, AuthMountAccessor: p.AuthMountAccessor, AuditCredentials: p.AuditCredentials}, p.ServiceAccount, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				f.responses["sys/policies/acl/"+base.Roles[0].Name] = setupMap(t, map[string]any{"name": base.Roles[0].Name, "policy": string(base.Roles[0].Policy)})
			case "aes-key":
				key["type"] = json.RawMessage(`"aes256-gcm96"`)
			case "exportable":
				key["exportable"] = json.RawMessage(`true`)
			case "deletable":
				key["deletion_allowed"] = json.RawMessage(`true`)
			case "other-name":
				key["name"] = json.RawMessage(`"configuration"`)
			case "bad-base64":
				key["keys"] = json.RawMessage(`{"1":{"public_key":"not base64!"}}`)
			case "missing-key":
				f.intercept = func(w http.ResponseWriter, r *http.Request) bool {
					if r.URL.Path != "/v1/"+signing.Mount+"/keys/"+signing.Key {
						return false
					}
					w.WriteHeader(http.StatusNotFound)
					return true
				}
			}
			check, err := f.reader.VerifyConfiguration(context.Background(), in, recipe.Profile)
			component := setupComponentError("context deletion signing key")
			if mode == "base-policy" {
				component = "configuration purpose policy"
			}
			if !errors.Is(err, ErrSetupUnavailable) || err != error(component) || check != (ConfigurationSetupCheck{}) {
				t.Fatal("changed deletion signing setup accepted", err)
			}
		})
	}
}
