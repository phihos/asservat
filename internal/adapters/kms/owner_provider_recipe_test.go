package kms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func ownerProviderRecipeInput(t *testing.T) (contracts.OwnerDeployment, contracts.WorkerObjectReference, contracts.WorkerObjectReference, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(9701), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if e != nil {
		t.Fatal(e)
	}
	roots := [][]byte{der}
	in := contracts.OwnerDeployment{Format: contracts.OwnerDeploymentFormat, InstallationID: "10000000-0000-4000-8000-000000000001", ClusterID: "10000000-0000-4000-8000-000000000002", Namespace: contracts.WorkerObjectReference{Name: "original-hub", UID: "10000000-0000-4000-8000-000000000003"}, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: "https://kubernetes.example", Roots: roots}, Postgres: contracts.OwnerPostgresEndpoint{Host: "database.example", Port: 5432, Database: "asservat", Roots: roots, MaxConnections: 1}, AuditStore: contracts.OwnerAuditStore{Endpoint: "https://audit.example", Roots: roots, Bucket: "audit", Region: "test"}, KeyService: contracts.OwnerKeyService{Endpoint: "https://bao.example", Roots: roots, AuditMount: "audit", AuditKey: "owner", PKIMount: "owner-pki", ServerRole: "server", ClientRole: "client"}}
	account := contracts.WorkerObjectReference{Name: "original-owner", UID: "10000000-0000-4000-8000-000000000004"}
	secret := contracts.WorkerObjectReference{Name: "selected-audit", UID: "10000000-0000-4000-8000-000000000005"}
	return in, account, secret, now
}

func TestOwnerProviderRecipeHasOnlyFourSeparatedEffects(t *testing.T) {
	in, account, secret, now := ownerProviderRecipeInput(t)
	r, e := OwnerProviderRecipeFor(in, "owner-auth", "auth_kubernetes_original", account, secret, now)
	if e != nil || ValidateOwnerProviderAuthentication(in, r.Profile, now) != nil {
		t.Fatal("public recipe", e)
	}
	want := []string{"audit/encrypt/owner", "audit/decrypt/owner", "owner-pki/sign/server", "owner-pki/sign/client"}
	seen := map[string]bool{}
	for i, entry := range r.Roles {
		if seen[entry.Name] || len(entry.Name) > 128 || !keyName.MatchString(entry.Name) {
			t.Fatal("purpose name overlaps or cannot be installed")
		}
		seen[entry.Name] = true
		var policy initialACL
		if json.Unmarshal(entry.Policy, &policy) != nil || len(policy.Path) != 4 {
			t.Fatal("unexpected provider effect/inspection privilege", string(entry.Policy))
		}
		for path, capability := range map[string]string{"auth/token/lookup-self": "read", "auth/token/renew-self": "update", "auth/token/revoke-self": "update", want[i]: "update"} {
			if !reflect.DeepEqual(policy.Path[path].Capabilities, []string{capability}) {
				t.Fatal("missing exact purpose path", entry.Purpose, path)
			}
		}
		var role ownerKubernetesAuthRole
		if json.Unmarshal(entry.Role, &role) != nil || !reflect.DeepEqual(role.Accounts, []string{account.Name}) || !reflect.DeepEqual(role.Namespaces, []string{in.Namespace.Name}) || role.NamespaceSelector != "" || role.Audience != "https://asservat."+in.InstallationID+"/owner-provider/"+in.ClusterID || role.AliasSource != "serviceaccount_uid" || !role.NoDefault || role.Type != "service" || role.TTL != 300 || role.MaxTTL != 900 || role.ExplicitMaxTTL != 900 || role.Period != 0 || role.Uses != 0 || len(role.BoundCIDRs) != 0 || !reflect.DeepEqual(role.Policies, []string{entry.Name}) {
			t.Fatal("role can widen identity, policies or lifetime", entry.Purpose)
		}
	}
	// Mutating one returned recipe cannot alter another call or input snapshot.
	r.Roles[0].Policy[0] = '!'
	again, e := OwnerProviderRecipeFor(in, "owner-auth", "auth_kubernetes_original", account, secret, now)
	if e != nil || again.Profile != r.Profile || again.Roles[0].Policy[0] != '{' {
		t.Fatal("recipe shares mutable returned state", e)
	}
}

func TestOwnerProviderRecipePinsPublicIdentitiesAndEndpointScope(t *testing.T) {
	in, account, secret, now := ownerProviderRecipeInput(t)
	r, e := OwnerProviderRecipeFor(in, "owner-auth", "auth_kubernetes_original", account, secret, now)
	if e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*contracts.OwnerDeployment, *contracts.OwnerProviderAuthentication){
		"installation": func(v *contracts.OwnerDeployment, _ *contracts.OwnerProviderAuthentication) {
			v.InstallationID = "20000000-0000-4000-8000-000000000001"
		},
		"cluster": func(v *contracts.OwnerDeployment, _ *contracts.OwnerProviderAuthentication) {
			v.ClusterID = "20000000-0000-4000-8000-000000000002"
		},
		"namespace-uid": func(v *contracts.OwnerDeployment, _ *contracts.OwnerProviderAuthentication) {
			v.Namespace.UID = "20000000-0000-4000-8000-000000000003"
		},
		"namespace-name": func(v *contracts.OwnerDeployment, _ *contracts.OwnerProviderAuthentication) {
			v.Namespace.Name = "other"
		},
		"kubernetes": func(v *contracts.OwnerDeployment, _ *contracts.OwnerProviderAuthentication) {
			v.Kubernetes.Endpoint = "https://other-api.example"
		},
		"bao": func(v *contracts.OwnerDeployment, _ *contracts.OwnerProviderAuthentication) {
			v.KeyService.Endpoint = "https://other-bao.example"
		},
		"transit-key": func(v *contracts.OwnerDeployment, _ *contracts.OwnerProviderAuthentication) {
			v.KeyService.AuditKey = "other"
		},
		"server-role": func(v *contracts.OwnerDeployment, _ *contracts.OwnerProviderAuthentication) {
			v.KeyService.ServerRole = "other"
		},
		"store": func(v *contracts.OwnerDeployment, _ *contracts.OwnerProviderAuthentication) {
			v.AuditStore.Endpoint = "https://other-store.example"
		},
		"bucket": func(v *contracts.OwnerDeployment, _ *contracts.OwnerProviderAuthentication) {
			v.AuditStore.Bucket = "other"
		},
		"mount": func(_ *contracts.OwnerDeployment, p *contracts.OwnerProviderAuthentication) {
			p.AuthMount = "other-auth"
		},
		"mount-replaced": func(_ *contracts.OwnerDeployment, p *contracts.OwnerProviderAuthentication) {
			p.AuthMountAccessor = "auth_kubernetes_other"
		},
		"account-recreated": func(_ *contracts.OwnerDeployment, p *contracts.OwnerProviderAuthentication) {
			p.ServiceAccount.UID = "20000000-0000-4000-8000-000000000004"
		},
		"audit-secret-replaced": func(_ *contracts.OwnerDeployment, p *contracts.OwnerProviderAuthentication) {
			p.AuditCredentials.UID = "20000000-0000-4000-8000-000000000005"
		},
		"zero-digest": func(_ *contracts.OwnerDeployment, p *contracts.OwnerProviderAuthentication) {
			p.RecipeSHA256 = strings.Repeat("0", 64)
		},
		"uppercase-digest": func(_ *contracts.OwnerDeployment, p *contracts.OwnerProviderAuthentication) {
			p.RecipeSHA256 = strings.ToUpper(p.RecipeSHA256)
		},
		"format": func(_ *contracts.OwnerDeployment, p *contracts.OwnerProviderAuthentication) {
			p.Format = "another-profile"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed, p := in, r.Profile
			change(&changed, &p)
			if ValidateOwnerProviderAuthentication(changed, p, now) == nil {
				t.Fatal("original recipe authorized changed public scope")
			}
		})
	}
	if ValidateOwnerProviderAuthentication(in, r.Profile, now.Add(2*time.Hour)) == nil {
		t.Fatal("expired provider root accepted")
	}
}

func TestOwnerProviderRecipeRejectsUnsafeInputBeforeGeneration(t *testing.T) {
	in, account, secret, now := ownerProviderRecipeInput(t)
	for name, change := range map[string]func(*contracts.OwnerDeployment, *string, *string, *contracts.WorkerObjectReference, *contracts.WorkerObjectReference){
		"wildcard-account":    func(_ *contracts.OwnerDeployment, _, _ *string, a, _ *contracts.WorkerObjectReference) { a.Name = "*" },
		"missing-account-uid": func(_ *contracts.OwnerDeployment, _, _ *string, a, _ *contracts.WorkerObjectReference) { a.UID = "" },
		"same-object-uid":     func(_ *contracts.OwnerDeployment, _, _ *string, a, s *contracts.WorkerObjectReference) { s.UID = a.UID },
		"missing-secret":      func(_ *contracts.OwnerDeployment, _, _ *string, _, s *contracts.WorkerObjectReference) { s.Name = "" },
		"auth-path":           func(_ *contracts.OwnerDeployment, m, _ *string, _, _ *contracts.WorkerObjectReference) { *m = "a/b" },
		"token-auth":          func(_ *contracts.OwnerDeployment, m, _ *string, _, _ *contracts.WorkerObjectReference) { *m = "token" },
		"missing-accessor":    func(_ *contracts.OwnerDeployment, _, a *string, _, _ *contracts.WorkerObjectReference) { *a = "" },
		"same-pki-role": func(v *contracts.OwnerDeployment, _, _ *string, _, _ *contracts.WorkerObjectReference) {
			v.KeyService.ClientRole = v.KeyService.ServerRole
		},
		"same-engine": func(v *contracts.OwnerDeployment, _, _ *string, _, _ *contracts.WorkerObjectReference) {
			v.KeyService.PKIMount = v.KeyService.AuditMount
		},
		"wildcard-key": func(v *contracts.OwnerDeployment, _, _ *string, _, _ *contracts.WorkerObjectReference) {
			v.KeyService.AuditKey = "*"
		},
		"plaintext": func(v *contracts.OwnerDeployment, _, _ *string, _, _ *contracts.WorkerObjectReference) {
			v.KeyService.Endpoint = "http://bao.example"
		},
	} {
		t.Run(name, func(t *testing.T) {
			v, m, accessor, a, s := in, "owner-auth", "auth_kubernetes_original", account, secret
			change(&v, &m, &accessor, &a, &s)
			if _, e := OwnerProviderRecipeFor(v, m, accessor, a, s, now); e == nil {
				t.Fatal("unsafe selected provider recipe generated")
			}
		})
	}
}

// Provider policy names are global within a mount/provider namespace; one
// control cluster may contain more than one independently protected owner.
func TestOwnerProviderRecipeNamesSeparateCompleteOriginalScopes(t *testing.T) {
	in, account, secret, now := ownerProviderRecipeInput(t)
	original, e := OwnerProviderRecipeFor(in, "owner-auth", "auth_kubernetes_original", account, secret, now)
	if e != nil {
		t.Fatal(e)
	}
	for name, change := range map[string]func(*contracts.OwnerDeployment, *contracts.WorkerObjectReference){
		"namespace": func(v *contracts.OwnerDeployment, _ *contracts.WorkerObjectReference) {
			v.Namespace = contracts.WorkerObjectReference{Name: "another-hub", UID: "20000000-0000-4000-8000-000000000003"}
		},
		"namespace-recreated": func(v *contracts.OwnerDeployment, _ *contracts.WorkerObjectReference) {
			v.Namespace.UID = "20000000-0000-4000-8000-000000000003"
		},
		"account": func(_ *contracts.OwnerDeployment, a *contracts.WorkerObjectReference) {
			a.Name = "another-owner"
			a.UID = "20000000-0000-4000-8000-000000000004"
		},
		"account-recreated": func(_ *contracts.OwnerDeployment, a *contracts.WorkerObjectReference) {
			a.UID = "20000000-0000-4000-8000-000000000004"
		},
		"cluster": func(v *contracts.OwnerDeployment, _ *contracts.WorkerObjectReference) {
			v.ClusterID = "20000000-0000-4000-8000-000000000002"
		},
		"installation": func(v *contracts.OwnerDeployment, _ *contracts.WorkerObjectReference) {
			v.InstallationID = "20000000-0000-4000-8000-000000000001"
		},
	} {
		t.Run(name, func(t *testing.T) {
			v, a := in, account
			change(&v, &a)
			got, e := OwnerProviderRecipeFor(v, "owner-auth", "auth_kubernetes_original", a, secret, now)
			if e != nil {
				t.Fatal(e)
			}
			for _, role := range got.Roles {
				if len(role.Name) > 128 || !keyName.MatchString(role.Name) {
					t.Fatal("scope name exceeds supported provider name", role.Name)
				}
				for _, prior := range original.Roles {
					if role.Name == prior.Name {
						t.Fatal("distinct original owner scopes collide", name, role.Purpose)
					}
				}
			}
		})
	}
}
