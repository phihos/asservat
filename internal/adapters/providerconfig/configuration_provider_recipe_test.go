package providerconfig

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

func configurationProviderRecipeFixture(t *testing.T) (contracts.HubWorkerDeployment, contracts.ConfigurationProviderSelection, contracts.WorkerObjectReference, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1491), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, k.Public(), k)
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

func TestConfigurationProviderRecipeSeparatesExactTwoEffects(t *testing.T) {
	in, selection, account, now := configurationProviderRecipeFixture(t)
	r, err := ConfigurationProviderRecipeFor(in, selection, account, now)
	if err != nil || ValidateConfigurationProviderAuthentication(in, r.Profile, now) != nil {
		t.Fatal("valid original recipe failed", err)
	}
	for i, effect := range []string{"audit/encrypt/configuration", "audit/decrypt/configuration"} {
		entry := r.Roles[i]
		var acl ownerProviderACL
		var role OwnerKubernetesAuthRole
		if len(entry.Name) > 128 || !providerName.MatchString(entry.Name) || json.Unmarshal(entry.Policy, &acl) != nil || len(acl.Path) != 4 || json.Unmarshal(entry.Role, &role) != nil {
			t.Fatal("invalid generated role/policy")
		}
		for path, capability := range map[string]string{effect: "update", "auth/token/lookup-self": "read", "auth/token/renew-self": "update", "auth/token/revoke-self": "update"} {
			if !reflect.DeepEqual(acl.Path[path].Capabilities, []string{capability}) {
				t.Fatal("missing purpose restriction", path)
			}
		}
		if !reflect.DeepEqual(role.Accounts, []string{account.Name}) || !reflect.DeepEqual(role.Namespaces, []string{in.Namespace.Name}) || role.NamespaceSelector != "" ||
			role.Audience != contracts.ConfigurationProviderAudience(in.InstallationID, in.ClusterID) || role.AliasSource != "serviceaccount_uid" || !role.NoDefault || role.Type != "service" ||
			role.TTL != 300 || role.MaxTTL != 900 || role.ExplicitMaxTTL != 900 || role.Period != 0 || role.Uses != 0 || len(role.BoundCIDRs) != 0 || !reflect.DeepEqual(role.Policies, []string{entry.Name}) {
			t.Fatal("role widened identity/policy/time")
		}
	}
	if r.Roles[0].Name == r.Roles[1].Name {
		t.Fatal("two effects share a role")
	}
	r.Roles[0].Policy[0] = '!'
	again, err := ConfigurationProviderRecipeFor(in, selection, account, now)
	if err != nil || again.Profile != r.Profile || again.Roles[0].Policy[0] != '{' {
		t.Fatal("recipe retains mutable returned policy", err)
	}
}

func TestConfigurationProviderRecipeBindsOriginalSourceAndProviderScope(t *testing.T) {
	in, selection, account, now := configurationProviderRecipeFixture(t)
	r, err := ConfigurationProviderRecipeFor(in, selection, account, now)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*contracts.HubWorkerDeployment, *contracts.ConfigurationProviderAuthentication){
		"installation": func(v *contracts.HubWorkerDeployment, _ *contracts.ConfigurationProviderAuthentication) {
			v.InstallationID = "20000000-0000-4000-8000-000000000001"
		},
		"cluster": func(v *contracts.HubWorkerDeployment, _ *contracts.ConfigurationProviderAuthentication) {
			v.ClusterID = "20000000-0000-4000-8000-000000000001"
		},
		"namespace": func(v *contracts.HubWorkerDeployment, _ *contracts.ConfigurationProviderAuthentication) {
			v.Namespace.Name = "other"
		},
		"fleet-source": func(v *contracts.HubWorkerDeployment, _ *contracts.ConfigurationProviderAuthentication) {
			v.FleetSource.UID = "20000000-0000-4000-8000-000000000001"
		},
		"owner-source": func(v *contracts.HubWorkerDeployment, _ *contracts.ConfigurationProviderAuthentication) {
			v.OwnerSource.UID = "20000000-0000-4000-8000-000000000001"
		},
		"transit": func(v *contracts.HubWorkerDeployment, _ *contracts.ConfigurationProviderAuthentication) {
			v.KeyService.AuditKey = "another"
		},
		"provider": func(v *contracts.HubWorkerDeployment, _ *contracts.ConfigurationProviderAuthentication) {
			v.KeyService.Endpoint = "https://another.example"
		},
		"bucket": func(v *contracts.HubWorkerDeployment, _ *contracts.ConfigurationProviderAuthentication) {
			v.AuditStore.Bucket = "another"
		},
		"region": func(v *contracts.HubWorkerDeployment, _ *contracts.ConfigurationProviderAuthentication) {
			v.AuditStore.Region = "another"
		},
		"account": func(_ *contracts.HubWorkerDeployment, p *contracts.ConfigurationProviderAuthentication) {
			p.ServiceAccount.UID = "20000000-0000-4000-8000-000000000001"
		},
		"secret": func(_ *contracts.HubWorkerDeployment, p *contracts.ConfigurationProviderAuthentication) {
			p.AuditCredentials.UID = "20000000-0000-4000-8000-000000000001"
		},
		"mount": func(_ *contracts.HubWorkerDeployment, p *contracts.ConfigurationProviderAuthentication) {
			p.AuthMount = "another"
		},
		"accessor": func(_ *contracts.HubWorkerDeployment, p *contracts.ConfigurationProviderAuthentication) {
			p.AuthMountAccessor = "auth_replaced"
		},
		"digest": func(_ *contracts.HubWorkerDeployment, p *contracts.ConfigurationProviderAuthentication) {
			p.RecipeSHA256 = strings.Repeat("0", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			v, p := in, r.Profile
			mutate(&v, &p)
			if ValidateConfigurationProviderAuthentication(v, p, now) == nil {
				t.Fatal("changed scope retained original profile")
			}
		})
	}
	if ValidateConfigurationProviderAuthentication(in, r.Profile, now.Add(2*time.Hour)) == nil {
		t.Fatal("expired original roots accepted")
	}
}

func TestConfigurationProviderRecipeRejectsForeignSecretAndAuthorityShape(t *testing.T) {
	in, selection, account, now := configurationProviderRecipeFixture(t)
	for _, name := range []string{"foreign-secret", "same-object", "token-auth", "wildcard-account", "missing-source", "invalid-key", "insecure-endpoint"} {
		t.Run(name, func(t *testing.T) {
			v, s, a := in, selection, account
			switch name {
			case "foreign-secret":
				s.AuditCredentials.Name = "another-secret"
			case "same-object":
				s.AuditCredentials.UID = a.UID
			case "token-auth":
				s.AuthMount = "token"
			case "wildcard-account":
				a.Name = "*"
			case "missing-source":
				v.OwnerSource.UID = ""
			case "invalid-key":
				v.KeyService.AuditKey = "*"
			case "insecure-endpoint":
				v.KeyService.Endpoint = "http://bao.example"
			}
			if _, err := ConfigurationProviderRecipeFor(v, s, a, now); err == nil {
				t.Fatal("invalid public selection generated recipe")
			}
		})
	}
}
