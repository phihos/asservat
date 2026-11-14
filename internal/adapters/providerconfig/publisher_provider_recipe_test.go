package providerconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"slices"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func publisherRecipeFixture() (contracts.PublisherDeployment, contracts.PublisherProviderAuthentication) {
	installation := "10000000-0000-4000-8000-000000002030"
	namespace := contracts.WorkerObjectReference{Name: "asservat", UID: "10000000-0000-4000-8000-000000002032"}
	provider := [][]byte{{1, 2, 3}}
	in := contracts.PublisherDeployment{Format: contracts.PublisherDeploymentFormat, InstallationID: installation, ClusterID: "10000000-0000-4000-8000-000000002031", PermissionRootID: "10000000-0000-4000-8000-000000002034", Namespace: namespace,
		AuditKeys: contracts.PublisherTransit{Endpoint: "https://bao.example", Roots: provider, Mount: "transit", Key: PublisherAuditKey(installation)},
		Verifier:  contracts.PublisherVerifier{Endpoint: "https://bao.example", Roots: provider, PKIMount: "worker-pki", Role: contracts.PublisherVerifierRole(installation)}}
	sel := contracts.PublisherProviderAuthentication{AuthMount: "kubernetes", AuthMountAccessor: "auth_kubernetes_1", Namespace: namespace,
		ServiceAccount: contracts.WorkerObjectReference{Name: contracts.PublisherName(installation), UID: "10000000-0000-4000-8000-000000002033"}}
	return in, sel
}

// ADR-203 decision 3: three purpose-separated roles bound to the publisher
// account, namespace and audience, each confined to exactly one provider
// path, with a binding digest over the provider and every path.
func TestPublisherProviderRecipeIsExactAndBound(t *testing.T) {
	in, sel := publisherRecipeFixture()
	r, err := PublisherProviderRecipeFor(in, sel)
	if err != nil {
		t.Fatal(err)
	}
	if ValidatePublisherProviderAuthentication(in, r.Profile, time.Now()) != nil || r.Profile.Format != contracts.PublisherProviderAuthenticationFormat || len(r.Profile.RecipeSHA256) != 64 {
		t.Fatal("recipe does not validate its own profile")
	}
	paths := map[string]string{
		"audit-wrap":    "transit/encrypt/" + PublisherAuditKey(in.InstallationID),
		"audit-unwrap":  "transit/decrypt/" + PublisherAuditKey(in.InstallationID),
		"verifier-sign": "worker-pki/sign/" + contracts.PublisherVerifierRole(in.InstallationID),
	}
	names := map[string]bool{}
	for i, role := range r.Roles {
		var body OwnerKubernetesAuthRole
		if role.Purpose != PublisherProviderPurposes[i] || names[role.Name] || !strings.HasPrefix(role.Name, "asservat-publisher-") || json.Unmarshal(role.Role, &body) != nil ||
			body.Audience != contracts.PublisherProviderAudience(in.InstallationID, in.ClusterID) || !slices.Equal(body.Accounts, []string{sel.ServiceAccount.Name}) ||
			!slices.Equal(body.Namespaces, []string{in.Namespace.Name}) || !body.NoDefault || !slices.Equal(body.Policies, []string{role.Name}) || body.AliasSource != "serviceaccount_uid" {
			t.Fatal("role not bound to the publisher account", role.Purpose)
		}
		names[role.Name] = true
		var acl ownerProviderACL
		if json.Unmarshal(role.Policy, &acl) != nil || len(acl.Path) != 4 {
			t.Fatal("policy grants more than one effect path", role.Purpose)
		}
		for path, rule := range acl.Path {
			switch path {
			case "auth/token/lookup-self":
				if !slices.Equal(rule.Capabilities, []string{"read"}) {
					t.Fatal("lookup-self", rule)
				}
			case "auth/token/renew-self", "auth/token/revoke-self", paths[role.Purpose]:
				if !slices.Equal(rule.Capabilities, []string{"update"}) {
					t.Fatal("update path", path, rule)
				}
			default:
				t.Fatal("unexpected policy path", role.Purpose, path)
			}
		}
	}
	for name, mutate := range map[string]func(*contracts.PublisherDeployment, *contracts.PublisherProviderAuthentication){
		"other account": func(_ *contracts.PublisherDeployment, s *contracts.PublisherProviderAuthentication) {
			s.ServiceAccount.Name = "owner"
		},
		"token mount": func(_ *contracts.PublisherDeployment, s *contracts.PublisherProviderAuthentication) {
			s.AuthMount = "token"
		},
		"other namespace": func(_ *contracts.PublisherDeployment, s *contracts.PublisherProviderAuthentication) {
			s.Namespace.Name = "other"
		},
		"shared UID": func(_ *contracts.PublisherDeployment, s *contracts.PublisherProviderAuthentication) {
			s.ServiceAccount.UID = s.Namespace.UID
		},
		"owner audit key": func(c *contracts.PublisherDeployment, _ *contracts.PublisherProviderAuthentication) {
			c.AuditKeys.Key = "audit"
		},
		"worker role": func(c *contracts.PublisherDeployment, _ *contracts.PublisherProviderAuthentication) {
			c.Verifier.Role = "worker"
		},
		"same mount": func(c *contracts.PublisherDeployment, _ *contracts.PublisherProviderAuthentication) {
			c.Verifier.PKIMount = c.AuditKeys.Mount
		},
		"split provider": func(c *contracts.PublisherDeployment, _ *contracts.PublisherProviderAuthentication) {
			c.Verifier.Endpoint = "https://other.example"
		},
		"split provider root": func(c *contracts.PublisherDeployment, _ *contracts.PublisherProviderAuthentication) {
			c.Verifier.Roots = [][]byte{{9}}
		},
		"plain endpoint": func(c *contracts.PublisherDeployment, _ *contracts.PublisherProviderAuthentication) {
			c.AuditKeys.Endpoint, c.Verifier.Endpoint = "http://bao.example", "http://bao.example"
		},
		"format": func(c *contracts.PublisherDeployment, _ *contracts.PublisherProviderAuthentication) {
			c.Format = "other"
		},
	} {
		c, s := publisherRecipeFixture()
		mutate(&c, &s)
		if _, err := PublisherProviderRecipeFor(c, s); err == nil {
			t.Fatal("accepted:", name)
		}
	}
	changed := in
	changed.AuditKeys.Mount, changed.Verifier.PKIMount = "other-transit", "other-pki"
	if ValidatePublisherProviderAuthentication(changed, r.Profile, time.Now()) == nil {
		t.Fatal("profile digest does not bind the provider paths")
	}
	tampered := r.Profile
	tampered.AuthMountAccessor = "auth_kubernetes_2"
	if ValidatePublisherProviderAuthentication(in, tampered, time.Now()) == nil {
		t.Fatal("profile digest does not bind the auth mount accessor")
	}
}

func publisherSetupFixture(t *testing.T, f *setupFixture) contracts.PublisherDeployment {
	t.Helper()
	p := contracts.PublisherDeployment{Format: contracts.PublisherDeploymentFormat, InstallationID: f.in.InstallationID, ClusterID: f.in.ClusterID, PermissionRootID: f.in.PermissionRootID, Namespace: f.in.Namespace, AuditStore: f.in.AuditStore,
		AuditKeys: contracts.PublisherTransit{Endpoint: f.in.KeyService.Endpoint, Roots: f.in.KeyService.Roots, Mount: f.in.KeyService.AuditMount, Key: PublisherAuditKey(f.in.InstallationID)},
		Evidence:  contracts.PublisherEvidence{Endpoint: "https://evidence.invalid", Roots: f.roots, Region: "test", Bucket: "evidence", StoreID: "10000000-0000-4000-8000-000000002035"},
		Verifier:  contracts.PublisherVerifier{Endpoint: f.in.KeyService.Endpoint, Roots: f.in.KeyService.Roots, PKIMount: "worker-pki", Role: contracts.PublisherVerifierRole(f.in.InstallationID), IssuerRoots: f.roots}}
	r, err := PublisherProviderRecipeFor(p, contracts.PublisherProviderAuthentication{AuthMount: f.profile.AuthMount, AuthMountAccessor: f.profile.AuthMountAccessor, Namespace: f.in.Namespace,
		ServiceAccount: contracts.WorkerObjectReference{Name: contracts.PublisherName(f.in.InstallationID), UID: "10000000-0000-4000-8000-000000002036"}})
	if err != nil {
		t.Fatal(err)
	}
	p.ProviderAuthentication = r.Profile
	return p
}

// ADR-203: the installer's readback accepts only the exact applied
// publisher roles, audit key, worker issuer and verifier PKI role.
func TestPublisherReadbackIsExact(t *testing.T) {
	for _, mode := range []string{"valid", "exportable-audit-key", "wider-verifier-uri", "changed-policy", "other-issuer-roots", "unpinned-issuer", "foreign-issuer"} {
		t.Run(mode, func(t *testing.T) {
			f := newSetupFixture(t)
			f.in.PermissionRootID = "10000000-0000-4000-8000-00000000203a"
			p := publisherSetupFixture(t, f)
			setup, err := PublisherProviderSetupFor(p)
			if err != nil {
				t.Fatal(err)
			}
			key := map[string]any{"name": p.AuditKeys.Key, "type": "aes256-gcm96", "derived": false, "exportable": false, "allow_plaintext_backup": false, "deletion_allowed": false, "supports_encryption": true, "supports_decryption": true, "latest_version": 1, "min_decryption_version": 1, "min_encryption_version": 0}
			role, roles, roots := setup.PKIRole.Role, setup.Authentication.Roles, f.roots
			switch mode {
			case "exportable-audit-key":
				key["exportable"] = true
			case "wider-verifier-uri":
				role = json.RawMessage(bytes.Replace(role, []byte("/key-client/verifier/*"), []byte("/key-client/*"), 1))
			case "changed-policy":
				roles[2].Policy = json.RawMessage(`{"path":{}}`)
			case "other-issuer-roots":
				roots = [][]byte{bytes.Repeat([]byte{1}, 8)}
			case "unpinned-issuer":
				p.Verifier.IssuerRoots = nil
			case "foreign-issuer":
				roots = newSetupFixture(t).roots
				p.Verifier.IssuerRoots = roots
			}
			f.responses["transit/keys/"+p.AuditKeys.Key] = setupMap(t, key)
			f.responses["sys/mounts/worker-pki"] = setupMap(t, map[string]any{"type": "pki"})
			f.responses["worker-pki/cert/ca"] = setupMap(t, map[string]any{"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.roots[0]}))})
			f.responses["worker-pki/roles/"+p.Verifier.Role] = setupMap(t, role)
			for _, r := range roles {
				f.responses["auth/owner-auth/role/"+r.Name] = setupMap(t, r.Role)
				f.responses["sys/policies/acl/"+r.Name] = setupMap(t, map[string]any{"name": r.Name, "policy": string(r.Policy)})
			}
			until, err := f.reader.VerifyPublisher(context.Background(), p, roots)
			if (err == nil) != (mode == "valid") || err == nil && !until.After(time.Now()) {
				t.Fatal(mode, err)
			}
		})
	}
}
