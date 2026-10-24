package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/contracts"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// Runs the actual fixed-file loader and InitialPreparationDeployment.Run against
// real Kubernetes/Postgres/OpenBao. The finite bootstrap roots/admin grants,
// existing OpenBao roles/ACLs and externally managed S3 keys are fixture inputs.
// This checkpoint leaves the original Pod gated; it is not installed activation.
func TestInitialPreparationProvidersWithRealServices(t *testing.T) {
	if os.Getenv("ASSERVAT_CONTEXT_FIXTURES") == "" {
		t.Skip("run owned context-integration fixture")
	}
	var f fixture
	raw, e := os.ReadFile(os.Getenv("ASSERVAT_CONTEXT_FIXTURES"))
	if e != nil || json.Unmarshal(raw, &f) != nil || f.Postgres == "" || f.KMS == "" || f.S3 == "" {
		t.Fatal("provider fixture unavailable")
	}
	var materialRef, providerRef contracts.WorkerObjectReference
	var adminToken string
	setup := func(ctx context.Context, kc *rest.Config, api kubernetes.Interface, plan *contracts.InitialPreparationPlan) {
		body, _ := json.Marshal(contracts.InitialPreparationPrivateState{Format: contracts.InitialPreparationPrivateFormat, InstallationID: plan.InstallationID, RequestID: plan.RequestID})
		private, e := api.CoreV1().Secrets(plan.BootstrapNamespace.Name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "private-progress", Annotations: map[string]string{"asservat.io/installation-id": plan.InstallationID, "asservat.io/preparation-request": plan.RequestID}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"state.json": body}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("fixture private progress", e)
		}
		plan.PrivateState = &contracts.WorkerObjectReference{Name: private.Name, UID: string(private.UID)}
		account, e := api.CoreV1().ServiceAccounts(plan.BootstrapNamespace.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "preparer"}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		plan.Administrators = append(plan.Administrators, contracts.OwnerDeploymentActor{Kind: "User", Name: "system:serviceaccount:" + account.Namespace + ":" + account.Name})
		role, e := api.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "initial-provider-fixture-bootstrap"}, Rules: []rbac.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"namespaces", "serviceaccounts", "serviceaccounts/token", "configmaps", "secrets", "pods"}, Verbs: []string{"get", "create", "update"}},
			{APIGroups: []string{rbac.GroupName}, Resources: []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"}, Verbs: []string{"get", "create", "update"}},
			{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, Verbs: []string{"get", "create", "update"}},
			{APIGroups: []string{"authentication.k8s.io"}, Resources: []string{"selfsubjectreviews", "tokenreviews"}, Verbs: []string{"create"}},
		}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		binding, e := api.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: role.Name}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: role.Name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Namespace: account.Namespace, Name: account.Name}}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			clean, done := context.WithTimeout(context.Background(), 10*time.Second)
			defer done()
			if e := api.RbacV1().ClusterRoleBindings().Delete(clean, binding.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &binding.UID}}); e != nil && !apierrors.IsNotFound(e) {
				t.Error(e)
			}
			if e := api.RbacV1().ClusterRoles().Delete(clean, role.Name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &role.UID}}); e != nil && !apierrors.IsNotFound(e) {
				t.Error(e)
			}
		})
		token, e := api.CoreV1().ServiceAccounts(account.Namespace).CreateToken(ctx, account.Name, &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600)), BoundObjectRef: &auth.BoundObjectReference{APIVersion: "v1", Kind: "Secret", Name: private.Name, UID: private.UID}}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("fixture scoped bootstrap token unavailable")
		}
		adminToken = token.Status.Token
		parts := strings.Split(adminToken, ".")
		if len(parts) != 3 {
			t.Fatal("fixture audience syntax")
		}
		body, e = base64.RawURLEncoding.DecodeString(parts[1])
		if e != nil {
			t.Fatal("fixture audience encoding")
		}
		defer clear(body)
		var claims struct {
			Audience []string `json:"aud"`
		}
		if json.Unmarshal(body, &claims) != nil || len(claims.Audience) != 1 {
			t.Fatal("fixture audience profile")
		}
		plan.ProbeAudience = claims.Audience[0]
		seed, e := postgres.NewInitialSQLCredentials(plan.InstallationID, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		material := contracts.InitialSQLMaterial{Format: contracts.InitialSQLMaterialFormat, InstallationID: plan.InstallationID, RequestID: plan.RequestID, PreparationPassword: seed.Preparation.Password, AuditPassword: seed.Audit.Password, ActivationPassword: seed.Activation.Password}
		body, _ = json.Marshal(material)
		defer clear(body)
		secret, e := api.CoreV1().Secrets(account.Namespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "sql-material"}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: map[string][]byte{"material.json": body}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("fixture SQL material", e)
		}
		materialRef = contracts.WorkerObjectReference{Name: secret.Name, UID: string(secret.UID)}
	}
	initialPreparationSupervisorNativePlan(t, true, false, setup, func(ctx context.Context, kc *rest.Config, api kubernetes.Interface, _, _ *kube.PermissionClient, c contracts.InitialPreparer) {
		admin := initialFreshDatabase(t, ctx, f.Postgres)
		endpoint, e := url.Parse(f.Postgres)
		if e != nil {
			t.Fatal(e)
		}
		address, pgTLS := pgTLSBridge(t, endpoint.Host)
		maintenance := initialSQLMaintenance(t, ctx, admin, address, pgTLS)
		defer maintenance.Close()
		connection, e := net.DialTimeout("tcp", address, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		if _, e = connection.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47}); e != nil {
			t.Fatal(e)
		}
		var ssl [1]byte
		if _, e = io.ReadFull(connection, ssl[:]); e != nil || ssl[0] != 'S' {
			t.Fatal("fixture SQL TLS unavailable")
		}
		secure := tls.Client(connection, pgTLS)
		if e = secure.HandshakeContext(ctx); e != nil {
			t.Fatal(e)
		}
		sqlRoot := secure.ConnectionState().PeerCertificates[0].Raw
		secure.Close()
		host, portText, _ := net.SplitHostPort(address)
		port, _ := strconv.Atoi(portText)
		keys, storage := tlsBridge(t, f.KMS), tlsBridge(t, f.S3)
		native := rest.CopyConfig(kc)
		if e = rest.LoadTLSFiles(native); e != nil {
			t.Fatal(e)
		}
		block, _ := pem.Decode(native.CAData)
		if block == nil {
			t.Fatal("fixture API roots")
		}
		profile := contracts.InitialProviderProfile{Format: contracts.InitialProviderProfileFormat, Material: contracts.WorkerObjectReference{Name: "provider-material", UID: custodyID()}, IssuerPolicy: "initial-provider-issuer", WrapRole: "initial-provider-wrap", WrapPolicy: "initial-provider-encrypt", UnwrapRole: "initial-provider-unwrap", UnwrapPolicy: "initial-provider-decrypt"}
		policies, e := kms.InitialProviderPolicies(profile, "initial-provider-transit", "audit")
		if e != nil {
			t.Fatal(e)
		}
		request(t, f.KMS, "synthetic-root", "sys/mounts/initial-provider-transit", map[string]any{"type": "transit"}, 204)
		request(t, f.KMS, "synthetic-root", "initial-provider-transit/keys/audit", map[string]any{"type": "aes256-gcm96"}, 200)
		for name, policy := range policies {
			request(t, f.KMS, "synthetic-root", "sys/policies/acl/"+name, map[string]any{"policy": policy}, 204)
		}
		for role, policy := range map[string]string{profile.WrapRole: profile.WrapPolicy, profile.UnwrapRole: profile.UnwrapPolicy} {
			request(t, f.KMS, "synthetic-root", "auth/token/roles/"+role, map[string]any{"allowed_policies": []string{policy}, "orphan": false, "renewable": false, "token_type": "service", "token_no_default_policy": true, "token_explicit_max_ttl": 900}, 204)
		}
		issued := request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{profile.IssuerPolicy}, "no_default_policy": true, "no_parent": false, "renewable": false, "type": "service", "ttl": "10m", "explicit_max_ttl": "10m"}, 200)
		issuerToken := issued["auth"].(map[string]any)["client_token"].(string)
		material := contracts.InitialProviderMaterial{Format: contracts.InitialProviderMaterialFormat, InstallationID: c.Plan.InstallationID, RequestID: c.Plan.RequestID, IssuerToken: issuerToken, Storage: contracts.OwnerStorageCredential{AccessKeyID: "synthetic-only", SecretAccessKey: "synthetic-only-secret"}, StorageUseUntil: time.Now().UTC().Add(time.Hour)}
		data, _ := json.Marshal(material)
		defer clear(data)
		secret, e := api.CoreV1().Secrets(c.Plan.BootstrapNamespace.Name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: profile.Material.Name}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: map[string][]byte{"material.json": data}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("fixture provider material", e)
		}
		providerRef = contracts.WorkerObjectReference{Name: secret.Name, UID: string(secret.UID)}
		profile.Material = providerRef
		var fleet contracts.FleetSettings
		raw, e := os.ReadFile("../../examples/fleet-settings.json")
		if e != nil || json.Unmarshal(raw, &fleet) != nil {
			t.Fatal("fixture public fleet")
		}
		fleet.InstallationID = c.Plan.InstallationID
		c.Services = &contracts.InitialPreparationServices{Format: contracts.InitialPreparationServicesFormat, Fleet: fleet, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: native.Host, Roots: [][]byte{block.Bytes}}, Postgres: contracts.OwnerPostgresEndpoint{Host: host, Port: port, Database: admin.Config().ConnConfig.Database, Roots: [][]byte{sqlRoot}, MaxConnections: 2}, AuditStore: contracts.OwnerAuditStore{Endpoint: storage.URL, Roots: [][]byte{storage.Certificate().Raw}, Region: "us-east-1", Bucket: "initial-provider"}, KeyService: contracts.ConfigurationKeyService{Endpoint: keys.URL, Roots: [][]byte{keys.Certificate().Raw}, AuditMount: "initial-provider-transit", AuditKey: "audit"}}
		c.Kubernetes = c.Services.Kubernetes
		c.SQLMaterial = &materialRef
		c.Providers = &profile
		// Native helper's exact cleanup owner remains separate from the projected SA.
		t.Cleanup(func() {
			clean, done := context.WithTimeout(context.Background(), 15*time.Second)
			defer done()
			for _, name := range []string{c.Plan.Workload.FleetGuard, c.Plan.Workload.WitnessGuard, c.Plan.Workload.WorkloadGuard} {
				b, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(clean, name, meta.GetOptions{})
				if e == nil && b.Annotations["asservat.io/installation-id"] == c.Plan.InstallationID {
					if e = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(clean, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &b.UID}}); e != nil && !apierrors.IsNotFound(e) {
						t.Error(e)
					}
				}
				p, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(clean, name, meta.GetOptions{})
				if e == nil && p.Annotations["asservat.io/installation-id"] == c.Plan.InstallationID {
					if e = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(clean, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &p.UID}}); e != nil && !apierrors.IsNotFound(e) {
						t.Error(e)
					}
				}
			}
		})
		anchor, e := api.CoreV1().Secrets(c.Plan.BootstrapNamespace.Name).Get(ctx, "probe-lifetime", meta.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		probe, e := api.CoreV1().ServiceAccounts(anchor.Namespace).CreateToken(ctx, "probe", &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600)), BoundObjectRef: &auth.BoundObjectReference{APIVersion: "v1", Kind: "Secret", Name: anchor.Name, UID: anchor.UID}}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("fixture bootstrap probe unavailable")
		}
		dir := t.TempDir()
		write := func(name string, v []byte) {
			t.Helper()
			if e := os.WriteFile(filepath.Join(dir, name), v, 0600); e != nil {
				t.Fatal(e)
			}
		}
		data, _ = json.Marshal(c)
		write("deployment.json", data)
		clear(data)
		write("administrator-token", []byte(adminToken))
		write("probe-token", []byte(probe.Status.Token))
		maintenanceConfig := maintenance.Config()
		data, _ = json.Marshal(contracts.OwnerSQLCredential{Username: maintenanceConfig.ConnConfig.User, Password: maintenanceConfig.ConnConfig.Password})
		write("sql-maintenance.json", data)
		clear(data)
		files, e := os.OpenRoot(dir)
		if e != nil {
			t.Fatal(e)
		}
		defer files.Close()
		run := func() {
			t.Helper()
			deployment, e := bootstrap.NewInitialPreparationDeployment(ctx, files)
			if e != nil {
				t.Fatal("actual preparation loader", e)
			}
			defer deployment.Close()
			if _, e = deployment.Run(); e != nil {
				t.Fatal("actual preparation Run", e)
			}
		}
		run()
		projection, e := api.CoreV1().Secrets(c.Plan.Workload.Namespace).Get(ctx, c.Plan.Workload.Credentials, meta.GetOptions{})
		if e != nil || projection.Immutable == nil || !*projection.Immutable || len(projection.Data) != 7 {
			t.Fatal("actual fixed provider projection", e)
		}
		for _, name := range []string{"sql-prepare.json", "sql-audit.json", "sql-activate.json", "audit-storage.json", "audit-wrap.token", "audit-unwrap.token", "kube-probe.token"} {
			if len(projection.Data[name]) == 0 {
				t.Fatal("required fixed projection member missing", name)
			}
		}
		for _, v := range projection.Data {
			defer clear(v)
			if bytes.Contains(v, []byte(issuerToken)) || bytes.Contains(v, []byte(maintenanceConfig.ConnConfig.Password)) || bytes.Contains(v, []byte(maintenanceConfig.ConnConfig.User)) {
				t.Fatal("maintenance credential leaked into activation projection")
			}
		}
		t.Run("original-loader-replay", func(t *testing.T) {
			run()
			after, e := api.CoreV1().Secrets(projection.Namespace).Get(ctx, projection.Name, meta.GetOptions{})
			if e != nil || after.UID != projection.UID || after.ResourceVersion != projection.ResourceVersion {
				t.Fatal("retry replaced final projection", e)
			}
		})
		wrap, unwrap := string(projection.Data["audit-wrap.token"]), string(projection.Data["audit-unwrap.token"])
		encrypted := request(t, f.KMS, wrap, "initial-provider-transit/encrypt/audit", map[string]any{"plaintext": base64.StdEncoding.EncodeToString([]byte("synthetic-installation-audit"))}, 200)
		cipher := encrypted["data"].(map[string]any)["ciphertext"].(string)
		request(t, f.KMS, unwrap, "initial-provider-transit/decrypt/audit", map[string]any{"ciphertext": cipher}, 200)
		request(t, f.KMS, wrap, "initial-provider-transit/decrypt/audit", map[string]any{"ciphertext": cipher}, 403)
		request(t, f.KMS, unwrap, "initial-provider-transit/encrypt/audit", map[string]any{"plaintext": base64.StdEncoding.EncodeToString([]byte("synthetic"))}, 403)
		pod, e := api.CoreV1().Pods(c.Plan.Workload.Namespace).Get(ctx, c.Plan.Workload.Name, meta.GetOptions{})
		if e != nil || len(pod.Spec.SchedulingGates) != 1 || pod.Spec.NodeName != "" {
			t.Fatal("provider preparation unexpectedly activated Pod", e)
		}
		// Both real Run owners have joined and the original Pod has never run.
		// This qualifies provider revocation only; activation/SQL/storage cleanup
		// and command-level retirement remain separate composition work.
		t.Run("original-provider-rights-retirement", func(t *testing.T) {
			private, err := api.CoreV1().Secrets(c.Plan.BootstrapNamespace.Name).Get(ctx, c.Plan.PrivateState.Name, meta.GetOptions{})
			var state contracts.InitialPreparationPrivateState
			if err != nil || string(private.UID) != c.Plan.PrivateState.UID || json.Unmarshal(private.Data["state.json"], &state) != nil || state.Providers == nil || state.Providers.Wrap == nil || state.Providers.Unwrap == nil {
				t.Fatal("retained original provider state unavailable")
			}
			defer clear(private.Data["state.json"])
			issuer, err := kms.NewInitialProviderIssuer(keys.URL, issuerToken, "initial-provider-transit", "audit", c.Plan.InstallationID, c.Plan.RequestID, profile, keys.Client(), time.Now)
			if err != nil {
				t.Fatal("retained provider retirement adapter unavailable")
			}
			defer issuer.Close()
			for purpose, claim := range map[string]*contracts.InitialProviderIssue{"wrap": state.Providers.Wrap, "unwrap": state.Providers.Unwrap} {
				if claim.Response == nil {
					t.Fatal("original positive provider completion missing")
				}
				for range 2 {
					deadline, err := issuer.Revoke(ctx, purpose, *claim, state.Providers.Parent, *claim.Response)
					if err != nil || !time.Now().Before(deadline) {
						t.Fatal("original provider revocation/replay unavailable")
					}
				}
				if issuer.Verify(ctx, purpose, *claim, state.Providers.Parent, *claim.Response) == nil {
					t.Fatal("retired original token remained valid")
				}
			}
			request(t, f.KMS, wrap, "initial-provider-transit/encrypt/audit", map[string]any{"plaintext": base64.StdEncoding.EncodeToString([]byte("synthetic"))}, 403)
			request(t, f.KMS, unwrap, "initial-provider-transit/decrypt/audit", map[string]any{"ciphertext": cipher}, 403)
		})
		t.Log("actual fixed-file preparation loader and Run; original SQL/native probe, two scoped OpenBao issue claims and seven immutable target files. Bootstrap identity/roles/material/S3 credentials remain explicit fixture inputs. Provider revocation follows joined preparation while original Pod stays gated; activation/handover and composed retirement remain pending")
	})
}
