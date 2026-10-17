package integration

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgxpool"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// The fixture supplies protected bootstrap private/material roots and a scoped
// maintenance credential. Actual preparer, native independent guards, original
// probe, credential binding/Secret and SQL provisioning are product components.
// No provider credential issuance, Pod handover or activation is claimed here.
func TestInitialPreparationSQLWithRealKubernetesPostgres(t *testing.T) {
	var materialRef contracts.WorkerObjectReference
	setup := func(ctx context.Context, kc *rest.Config, api kubernetes.Interface, plan *contracts.InitialPreparationPlan) {
		body, _ := json.Marshal(contracts.InitialPreparationPrivateState{Format: contracts.InitialPreparationPrivateFormat, InstallationID: plan.InstallationID, RequestID: plan.RequestID})
		private, e := api.CoreV1().Secrets(plan.BootstrapNamespace.Name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "private-progress", Annotations: map[string]string{"asservat.io/installation-id": plan.InstallationID, "asservat.io/preparation-request": plan.RequestID}}, Type: core.SecretTypeOpaque, Data: map[string][]byte{"state.json": body}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("fixture private root", e)
		}
		plan.PrivateState = &contracts.WorkerObjectReference{Name: private.Name, UID: string(private.UID)}
		account, e := api.CoreV1().ServiceAccounts(plan.BootstrapNamespace.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: "fixture-audience"}, AutomountServiceAccountToken: ptr.To(false)}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		response, e := api.CoreV1().ServiceAccounts(account.Namespace).CreateToken(ctx, account.Name, &auth.TokenRequest{Spec: auth.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600)), BoundObjectRef: &auth.BoundObjectReference{APIVersion: "v1", Kind: "Secret", Name: private.Name, UID: private.UID}}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("fixture audience unavailable")
		}
		parts := strings.Split(response.Status.Token, ".")
		if len(parts) != 3 {
			t.Fatal("fixture audience syntax")
		}
		raw, e := base64.RawURLEncoding.DecodeString(parts[1])
		if e != nil {
			t.Fatal("fixture audience encoding")
		}
		defer clear(raw)
		var claims struct {
			Audience []string `json:"aud"`
		}
		if json.Unmarshal(raw, &claims) != nil || len(claims.Audience) != 1 {
			t.Fatal("fixture audience profile")
		}
		plan.ProbeAudience = claims.Audience[0]
		// Random retained values use the existing maintained credential generator;
		// the product binder below supplies the actual original fifteen-minute dates.
		seed, e := postgres.NewInitialSQLCredentials(plan.InstallationID, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		material := contracts.InitialSQLMaterial{Format: contracts.InitialSQLMaterialFormat, InstallationID: plan.InstallationID, RequestID: plan.RequestID, PreparationPassword: seed.Preparation.Password, AuditPassword: seed.Audit.Password, ActivationPassword: seed.Activation.Password}
		raw, e = json.Marshal(material)
		if e != nil {
			t.Fatal(e)
		}
		defer clear(raw)
		secret, e := api.CoreV1().Secrets(plan.BootstrapNamespace.Name).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "sql-material"}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true), Data: map[string][]byte{"material.json": raw}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal("fixture immutable material", e)
		}
		materialRef = contracts.WorkerObjectReference{Name: secret.Name, UID: string(secret.UID)}
	}
	initialPreparationSupervisorNativePlan(t, true, false, setup, func(ctx context.Context, kc *rest.Config, api kubernetes.Interface, admin, probe *kube.PermissionClient, c contracts.InitialPreparer) {
		var f fixture
		raw, e := os.ReadFile(os.Getenv("ASSERVAT_CONTEXT_FIXTURES"))
		if e != nil || json.Unmarshal(raw, &f) != nil || f.Postgres == "" {
			t.Fatal("SQL fixture unavailable")
		}
		sql, e := pgxpool.New(ctx, f.Postgres)
		if e != nil {
			t.Fatal(e)
		}
		defer sql.Close()
		u, e := url.Parse(f.Postgres)
		if e != nil {
			t.Fatal("fixture SQL endpoint")
		}
		address, tlsConfig := pgTLSBridge(t, u.Host)
		maintenance := initialSQLMaintenance(t, ctx, sql, address, tlsConfig)
		defer maintenance.Close()
		manager, e := postgres.NewInitialSQLRoles(ctx, maintenance, c.Plan.InstallationID)
		if e != nil {
			t.Fatal("scoped maintenance", e)
		}
		native := rest.CopyConfig(kc)
		if e = rest.LoadTLSFiles(native); e != nil {
			t.Fatal(e)
		}
		block, _ := pem.Decode(native.CAData)
		if block == nil {
			t.Fatal("fixture root")
		}
		roots := [][]byte{block.Bytes}
		var fleet contracts.FleetSettings
		raw, e = os.ReadFile("../../examples/fleet-settings.json")
		if e != nil || json.Unmarshal(raw, &fleet) != nil {
			t.Fatal("fixture fleet", e)
		}
		fleet.InstallationID = c.Plan.InstallationID
		// Public provider placeholders are not used for provider I/O in this component
		// test. Actual SQL goes through the separate TLS bridge and scoped role above.
		c.Services = &contracts.InitialPreparationServices{Format: contracts.InitialPreparationServicesFormat, Fleet: fleet, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: native.Host, Roots: roots}, Postgres: contracts.OwnerPostgresEndpoint{Host: "sql.example.test", Port: 5432, Database: "asservat", Roots: roots, MaxConnections: 2}, AuditStore: contracts.OwnerAuditStore{Endpoint: "https://audit.example.test", Roots: roots, Region: "test", Bucket: "audit"}, KeyService: contracts.ConfigurationKeyService{Endpoint: "https://keys.example.test", Roots: roots, AuditMount: "transit", AuditKey: "audit"}}
		c.SQLMaterial = &materialRef
		// Exact fixture-owned policy teardown, independent of product handover.
		t.Cleanup(func() {
			clean, end := context.WithTimeout(context.Background(), 15*time.Second)
			defer end()
			for _, name := range []string{c.Plan.Workload.FleetGuard, c.Plan.Workload.WitnessGuard, c.Plan.Workload.WorkloadGuard} {
				b, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(clean, name, meta.GetOptions{})
				if e == nil {
					if b.Annotations["asservat.io/installation-id"] != c.Plan.InstallationID || b.Annotations["asservat.io/preparation-request"] != c.Plan.RequestID {
						t.Error("foreign policy binding")
						continue
					}
					if e = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(clean, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &b.UID}}); e != nil && !apierrors.IsNotFound(e) {
						t.Error(e)
					}
				} else if !apierrors.IsNotFound(e) {
					t.Error(e)
				}
				p, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(clean, name, meta.GetOptions{})
				if e == nil {
					if p.Annotations["asservat.io/installation-id"] != c.Plan.InstallationID || p.Annotations["asservat.io/preparation-request"] != c.Plan.RequestID {
						t.Error("foreign policy")
						continue
					}
					if e = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(clean, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &p.UID}}); e != nil && !apierrors.IsNotFound(e) {
						t.Error(e)
					}
				} else if !apierrors.IsNotFound(e) {
					t.Error(e)
				}
			}
		})
		p, e := kube.NewInitialPreparer(native, admin, probe, c)
		if e != nil {
			t.Fatal(e)
		}
		defer p.Close()
		materialReader, e := kube.NewInitialSQLMaterialReader(p, materialRef)
		if e != nil {
			t.Fatal(e)
		}
		if e = materialReader.CheckInitialSQLMaterial(ctx); e != nil {
			t.Fatal("material preflight", e)
		}
		end := time.Now().Add(30 * time.Second)
		for {
			_, e = p.PrepareFinalInputs(ctx)
			if e == nil {
				break
			}
			if !errors.Is(e, kube.ErrInitialPreparationPolicyPending) || !time.Now().Before(end) {
				t.Fatal("public inputs", e)
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(50 * time.Millisecond):
			}
		}
		observed, e := p.ReadPreparedInputs(ctx)
		if e != nil {
			t.Fatal("current public inputs", e)
		}
		issued, e := p.PrepareProbe(ctx)
		if e != nil {
			t.Fatal("original native probe", e)
		}
		defer clear(issued.Token)
		ns := cfg.NamespaceRef{Name: observed.Configuration.Namespace.Name, UID: observed.Configuration.Namespace.UID}
		targetAdmin, e := kube.NewPermissionClient(native, c.Plan.ClusterID, ns, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		targetConfig := &rest.Config{Host: native.Host, TLSClientConfig: rest.TLSClientConfig{CAData: native.CAData}, BearerToken: string(issued.Token)}
		targetProbe, e := kube.NewPermissionClient(targetConfig, c.Plan.ClusterID, ns, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		binder, e := kube.NewInitialPreparationCredentialBinder(p, targetAdmin, targetProbe, observed.Configuration, observed.Input.UID, materialRef)
		if e != nil {
			t.Fatal("credential binder", e)
		}
		material, binding, _, e := binder.Bind(ctx)
		if e != nil {
			t.Fatal("original binding", e)
		}
		credentials, e := postgres.BindInitialSQLMaterial(material, c.Plan.InstallationID, c.Plan.RequestID, binding.NotBefore, binding.NotAfter)
		if e != nil {
			t.Fatal(e)
		}
		bytes, e := hex.DecodeString(binding.StartupDigest)
		if e != nil || len(bytes) != 32 {
			t.Fatal("startup digest")
		}
		var digest artifact.Digest
		copy(digest[:], bytes)
		payload, e := postgres.EncodeInitialSQLCredentials(credentials, digest)
		if e != nil {
			t.Fatal(e)
		}
		defer clear(payload)
		stored, e := binder.PersistSQLState(ctx, payload)
		if e != nil {
			t.Fatal("original SQL Secret", e)
		}
		provision := func() error {
			effect, done := context.WithDeadline(ctx, stored.ValidUntil)
			defer done()
			if e := manager.Provision(effect, credentials); e != nil {
				return e
			}
			_, _, _, e := binder.Bind(effect)
			if e != nil {
				return e
			}
			if !time.Now().Before(stored.ValidUntil) {
				return cfg.ErrUnavailable
			}
			return nil
		}
		if e = provision(); e != nil {
			t.Fatal("current bounded SQL provisioning", e)
		}
		t.Run("original-secret-and-role-replay", func(t *testing.T) {
			replay, e := binder.PersistSQLState(ctx, payload)
			if e != nil || replay.Secret != stored.Secret {
				t.Fatal("Secret replay changed UID", e)
			}
			stored = replay
			var before string
			var until time.Time
			if e = sql.QueryRow(ctx, "SELECT rolpassword,rolvaliduntil FROM pg_authid WHERE rolname=$1", credentials.Preparation.Username).Scan(&before, &until); e != nil {
				t.Fatal("fixture role snapshot")
			}
			if e = provision(); e != nil {
				t.Fatal("exact SQL replay", e)
			}
			var same bool
			if e = sql.QueryRow(ctx, "SELECT rolpassword=$2 AND rolvaliduntil=$3 FROM pg_authid WHERE rolname=$1", credentials.Preparation.Username, before, until).Scan(&same); e != nil || !same || !until.Equal(binding.NotAfter) {
				t.Fatal("SQL replay renewed original values")
			}
		})
		t.Run("wrong-original-password-cannot-replace-state", func(t *testing.T) {
			other, e := postgres.NewInitialSQLCredentials(credentials.InstallationID, time.Now())
			if e != nil {
				t.Fatal(e)
			}
			wrong := credentials
			wrong.Preparation.Password = other.Preparation.Password
			bad, e := postgres.EncodeInitialSQLCredentials(wrong, digest)
			if e != nil {
				t.Fatal("valid changed credential encoding", e)
			}
			defer clear(bad)
			if _, e = binder.PersistSQLState(ctx, bad); e == nil {
				t.Fatal("changed material accepted")
			}
		})
		t.Run("retired-roles-cannot-be-revived", func(t *testing.T) {
			if e = manager.Retire(ctx, credentials); e != nil {
				t.Fatal("retire", e)
			}
			if e = manager.Provision(ctx, credentials); e == nil {
				t.Fatal("retired SQL authority revived")
			}
			var live int
			if e = sql.QueryRow(ctx, "SELECT count(*) FROM pg_roles WHERE rolname=ANY($1) AND rolcanlogin", []string{credentials.Preparation.Username, credentials.Audit.Username, credentials.Activation.Username}).Scan(&live); e != nil || live != 0 {
				t.Fatal("retired role login remains", e)
			}
		})
		pod, e := api.CoreV1().Pods(ns.Name).Get(ctx, c.Plan.Workload.Name, meta.GetOptions{})
		if e != nil || len(pod.Spec.SchedulingGates) != 1 || pod.Spec.NodeName != "" || pod.Status.StartTime != nil {
			t.Fatal("SQL preparation launched Pod", e)
		}
		var activated int
		if e = sql.QueryRow(ctx, "SELECT count(*) FROM fleet_initial_activation WHERE installation_id=$1", c.Plan.InstallationID).Scan(&activated); e != nil || activated != 0 {
			t.Fatal("SQL preparation activated", e)
		}
	})
}
