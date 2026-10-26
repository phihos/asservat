package integration

import (
	"asservat.local/asservat/internal/adapters/kms"
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Runs actual preparation, original Pod activation and passive history. All
// bootstrap identities/provider setup are fixture inputs, never runtime grants.
func TestInitialPreparationHandoverWithRealServices(t *testing.T) {
	if os.Getenv("ASSERVAT_CONTEXT_FIXTURES") == "" || os.Getenv("ASSERVAT_INITIAL_HANDOVER_NATIVE") != "1" {
		t.Skip("run owned --initial-handover qualification with a fresh database")
	}
	initialPreparationHandoverWithRealServices(t, false)
}

func TestInitialSchemaHandoverWithRealServices(t *testing.T) {
	if os.Getenv("ASSERVAT_CONTEXT_FIXTURES") == "" || os.Getenv("ASSERVAT_INITIAL_SCHEMA_HANDOVER_NATIVE") != "1" {
		t.Skip("run owned --initial-schema-handover qualification with an empty database")
	}
	initialPreparationHandoverWithRealServices(t, true)
}

func initialPreparationHandoverWithRealServices(t *testing.T, initializeSchema bool) {
	t.Helper()
	var f fixture
	raw, e := os.ReadFile(os.Getenv("ASSERVAT_CONTEXT_FIXTURES"))
	if e != nil || json.Unmarshal(raw, &f) != nil || f.Postgres == "" || f.KMS == "" || f.S3 == "" || f.WorkerImage == "" || f.NativeProviders.Postgres == "" {
		t.Fatal("provider fixture unavailable")
	}
	fixtureContext, finishFixture := context.WithTimeout(context.Background(), 5*time.Minute)
	defer finishFixture()
	admin, e := pgxpool.New(fixtureContext, f.Postgres)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close()
	rootCert, e := x509.ParseCertificate(f.NativeProviders.Root)
	if e != nil {
		t.Fatal("native TLS root", e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	host, portText, e := net.SplitHostPort(f.NativeProviders.Postgres)
	if e != nil {
		t.Fatal(e)
	}
	port, e := strconv.Atoi(portText)
	if e != nil {
		t.Fatal(e)
	}
	sqlTLS := &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS13}
	var maintenance *pgxpool.Pool
	if initializeSchema {
		maintenance = initialEmptySchemaManager(t, fixtureContext, admin, f.NativeProviders.Postgres, sqlTLS)
	} else {
		maintenance = initialSQLMaintenance(t, fixtureContext, admin, f.NativeProviders.Postgres, sqlTLS)
	}
	defer maintenance.Close()
	// This is independently provisioned fixture administration, pinned before
	// the plan/guards are declared. Runtime readers cannot choose a replacement.
	var historyManager contracts.InitialSQLHistoryManager
	if e = admin.QueryRow(fixtureContext, "SELECT rolname,oid FROM pg_roles WHERE rolname=$1", maintenance.Config().ConnConfig.User).Scan(&historyManager.Name, &historyManager.OID); e != nil || historyManager.Name == "" || historyManager.OID == 0 {
		t.Fatal("fixture original SQL manager identity unavailable")
	}
	t.Run("native-handover-admission", func(t *testing.T) { nativeInitialHandoverAdmission(t, f, historyManager) })
	var materialRef, providerRef contracts.WorkerObjectReference
	var adminToken string
	setup := func(ctx context.Context, kc *rest.Config, api kubernetes.Interface, plan *contracts.InitialPreparationPlan) {
		plan.Handover = contracts.InitialPreparationHandoverProtocol
		if initializeSchema {
			plan.SchemaInitialization = contracts.InitialSchemaProtocol
		}
		plan.HistoryManager = &historyManager
		plan.Workload.Image = f.WorkerImage
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
		role, e := api.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: "initial-handover-fixture-bootstrap"}, Rules: []rbac.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"namespaces", "serviceaccounts", "serviceaccounts/token", "configmaps", "secrets", "pods"}, Verbs: []string{"get", "create", "update", "delete"}},
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
	initialPreparationSupervisorNativePlanWithin(t, 4*time.Minute, true, false, setup, func(ctx context.Context, kc *rest.Config, api kubernetes.Interface, _, _ *kube.PermissionClient, c contracts.InitialPreparer) {
		transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
		defer transport.CloseIdleConnections()
		providerHTTP := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		native := rest.CopyConfig(kc)
		if e = rest.LoadTLSFiles(native); e != nil {
			t.Fatal(e)
		}
		block, _ := pem.Decode(native.CAData)
		if block == nil {
			t.Fatal("fixture API roots")
		}
		node, e := api.CoreV1().Nodes().Get(ctx, f.Clusters[0].Pod.NodeName, meta.GetOptions{})
		if e != nil || string(node.UID) != f.Clusters[0].NodeUID {
			t.Fatal("owned node identity unavailable")
		}
		apiIP := ""
		for _, address := range node.Status.Addresses {
			if address.Type == core.NodeInternalIP {
				apiIP = address.Address
				break
			}
		}
		if net.ParseIP(apiIP) == nil {
			t.Fatal("owned node API address unavailable")
		}
		native.Host = "https://" + net.JoinHostPort(apiIP, "6443")
		direct, e := kubernetes.NewForConfig(native)
		if e != nil {
			t.Fatal(e)
		}
		checked, e := direct.CoreV1().Nodes().Get(ctx, node.Name, meta.GetOptions{})
		if e != nil || checked.UID != node.UID {
			t.Fatal("shared native API origin unavailable", e)
		}
		profile := contracts.InitialProviderProfile{Format: contracts.InitialProviderProfileFormat, Material: contracts.WorkerObjectReference{Name: "provider-material", UID: custodyID()}, IssuerPolicy: "initial-handover-issuer", WrapRole: "initial-handover-wrap", WrapPolicy: "initial-handover-encrypt", UnwrapRole: "initial-handover-unwrap", UnwrapPolicy: "initial-handover-decrypt"}
		policies, e := kms.InitialProviderPolicies(profile, "initial-handover-transit", "audit")
		if e != nil {
			t.Fatal(e)
		}
		request(t, f.KMS, "synthetic-root", "sys/mounts/initial-handover-transit", map[string]any{"type": "transit"}, 204)
		request(t, f.KMS, "synthetic-root", "initial-handover-transit/keys/audit", map[string]any{"type": "aes256-gcm96"}, 200)
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
		c.Services = &contracts.InitialPreparationServices{Format: contracts.InitialPreparationServicesFormat, Fleet: fleet, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: native.Host, Roots: [][]byte{block.Bytes}}, Postgres: contracts.OwnerPostgresEndpoint{Host: host, Port: port, Database: "custody_test", Roots: [][]byte{f.NativeProviders.Root}, MaxConnections: 2}, AuditStore: contracts.OwnerAuditStore{Endpoint: f.NativeProviders.S3, Roots: [][]byte{f.NativeProviders.Root}, Region: "us-east-1", Bucket: "initial-handover"}, KeyService: contracts.ConfigurationKeyService{Endpoint: f.NativeProviders.KMS, Roots: [][]byte{f.NativeProviders.Root}, AuditMount: "initial-handover-transit", AuditKey: "audit"}}
		c.Kubernetes = c.Services.Kubernetes
		c.SQLMaterial = &materialRef
		c.Providers = &profile
		bucket := c.Services.AuditStore.Bucket
		s3client := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(f.NativeProviders.S3), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", ""), HTTPClient: providerHTTP})
		if _, e = s3client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); e != nil {
			t.Fatal(e)
		}
		// The activation writes its audit through the versioned audit store,
		// which refuses a receipt without an immutable version (as in the
		// chain and Helm fixtures).
		if _, e = s3client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); e != nil {
			t.Fatal(e)
		}
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
		var originalSchema contracts.InitialPreparationSchema
		if initializeSchema {
			originalSchema = initialMountedSchemaHandover(t, ctx, admin, api, c, adminToken, probe.Status.Token)
		}
		historySeed, e := postgres.NewInitialSQLCredentials(c.Plan.InstallationID, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		historyName, e := postgres.InitialSQLHistoryRoleName(c.Plan.InstallationID)
		if e != nil {
			t.Fatal(e)
		}
		historyCredential, _ := json.Marshal(contracts.OwnerSQLCredential{Username: historyName, Password: historySeed.Preparation.Password})
		write("sql-history.json", historyCredential)
		clear(historyCredential)
		if initializeSchema {
			initialSchemaConstructorMismatch(t, ctx, admin, api, c, files)
		}
		// Watch before any target CREATE; retained terminal data comes from the
		// real API, not a synthesized replacement Pod or inferred image tag.
		watcher, e := api.CoreV1().Pods("").Watch(ctx, meta.ListOptions{FieldSelector: "metadata.name=" + c.Plan.Workload.Name})
		if e != nil {
			t.Fatal(e)
		}
		terminals := make(chan *core.Pod, 1)
		joined := make(chan struct{})
		go func() {
			defer close(joined)
			for event := range watcher.ResultChan() {
				pod, ok := event.Object.(*core.Pod)
				if !ok || pod.Namespace != c.Plan.Workload.Namespace || pod.Name != c.Plan.Workload.Name {
					continue
				}
				if pod.Status.Phase == core.PodSucceeded || pod.Status.Phase == core.PodFailed {
					terminals <- pod.DeepCopy()
					return
				}
			}
		}()
		defer func() { watcher.Stop(); <-joined }()
		run := func(t *testing.T) contracts.InitialPreparationRoot {
			t.Helper()
			deployment, err := bootstrap.NewInitialPreparationDeployment(ctx, files)
			if err != nil {
				t.Fatal("actual handover loader", err)
			}
			defer deployment.Close()
			out, err := deployment.Run()
			if err != nil {
				// Diagnostics only: the original Pod's own last output, read
				// after the product already returned its verdict.
				logs, le := api.CoreV1().Pods(c.Plan.Workload.Namespace).GetLogs(c.Plan.Workload.Name, &core.PodLogOptions{TailLines: ptr.To(int64(40))}).DoRaw(context.Background())
				t.Logf("original activation Pod logs (err=%v):\n%s", le, logs)
				t.Fatal("actual handover Run", err)
			}
			return out
		}
		out := run(t)
		if initializeSchema && (out.Schema == nil || !initialSchemaHandoverSame(*out.Schema, originalSchema)) {
			t.Fatal("activation handover changed the original completed schema binding")
		}
		var terminal *core.Pod
		observation, stopObservation := context.WithTimeout(ctx, 5*time.Second)
		defer stopObservation()
		select {
		case terminal = <-terminals:
		case <-observation.Done():
			t.Fatal("original Pod terminal observation missing")
		}
		if out.Activation == nil || out.Activation.Pod == nil || out.Activation.Pod.Receipt == nil || terminal.UID != types.UID(out.Activation.Pod.Receipt.UID) || terminal.Status.Phase != core.PodSucceeded || len(terminal.Status.ContainerStatuses) != 1 {
			t.Fatal("original activation Pod did not succeed")
		}
		status := terminal.Status.ContainerStatuses[0]
		digest := strings.Split(f.WorkerImage, "@")
		if len(digest) != 2 || !strings.HasSuffix(status.ImageID, digest[1]) || status.RestartCount != 0 || status.State.Terminated == nil || status.State.Terminated.ExitCode != 0 {
			t.Fatal("wrong activation image/process outcome")
		}
		t.Log("actual original activation Pod", terminal.UID, "image", status.ImageID, "exit", status.State.Terminated.ExitCode)
		if out.Activation.Handover == nil || out.Activation.Handover.Cleanup == nil {
			t.Fatal("completed handover lacks cleanup disposition")
		}
		cleanup := out.Activation.Handover.Cleanup
		wantSteps := []string{"sql", "wrap", "unwrap", "probe", "target-secrets", "setup-rbac", "private-state", "pod"}
		if len(cleanup.Steps) != len(wantSteps) {
			t.Fatal("cleanup not complete")
		}
		prior := cleanup.StartedAt
		for i, step := range cleanup.Steps {
			if step.Step != wantSteps[i] || step.CompletedAt.IsZero() || step.CompletedAt.Before(prior) || step.CompletedAt.After(time.Now()) {
				t.Fatal("invalid cleanup ordering")
			}
			prior = step.CompletedAt
		}
		if _, err := api.CoreV1().Pods(c.Plan.Workload.Namespace).Get(ctx, c.Plan.Workload.Name, meta.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatal("original Pod was not removed by product cleanup", err)
		}
		if _, err := api.CoreV1().Secrets(c.Plan.Workload.Namespace).Get(ctx, c.Plan.Workload.Credentials, meta.GetOptions{}); !apierrors.IsNotFound(err) {
			t.Fatal("activation projection remains after cleanup", err)
		}
		private, err := api.CoreV1().Secrets(c.Plan.BootstrapNamespace.Name).Get(ctx, c.Plan.PrivateState.Name, meta.GetOptions{})
		if err != nil || string(private.UID) != c.Plan.PrivateState.UID || len(private.Data) != 1 || string(private.Data["retired"]) != "true" || private.Immutable == nil || !*private.Immutable {
			t.Fatal("private original material was not cleared in place", err)
		}
		var recordBytes, receiptBytes []byte
		var activated, blocked bool
		if e = admin.QueryRow(ctx, "SELECT record_json,audit_receipt_json,activated_at IS NOT NULL FROM fleet_initial_activation WHERE installation_id=$1", c.Plan.InstallationID).Scan(&recordBytes, &receiptBytes, &activated); e != nil || !activated {
			t.Fatal("actual audited SQL activation missing", e)
		}
		if e = admin.QueryRow(ctx, "SELECT recovery_blocked FROM fleet_current_trust WHERE installation_id=$1", c.Plan.InstallationID).Scan(&blocked); e != nil || blocked {
			t.Fatal("current database incarnation was not activated", e)
		}
		var record audit.InitialInstallation
		var receipt audit.Receipt
		if json.Unmarshal(recordBytes, &record) != nil || json.Unmarshal(receiptBytes, &receipt) != nil || !record.Valid() || !receipt.ValidInitialInstallation(c.Plan.InstallationID, record.Claim.ID) {
			t.Fatal("invalid retained activation audit")
		}
		startup, err := api.CoreV1().ConfigMaps(c.Plan.Workload.Namespace).Get(ctx, c.Plan.Workload.Configuration, meta.GetOptions{})
		if err != nil || startup.Immutable == nil || !*startup.Immutable || len(startup.Data) != 1 {
			t.Fatal("original immutable startup missing", err)
		}
		expectedPlan := sha256.Sum256([]byte(startup.Data["deployment.json"]))
		if [32]byte(record.Claim.PlanDigest) != expectedPlan || cleanup.ActivatedClaimID != record.Claim.ID || record.Scope.InstallationID != c.Plan.InstallationID || record.Scope.ClusterID != c.Plan.ClusterID || record.Scope.Namespace != c.Plan.Workload.Namespace {
			t.Fatal("activation audit differs from original startup/cleanup scope")
		}
		object, e := s3client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &receipt.Key, VersionId: &receipt.Version})
		if e != nil {
			t.Fatal("immutable audit version unavailable", e)
		}
		encrypted, e := io.ReadAll(io.LimitReader(object.Body, 128<<10+1))
		object.Body.Close()
		defer clear(encrypted)
		if e != nil || len(encrypted) > 128<<10 || int64(len(encrypted)) != receipt.Bytes || sha256.Sum256(encrypted) != [32]byte(receipt.SHA256) {
			t.Fatal("immutable audit bytes differ")
		}
		// Fixture-only independent verifier: never installation activation authority.
		opener, e := kms.NewOpener(f.NativeProviders.KMS, "synthetic-root", "initial-handover-transit", "audit", providerHTTP)
		if e != nil {
			t.Fatal(e)
		}
		if e = framed.VerifyInitialInstallation(ctx, opener, record, encrypted); e != nil {
			t.Fatal("actual encrypted audit verification failed", e)
		}
		// Force passive startup to prove that no maintenance/issuer fallback is used.
		if e = os.Remove(filepath.Join(dir, "sql-maintenance.json")); e != nil {
			t.Fatal(e)
		}
		request(t, f.KMS, "synthetic-root", "auth/token/revoke", map[string]any{"token": issuerToken}, 204)
		t.Run("passive-reopen-after-credential-retirement", func(t *testing.T) {
			after := run(t)
			if after.RootUID != out.RootUID || after.Activation == nil || after.Activation.Pod == nil || after.Activation.Pod.Receipt == nil || after.Activation.Pod.Receipt.UID != string(terminal.UID) {
				t.Fatal("passive history changed original identity")
			}
			if initializeSchema && (after.Schema == nil || !initialSchemaHandoverSame(*after.Schema, originalSchema)) {
				t.Fatal("passive reopen changed the original completed schema binding")
			}
			var count int
			if err := admin.QueryRow(ctx, "SELECT count(*) FROM fleet_initial_activation WHERE installation_id=$1", c.Plan.InstallationID).Scan(&count); err != nil || count != 1 {
				t.Fatal("passive read created/replaced activation", err)
			}
		})
		t.Log("actual original loader-to-Pod activation, exact compiled image and immutable encrypted audit; passive restart with setup credentials unavailable. Fixture supplies bootstrap/provider roots only; no public investigation runtime enabled")
	})
}
