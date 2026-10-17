package integration

import (
	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5/pgxpool"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"net/url"
	"testing"
	"time"
)

// The test explicitly refreshes the real source/projection before driver use.
// Runtime supervision will do this independently; no fixture grace period exists.
type refreshedWorkerConfiguration struct {
	observer *evidence.WorkerConfigurationObserver
	current  *postgres.WorkerConfigurations
}

func (f refreshedWorkerConfiguration) CurrentWorkerConfiguration(c context.Context, p value.DownloadWorkerProfile) (time.Time, error) {
	if e := f.observer.Observe(c); e != nil {
		return time.Time{}, e
	}
	return f.current.CurrentWorkerConfiguration(c, p)
}

func qualifiedWorkerConfiguration(t *testing.T, ctx context.Context, f fixture, admin kubernetes.Interface, config *rest.Config, p value.DownloadWorkerProfile) (value.DownloadWorkerProfile, evidence.WorkerConfigurationGuard) {
	t.Helper()
	epoch := custodyID()
	wire := contracts.WorkerConfiguration{Format: "asservat-worker-configuration/v1", InstallationID: p.InstallationID, ClusterID: p.ClusterID, RecoveryEpoch: epoch, Revision: 1, Namespace: contracts.WorkerObjectReference{Name: p.Namespace, UID: p.NamespaceUID}, ServiceAccount: contracts.WorkerObjectReference{Name: p.ServiceAccount, UID: p.ServiceAccountUID}, PriorityClass: contracts.WorkerObjectReference{Name: p.PriorityClass, UID: p.PriorityClassUID}, ControlConfig: contracts.LocalKeySecretReference{Name: p.ControlConfig, UID: p.ControlConfigUID, SHA256: hex.EncodeToString(p.ControlDigest[:])}, Image: p.Image, ImagePullSecrets: []string{}, CPUMillis: p.CPUMillis, MemoryBytes: p.MemoryBytes, MaxRuntimeSeconds: int64(p.MaxRuntime / time.Second)}
	if p.StoreCredentialSecret != "" {
		wire.Format = "asservat-worker-configuration/v2"
		wire.StoreCredentials = &contracts.WorkerObjectReference{Name: p.StoreCredentialSecret, UID: p.StoreCredentialSecretUID}
	}
	raw, _ := json.Marshal(wire)
	object, e := admin.CoreV1().ConfigMaps(p.Namespace).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: "worker-profile"}, Data: map[string]string{"worker-profile.json": string(raw)}}, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	who, e := admin.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if e != nil || who.Status.UserInfo.Username == "" {
		t.Fatal("fixture administrator identity", e)
	}
	plan := cfg.WorkerAdministration{Name: "asservat-worker-" + p.Namespace, SourceName: object.Name, ControlNamespace: cfg.NamespaceRef{Name: p.Namespace, UID: p.NamespaceUID}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: who.Status.UserInfo.Username}}}
	policy, binding, e := kube.WorkerConfigurationAdmission(plan)
	if e != nil {
		t.Fatal(e)
	}
	policy, e = admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, policy, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	binding, e = admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	readerSA := "worker-profile-reader"
	probeSA := "worker-profile-probe"
	makeClient := func(name string) (*kube.PermissionClient, kubernetes.Interface) {
		t.Helper()
		if _, e := admin.CoreV1().ServiceAccounts(p.Namespace).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name}}, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		token, e := admin.CoreV1().ServiceAccounts(p.Namespace).CreateToken(ctx, name, &auth.TokenRequest{}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		c := &rest.Config{Host: config.Host, BearerToken: token.Status.Token, TLSClientConfig: config.TLSClientConfig}
		c.TLSClientConfig.CertData = nil
		c.TLSClientConfig.KeyData = nil
		c.TLSClientConfig.CertFile = ""
		c.TLSClientConfig.KeyFile = ""
		client, e := kube.NewPermissionClient(c, p.ClusterID, plan.ControlNamespace, time.Now)
		if e != nil {
			t.Fatal(e)
		}
		api, e := kubernetes.NewForConfig(c)
		if e != nil {
			t.Fatal(e)
		}
		return client, api
	}
	reader, limited := makeClient(readerSA)
	probe, probeAPI := makeClient(probeSA)
	role := &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: plan.Name}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{p.Namespace}, Verbs: []string{"get"}}, {APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{plan.Name}, Verbs: []string{"get"}}}}
	if _, e = admin.RbacV1().ClusterRoles().Create(ctx, role, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	if _, e = admin.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: plan.Name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: readerSA, Namespace: p.Namespace}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: plan.Name}}, meta.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{readerSA, probeSA} {
		verbs := []string{"get"}
		if name == probeSA {
			verbs = append(verbs, "update", "patch", "delete")
		}
		if _, e = admin.RbacV1().Roles(p.Namespace).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: name}, Rules: []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{object.Name}, Verbs: verbs}}}, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
		if _, e = admin.RbacV1().RoleBindings(p.Namespace).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, Subjects: []rbac.Subject{{Kind: "ServiceAccount", Name: name, Namespace: p.Namespace}}, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: name}}, meta.CreateOptions{}); e != nil {
			t.Fatal(e)
		}
	}
	if p.StoreCredentialSecret != "" {
		role, err := admin.RbacV1().Roles(p.Namespace).Get(ctx, readerSA, meta.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		role.Rules = append(role.Rules, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{p.StoreCredentialSecret}, Verbs: []string{"get"}})
		if _, err = admin.RbacV1().Roles(p.Namespace).Update(ctx, role, meta.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	pin := kube.GuardPin{PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, BindingUID: string(binding.UID), BindingResourceVersion: binding.ResourceVersion}
	guard, e := kube.NewWorkerConfigurationProtection(reader, probe, plan, pin)
	if e != nil {
		t.Fatal(e)
	}
	source, e := kube.NewWorkerConfigurationSource(reader, guard, object.Name, string(object.UID), p.InstallationID)
	if e != nil {
		t.Fatal(e)
	}
	var observation value.DownloadWorkerObservation
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		observation, e = source.ReadWorkerConfiguration(ctx)
		if e == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if e != nil {
		if latest, readErr := admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, plan.Name, meta.GetOptions{}); readErr == nil {
			t.Logf("synthetic admission status: %+v", latest.Status)
		}
		t.Fatal("qualified worker configuration source", e)
	}
	p = observation.Configuration.Profile
	if _, e = limited.CoreV1().ConfigMaps(p.Namespace).Update(ctx, object, meta.UpdateOptions{}); !apierrors.IsForbidden(e) {
		t.Fatal("source reader gained mutation", e)
	}
	if _, e = probeAPI.CoreV1().ConfigMaps(p.Namespace).Patch(ctx, object.Name, types.MergePatchType, []byte(`{"data":{"worker-profile.json":"forged"}}`), meta.PatchOptions{}); e == nil {
		t.Fatal("non-administrator replaced profile")
	}
	if e = probeAPI.CoreV1().ConfigMaps(p.Namespace).Delete(ctx, object.Name, meta.DeleteOptions{}); e == nil {
		t.Fatal("non-administrator deleted profile")
	}
	// Real PostgreSQL/S3 with synthetic recovery root and audit wrapping keys.
	sqlAdmin, e := pgxpool.New(ctx, f.Postgres)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(sqlAdmin.Close)
	if _, e = sqlAdmin.Exec(ctx, "INSERT INTO fleet_trust(activated_postmaster_at,activated_database_oid,installation_id,issuer_epoch,source_uid,source_generation,source_digest,suspended,recovery_blocked,observed_at,fresh_until) VALUES(pg_catalog.pg_postmaster_start_time(),(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),$1,$2,'synthetic-worker-configuration',1,$3,false,false,statement_timestamp(),statement_timestamp()+interval '30 seconds')", p.InstallationID, epoch, bytes.Repeat([]byte{42}, 32)); e != nil {
		t.Fatal(e)
	}
	if _, err := seedSyntheticFleetObservation(ctx, sqlAdmin, p.InstallationID); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(f.Postgres)
	address, tlsConfig := pgTLSBridge(t, u.Host)
	makeLedger := func(role, password string) *postgres.WorkerConfigurations {
		t.Helper()
		pc, e := pgxpool.ParseConfig("postgres://" + role + ":" + password + "@" + address + "/custody_test?sslmode=disable")
		if e != nil {
			t.Fatal(e)
		}
		pc.ConnConfig.TLSConfig = tlsConfig
		pc.ConnConfig.Fallbacks = nil
		pc.MaxConns = 4
		pool, e := pgxpool.NewWithConfig(ctx, pc)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(pool.Close)
		l, e := postgres.NewWorkerConfigurations(ctx, pool, p.InstallationID, p.ClusterID, p.NamespaceUID, p.Configuration.UID)
		if e != nil {
			t.Fatal(e)
		}
		return l
	}
	l := makeLedger("worker_configuration_runtime", "synthetic-worker-configuration")
	ack := makeLedger("worker_configuration_audit_runtime", "synthetic-worker-configuration-audit")
	current := makeLedger("worker_configuration_read_runtime", "synthetic-worker-configuration-read")
	tls := tlsBridge(t, f.S3)
	creds := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	s3admin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: &tls.URL, UsePathStyle: true, Credentials: creds, HTTPClient: tls.Client(), RetryMaxAttempts: 1})
	if _, e = s3admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String("worker-configuration-" + p.Namespace)}); e != nil {
		t.Fatal(e)
	}
	if _, e = s3admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String("worker-configuration-" + p.Namespace), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); e != nil {
		t.Fatal(e)
	}
	store, e := objectstore.New(tls.URL, "us-east-1", "worker-configuration-"+p.Namespace, creds, tls.Client())
	if e != nil {
		t.Fatal(e)
	}
	material := make([]byte, 32)
	if _, e = rand.Read(material); e != nil {
		t.Fatal(e)
	}
	block, e := aes.NewCipher(material)
	clear(material)
	if e != nil {
		t.Fatal(e)
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		t.Fatal(e)
	}
	keys := authorityTestKeys{a: aead}
	observer := &evidence.WorkerConfigurationObserver{Reader: source, Ledger: l, Audit: &objectstore.WorkerConfigurationAuditObjects{Store: store, Seal: keys, Open: keys}, Acknowledgements: ack, Now: time.Now}
	if _, e = current.CurrentWorkerConfiguration(ctx, p); e == nil {
		t.Fatal("missing profile accepted")
	}
	if _, _, e = l.ObserveWorkerConfiguration(ctx, observation); e != nil {
		t.Fatal(e)
	}
	if _, e = current.CurrentWorkerConfiguration(ctx, p); e == nil {
		t.Fatal("unaudited profile accepted")
	}
	if e = observer.Observe(ctx); e != nil {
		t.Fatal(e)
	}
	// Removing protection denies the next source read and fences the projection.
	if e = admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, binding.Name, meta.DeleteOptions{}); e != nil {
		t.Fatal(e)
	}
	if e = observer.Observe(ctx); e == nil {
		t.Fatal("missing protection accepted")
	}
	if _, e = current.CurrentWorkerConfiguration(ctx, p); e == nil {
		t.Fatal("missing protection left profile active")
	}
	// Reinstalling protection is an explicit new bootstrap pin. Its digest
	// requires a fresh administrator revision and a new encrypted audit record.
	binding.ResourceVersion = ""
	binding.UID = ""
	binding.CreationTimestamp = meta.Time{}
	binding.ManagedFields = nil
	binding, e = admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, binding, meta.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	pin.BindingUID = string(binding.UID)
	pin.BindingResourceVersion = binding.ResourceVersion
	guard, e = kube.NewWorkerConfigurationProtection(reader, probe, plan, pin)
	if e != nil {
		t.Fatal(e)
	}
	source, e = kube.NewWorkerConfigurationSource(reader, guard, object.Name, string(object.UID), p.InstallationID)
	if e != nil {
		t.Fatal(e)
	}
	wire.Revision++
	raw, _ = json.Marshal(wire)
	object.Data["worker-profile.json"] = string(raw)
	if _, e = admin.CoreV1().ConfigMaps(p.Namespace).Update(ctx, object, meta.UpdateOptions{}); e != nil {
		t.Fatal(e)
	}
	observer.Reader = source
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		e = observer.Observe(ctx)
		if e == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if e != nil {
		t.Fatal("requalified configuration", e)
	}
	observation, e = source.ReadWorkerConfiguration(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = current.CurrentWorkerConfiguration(ctx, p); e == nil {
		t.Fatal("old profile survived rollout")
	}
	p = observation.Configuration.Profile
	t.Log("actual ConfigMap admission/update/delete protection, named reader RBAC, fail-closed missing guard, audited SQL projection and revision rollover passed; installation recovery and audit keys are fixture inputs")
	return p, refreshedWorkerConfiguration{observer, current}
}
