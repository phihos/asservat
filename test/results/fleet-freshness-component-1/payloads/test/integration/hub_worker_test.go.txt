package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5/pgxpool"
	admission "k8s.io/api/admissionregistration/v1"
	auth "k8s.io/api/authentication/v1"
	coordination "k8s.io/api/coordination/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// This fixture runs real protected sources and reconciliation through mounted
// scoped providers. A single explicit administrator step models initial recovery
// acceptance; no fixture timer refreshes SQL authority or acknowledges audit.
func TestHubConfigurationWorkerWithRealKubernetes(t *testing.T) { runHubConfigurationWorker(t, false) }
func TestHubConfigurationWorkerInRestrictedPod(t *testing.T)    { runHubConfigurationWorker(t, true) }
func runHubConfigurationWorker(t *testing.T, native bool) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("run make context-integration")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if json.Unmarshal(b, &f) != nil || len(f.Clusters) == 0 {
		t.Fatal("fixtures unavailable")
	}
	clear(b)
	ctx, end := context.WithTimeout(context.Background(), 120*time.Second)
	defer end()
	kc, err := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	api, err := kubernetes.NewForConfig(kc)
	if err != nil {
		t.Fatal(err)
	}
	namespace := "configuration-worker"
	if native {
		namespace += "-pod"
	}
	ns, err := api.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: namespace, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	who, err := api.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	installation, cluster, epoch := custodyID(), custodyID(), custodyID()
	bao, storage := tlsBridge(t, f.KMS), tlsBridge(t, f.S3)
	baoURL, storageURL := bao.URL, storage.URL
	baoRoot, storageRoot := bao.Certificate().Raw, storage.Certificate().Raw
	storageHTTP := storage.Client()
	if native {
		if f.WorkerImage == "" || f.NativeProviders.Postgres == "" {
			t.Fatal("native fixture unavailable")
		}
		baoURL, storageURL = f.NativeProviders.KMS, f.NativeProviders.S3
		baoRoot, storageRoot = f.NativeProviders.Root, f.NativeProviders.Root
		cert, e := x509.ParseCertificate(f.NativeProviders.Root)
		if e != nil {
			t.Fatal(e)
		}
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
		storageHTTP = &http.Client{Transport: transport, Timeout: 5 * time.Second}
		defer transport.CloseIdleConnections()
	}
	ref := func(name, uid string) contracts.WorkerObjectReference {
		return contracts.WorkerObjectReference{Name: name, UID: uid}
	}
	fleet := contracts.FleetSettings{SchemaVersion: "fleet-settings/v1", Revision: 1, InstallationID: installation, IssuerEpoch: epoch, Issuer: "https://identity.synthetic.invalid", Clients: []string{"console"}, Subjects: []contracts.IdentitySubject{}, Groups: []string{}, DeliveryProfiles: []string{"operators"}, MaxActiveBootstraps: 2, MaxBootstrapHistory: 4, MaxClusters: 2}
	owner := contracts.OwnerConfiguration{Format: contracts.OwnerConfigurationFormat, InstallationID: installation, ClusterID: cluster, IssuerEpoch: epoch, Revision: 1, Namespace: ref(ns.Name, string(ns.UID)), Service: ref("owner", custodyID()), Deployment: ref("owner", custodyID()), ServiceAccount: ref("owner", custodyID()), Port: 9443, IssuerRoots: [][]byte{baoRoot}}
	create := func(name, key string, v any) *core.ConfigMap {
		t.Helper()
		raw, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		cm, e := api.CoreV1().ConfigMaps(ns.Name).Create(ctx, &core.ConfigMap{ObjectMeta: meta.ObjectMeta{Name: name}, Data: map[string]string{key: string(raw)}}, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		return cm
	}
	fleetCM, ownerCM := create("fleet", "fleet.json", fleet), create("owner", "owner-pool.json", owner)
	protect := func(name, source string, build func(cfg.ConfigMapAdministration) (*admission.ValidatingAdmissionPolicy, *admission.ValidatingAdmissionPolicyBinding, error)) contracts.OwnerDeploymentGuard {
		t.Helper()
		plan := cfg.ConfigMapAdministration{Name: name, SourceName: source, ControlNamespace: cfg.NamespaceRef{Name: ns.Name, UID: string(ns.UID)}, Administrators: []cfg.KubernetesActor{{Kind: "User", Name: who.Status.UserInfo.Username}}}
		p, b, e := build(plan)
		if e != nil {
			t.Fatal(e)
		}
		p, e = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, p, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		b, e = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Create(ctx, b, meta.CreateOptions{})
		if e != nil {
			t.Fatal(e)
		}
		return contracts.OwnerDeploymentGuard{Name: name, PolicyUID: string(p.UID), PolicyGeneration: p.Generation, BindingUID: string(b.UID), BindingResourceVersion: b.ResourceVersion, Administrators: []contracts.OwnerDeploymentActor{{Kind: "User", Name: who.Status.UserInfo.Username}}}
	}
	fg := protect(namespace+"-fleet", fleetCM.Name, kube.FleetConfigurationAdmission)
	og := protect(namespace+"-owner", ownerCM.Name, kube.OwnerConfigurationAdmission)
	lease, err := api.CoordinationV1().Leases(ns.Name).Create(ctx, &coordination.Lease{ObjectMeta: meta.ObjectMeta{Name: "reconcile"}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ca := kc.CAData
	if len(ca) == 0 {
		ca, err = os.ReadFile(kc.CAFile)
		if err != nil {
			t.Fatal(err)
		}
	}
	caBlock, _ := pem.Decode(ca)
	if caBlock == nil {
		t.Fatal("API root missing")
	}
	pgURL, err := url.Parse(f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	address, pgTLS := pgTLSBridge(t, pgURL.Host)
	if native {
		address = f.NativeProviders.Postgres
		cert, e := x509.ParseCertificate(f.NativeProviders.Root)
		if e != nil {
			t.Fatal(e)
		}
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		server, _, e := net.SplitHostPort(address)
		if e != nil {
			t.Fatal(e)
		}
		pgTLS = &tls.Config{RootCAs: roots, ServerName: server, MinVersion: tls.VersionTLS13}
	}
	raw, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err = raw.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = raw.Write([]byte{0, 0, 0, 8, 4, 210, 22, 47}); err != nil {
		t.Fatal(err)
	}
	var response [1]byte
	if _, err = io.ReadFull(raw, response[:]); err != nil || response[0] != 'S' {
		t.Fatal("PG TLS unavailable", err)
	}
	tlsConn := tls.Client(raw, pgTLS)
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	pgRoot := tlsConn.ConnectionState().PeerCertificates[0].Raw
	tlsConn.Close()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	bucket := "configuration-worker-" + custodyID()
	s3admin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: &storageURL, UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", ""), HTTPClient: storageHTTP, RetryMaxAttempts: 1})
	if _, err = s3admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	// Active owner audit requires real immutable versions, including legacy input formats.
	if _, err = s3admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	c := contracts.HubWorkerDeployment{Format: contracts.HubWorkerDeploymentFormat, InstallationID: installation, ClusterID: cluster, Namespace: ref(ns.Name, string(ns.UID)), FleetSource: ref(fleetCM.Name, string(fleetCM.UID)), OwnerSource: ref(ownerCM.Name, string(ownerCM.UID)), FleetGuard: fg, OwnerGuard: og, LeaderLease: ref(lease.Name, string(lease.UID)), Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: kc.Host, Roots: [][]byte{caBlock.Bytes}}, Postgres: contracts.OwnerPostgresEndpoint{Host: host, Port: port, Database: "custody_test", Roots: [][]byte{pgRoot}, MaxConnections: 2}, AuditStore: contracts.OwnerAuditStore{Endpoint: storageURL, Roots: [][]byte{storageRoot}, Region: "us-east-1", Bucket: bucket}, KeyService: contracts.ConfigurationKeyService{Endpoint: baoURL, Roots: [][]byte{baoRoot}, AuditMount: namespace + "-audit", AuditKey: "records"}}
	if native {
		c.Kubernetes.Endpoint = "https://kubernetes.default.svc"
	}
	dir := t.TempDir()
	write := func(name string, b []byte) {
		t.Helper()
		if e := os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	writeJSON := func(name string, v any) {
		t.Helper()
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		write(name, b)
	}
	writeJSON("deployment.json", c)
	writeJSON("audit-storage.json", contracts.OwnerStorageCredential{AccessKeyID: "synthetic-only", SecretAccessKey: "synthetic-only-secret"})
	for _, r := range []struct{ file, user, password string }{{"fleet", "fleet_observe_runtime", "synthetic-fleet-observe"}, {"configuration", "owner_configuration_runtime", "synthetic-owner-configuration"}, {"audit", "owner_configuration_audit_runtime", "synthetic-owner-configuration-audit"}} {
		writeJSON("sql-"+r.file+".json", contracts.OwnerSQLCredential{Username: r.user, Password: r.password})
	}
	if !native {
		for _, role := range []string{"observer", "probe", "leader"} {
			name := "configuration-worker-" + role
			if _, err = api.CoreV1().ServiceAccounts(ns.Name).Create(ctx, &core.ServiceAccount{ObjectMeta: meta.ObjectMeta{Name: name}}, meta.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			rules := []rbac.PolicyRule{}
			if role == "leader" {
				rules = append(rules, rbac.PolicyRule{APIGroups: []string{"coordination.k8s.io"}, Resources: []string{"leases"}, ResourceNames: []string{lease.Name}, Verbs: []string{"get", "update"}})
			} else {
				verbs := []string{"get"}
				if role == "probe" {
					verbs = append(verbs, "update")
				}
				rules = append(rules, rbac.PolicyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, ResourceNames: []string{fleetCM.Name, ownerCM.Name}, Verbs: verbs})
			}
			if _, err = api.RbacV1().Roles(ns.Name).Create(ctx, &rbac.Role{ObjectMeta: meta.ObjectMeta{Name: name}, Rules: rules}, meta.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			subjects := []rbac.Subject{{Kind: "ServiceAccount", Name: name, Namespace: ns.Name}}
			if _, err = api.RbacV1().RoleBindings(ns.Name).Create(ctx, &rbac.RoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "Role", Name: name}}, meta.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
			if role != "probe" {
				rules = []rbac.PolicyRule{{APIGroups: []string{""}, Resources: []string{"namespaces"}, ResourceNames: []string{ns.Name}, Verbs: []string{"get"}}}
				if role == "observer" {
					rules = append(rules, rbac.PolicyRule{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingadmissionpolicies", "validatingadmissionpolicybindings"}, ResourceNames: []string{fg.Name, og.Name}, Verbs: []string{"get"}})
				}
				if _, err = api.RbacV1().ClusterRoles().Create(ctx, &rbac.ClusterRole{ObjectMeta: meta.ObjectMeta{Name: name}, Rules: rules}, meta.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
				if _, err = api.RbacV1().ClusterRoleBindings().Create(ctx, &rbac.ClusterRoleBinding{ObjectMeta: meta.ObjectMeta{Name: name}, Subjects: subjects, RoleRef: rbac.RoleRef{APIGroup: rbac.GroupName, Kind: "ClusterRole", Name: name}}, meta.CreateOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			token, e := api.CoreV1().ServiceAccounts(ns.Name).CreateToken(ctx, name, &auth.TokenRequest{}, meta.CreateOptions{})
			if e != nil {
				t.Fatal(e)
			}
			write("kube-"+role+".token", []byte(token.Status.Token))
		}
		protectHubWorkerNamespace(t, ctx, api, kc, owner, lease)
	}
	request(t, f.KMS, "synthetic-root", "sys/mounts/"+c.KeyService.AuditMount, map[string]any{"type": "transit"}, 204)
	request(t, f.KMS, "synthetic-root", c.KeyService.AuditMount+"/keys/records", map[string]any{"type": "aes256-gcm96"}, 200)
	for file, operation := range map[string]string{"audit-wrap.token": "encrypt", "audit-unwrap.token": "decrypt"} {
		name := namespace + "-" + operation
		request(t, f.KMS, "synthetic-root", "sys/policies/acl/"+name, map[string]any{"policy": `path "` + c.KeyService.AuditMount + `/` + operation + `/records" { capabilities=["update"] }`}, 204)
		r := request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{name}, "no_default_policy": true, "ttl": "15m"}, 200)
		write(file, []byte(r["auth"].(map[string]any)["client_token"].(string)))
	}
	var done chan error
	if native {
		done = startNativeHubWorker(t, ctx, api, kc, c, f.WorkerImage, dir, who.Status.UserInfo.Username)
	} else {
		files, e := os.OpenRoot(dir)
		if e != nil {
			t.Fatal(e)
		}
		defer files.Close()
		d, e := bootstrap.NewHubWorkerDeployment(ctx, files)
		if e != nil {
			t.Fatal("worker construction", e)
		}
		done = make(chan error, 1)
		go func() { done <- d.Run() }()
		defer func() {
			d.Close()
			select {
			case <-done:
			case <-time.After(8 * time.Second):
				t.Error("worker did not stop")
			}
		}()
	}
	db, err := pgxpool.New(ctx, f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	readerConfig, err := pgxpool.ParseConfig("postgres://owner_configuration_read_runtime:synthetic-owner-configuration-read@" + address + "/custody_test?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	readerConfig.ConnConfig.TLSConfig = pgTLS
	readerConfig.ConnConfig.Fallbacks = nil
	readerPool, err := pgxpool.NewWithConfig(ctx, readerConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer readerPool.Close()
	current, err := postgres.NewOwnerConfigurations(ctx, readerPool, installation, cluster, string(ns.UID), string(ownerCM.UID))
	if err != nil {
		t.Fatal(err)
	}
	await := func(label string, check func() bool) {
		t.Helper()
		until := time.Now().Add(16 * time.Second)
		for time.Now().Before(until) {
			if check() {
				return
			}
			select {
			case err := <-done:
				done <- err
				t.Fatal("worker stopped before "+label, err)
			default:
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal(label)
	}
	await("initial blocked root", func() bool {
		var blocked bool
		e := db.QueryRow(ctx, "SELECT recovery_blocked FROM fleet_trust WHERE installation_id=$1", installation).Scan(&blocked)
		return e == nil && blocked
	})
	if _, err = current.ReadOwnerConfiguration(ctx); err == nil {
		t.Fatal("observer cleared recovery")
	}
	// The only fixture authority transition; ordinary runtime observation cannot
	// execute it, and no background fixture refresh follows it.
	if _, err = db.Exec(ctx, "UPDATE fleet_trust SET activated_postmaster_at=pg_catalog.pg_postmaster_start_time(),activated_database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database()),recovery_blocked=false WHERE installation_id=$1", installation); err != nil {
		t.Fatal(err)
	}
	if _, err = seedSyntheticFleetObservation(ctx, db, installation); err != nil {
		t.Fatal(err)
	}
	await("audited current owner configuration", func() bool { _, e := current.ReadOwnerConfiguration(ctx); return e == nil })
	// Removing the admission binding must fence fleet trust even though the
	// source data and read permissions remain unchanged.
	if err = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(ctx, fg.Name, meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	await("removed source protection fenced SQL", func() bool {
		var suspended bool
		e := db.QueryRow(ctx, "SELECT suspended FROM fleet_trust WHERE installation_id=$1", installation).Scan(&suspended)
		return e == nil && suspended
	})
	if _, err = current.ReadOwnerConfiguration(ctx); err == nil {
		t.Fatal("unprotected fleet source remained current")
	}
	// Original Lease UID is a pin, not a discoverable replacement. Loss cancels
	// the leader and joins both source loops without recreating that Lease.
	if err = api.CoordinationV1().Leases(ns.Name).Delete(ctx, lease.Name, meta.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("lease loss reported success")
		}
		done <- err
	case <-time.After(18 * time.Second):
		t.Fatal("lease loss did not stop worker")
	}
	if _, err = api.CoordinationV1().Leases(ns.Name).Get(ctx, lease.Name, meta.GetOptions{}); err == nil {
		t.Fatal("runtime recreated lease")
	}
	t.Logf("nativePod=%t; mounted reconciliation used real protected sources, scheduling Lease and scoped SQL/S3/OpenBao; missing root stayed recovery-blocked, one fixture recovery acceptance enabled automatic audited observation, guard removal fenced reads and lease loss joined shutdown", native)
}
