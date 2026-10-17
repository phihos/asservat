package integration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/bootstrap"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Actual mounted-input composition runs outside the protected pause Pod in this
// fixture. Kubernetes authority, SQL role grants and scoped providers are real;
// initial recovery acceptance and the mount provisioner remain fixture-owned.
func exerciseNativeOwnerDeployment(t *testing.T, ctx context.Context, f fixture, admin kubernetes.Interface, kubeConfig *rest.Config, pool value.OwnerPool, accepted app.OwnerConfigurationReader, pod core.Pod, token []byte, listener net.Listener) {
	t.Helper()
	current, err := accepted.ReadOwnerConfiguration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := admin.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, "asservat-owner-workload", meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := admin.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, policy.Name, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	who, err := admin.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ca := kubeConfig.CAData
	if len(ca) == 0 {
		ca, err = os.ReadFile(kubeConfig.CAFile)
		if err != nil {
			t.Fatal(err)
		}
	}
	block, _ := pem.Decode(ca)
	if block == nil {
		t.Fatal("fixture API root missing")
	}
	postgresURL, err := url.Parse(f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	address, pgTLS := pgTLSBridge(t, postgresURL.Host)
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
		t.Fatal("fixture TLS response", err)
	}
	secured := tls.Client(raw, pgTLS)
	if err = secured.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	pgRoot := secured.ConnectionState().PeerCertificates[0].Raw
	secured.Close()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	bao := tlsBridge(t, f.KMS)
	storage := tlsBridge(t, f.S3)
	bucket := "owner-deployment-" + custodyID()
	s3admin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: &storage.URL, UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", ""), HTTPClient: storage.Client(), RetryMaxAttempts: 1})
	if _, err = s3admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatal(err)
	}
	// Active owner audit requires real immutable versions, including legacy input formats.
	if _, err = s3admin.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	c := contracts.OwnerDeployment{SchedulingLeases: []contracts.OwnerSchedulingLease{}, ConfigurationProbes: []contracts.OwnerConfigurationProbe{{ConfigMap: "owner-pool", ServiceAccount: "owner-config-probe"}}, Format: contracts.OwnerDeploymentFormat, InstallationID: pool.InstallationID, ClusterID: pool.ClusterID, PermissionRootID: custodyID(), Namespace: contracts.WorkerObjectReference{Name: pool.Namespace, UID: pool.NamespaceUID}, ConfigurationUID: current.Configuration.Revision.UID, Kubernetes: contracts.OwnerProviderEndpoint{Endpoint: kubeConfig.Host, Roots: [][]byte{block.Bytes}}, WorkloadGuard: contracts.OwnerDeploymentGuard{Name: policy.Name, PolicyUID: string(policy.UID), PolicyGeneration: policy.Generation, BindingUID: string(binding.UID), BindingResourceVersion: binding.ResourceVersion, Administrators: []contracts.OwnerDeploymentActor{{Kind: "User", Name: who.Status.UserInfo.Username}}}, Postgres: contracts.OwnerPostgresEndpoint{Host: host, Port: port, Database: "custody_test", Roots: [][]byte{pgRoot}, MaxConnections: 2}, AuditStore: contracts.OwnerAuditStore{Endpoint: storage.URL, Roots: [][]byte{storage.Certificate().Raw}, Region: "us-east-1", Bucket: bucket}, KeyService: contracts.OwnerKeyService{Endpoint: bao.URL, Roots: [][]byte{bao.Certificate().Raw}, AuditMount: "owner-deployment-audit", AuditKey: "records", PKIMount: "owner-native-pki", ServerRole: "deployment-server", ClientRole: "deployment-client"}, Connections: 2, Concurrency: 1}
	dir := t.TempDir()
	write := func(name string, b []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	jsonFile := func(name string, v any) {
		t.Helper()
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		write(name, b)
	}
	jsonFile("deployment.json", c)
	jsonFile("worker-controls.json", contracts.OwnerWorkerTrust{Format: contracts.OwnerWorkerTrustFormat, Controls: [][]byte{}})
	jsonFile("audit-storage.json", contracts.OwnerStorageCredential{AccessKeyID: "synthetic-only", SecretAccessKey: "synthetic-only-secret", SessionToken: ""})
	for _, role := range []struct{ file, user, password string }{
		{"enrollment", "owner_enrollment_runtime", "synthetic-owner-enrollment"},
		{"audit", "owner_enrollment_audit_runtime", "synthetic-owner-enrollment-audit"},
		{"activation", "owner_enrollment_activate_runtime", "synthetic-owner-enrollment-activate"},
		{"registry", "owner_enrollment_read_runtime", "synthetic-owner-enrollment-read"},
		{"routing", "worker_routing_read_runtime", "synthetic-worker-routing-read"},
	} {
		jsonFile("sql-"+role.file+".json", contracts.OwnerSQLCredential{Username: role.user, Password: role.password})
	}
	for file, account := range map[string]string{"kube-observer.token": "owner-workload-reader", "kube-probe.token": "owner-workload-probe"} {
		r, err := admin.CoreV1().ServiceAccounts(pool.Namespace).CreateToken(ctx, account, &auth.TokenRequest{}, meta.CreateOptions{})
		if err != nil {
			t.Fatal(err)
		}
		write(file, []byte(r.Status.Token))
	}
	write("owner-pod.token", token)
	request(t, f.KMS, "synthetic-root", "sys/mounts/owner-deployment-audit", map[string]any{"type": "transit"}, 204)
	request(t, f.KMS, "synthetic-root", "owner-deployment-audit/keys/records", map[string]any{"type": "aes256-gcm96"}, 200)
	providerToken := func(name, path string) []byte {
		t.Helper()
		request(t, f.KMS, "synthetic-root", "sys/policies/acl/"+name, map[string]any{"policy": `path "` + path + `" { capabilities=["update"] }`}, 204)
		r := request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{name}, "no_default_policy": true, "ttl": "15m"}, 200)
		return []byte(r["auth"].(map[string]any)["client_token"].(string))
	}
	for file, path := range map[string]string{"audit-wrap.token": "owner-deployment-audit/encrypt/records", "audit-unwrap.token": "owner-deployment-audit/decrypt/records", "owner-server-sign.token": "owner-native-pki/sign/deployment-server", "owner-client-sign.token": "owner-native-pki/sign/deployment-client"} {
		b := providerToken("deployment-"+file, path)
		write(file, b)
		clear(b)
	}
	// Only the fixture observer maintains these independently qualified current
	// source observations. The loader has no acceptance/recovery-write credential.
	observe, stopObserve := context.WithCancel(ctx)
	observed := make(chan struct{})
	go func() {
		defer close(observed)
		for {
			_, _ = accepted.ReadOwnerConfiguration(observe)
			select {
			case <-observe.Done():
				return
			case <-time.After(250 * time.Millisecond):
			}
		}
	}()
	defer func() {
		stopObserve()
		select {
		case <-observed:
		case <-time.After(6 * time.Second):
			t.Error("fixture observer did not stop")
		}
	}()
	files, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer files.Close()
	d, err := bootstrap.NewOwnerDeployment(ctx, files, string(pod.UID))
	if err != nil {
		t.Fatal("mounted owner construction", err)
	}
	defer d.Close()
	owner := d.Runtime.Binding()
	uri, err := mtls.OwnerURI(owner)
	if err != nil {
		t.Fatal(err)
	}
	name, err := mtls.OwnerServerName(owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, usage := range []string{"server", "client"} {
		role := map[string]any{"require_cn": false, "use_csr_common_name": false, "use_csr_sans": false, "allow_ip_sans": false, "allow_localhost": false, "allowed_uri_sans": []string{uri.String()}, "key_type": "any", "server_flag": usage == "server", "client_flag": usage == "client", "code_signing_flag": false, "email_protection_flag": false, "key_usage": []string{"DigitalSignature"}, "ext_key_usage": []string{}, "basic_constraints_valid_for_non_ca": true, "not_before_duration": "30s", "max_ttl": "1h", "ttl": "20m"}
		if usage == "server" {
			role["allowed_domains"] = []string{name}
			role["allow_bare_domains"] = true
		}
		request(t, f.KMS, "synthetic-root", "owner-native-pki/roles/deployment-"+usage, role, 200)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() { done <- d.Run(listener) }()
	defer func() {
		d.Close()
		select {
		case <-done:
		case <-time.After(7 * time.Second):
			t.Error("mounted owner runtime did not stop")
		}
	}()
	state := func(want bool) {
		t.Helper()
		until := time.Now().Add(12 * time.Second)
		for time.Now().Before(until) {
			if d.Runtime.Ready() == want {
				return
			}
			select {
			case err := <-done:
				done <- err
				t.Fatal("mounted runtime stopped early", err)
			default:
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("mounted owner readiness", want)
	}
	state(true)
	if err = os.Rename(filepath.Join(dir, "owner-pod.token"), filepath.Join(dir, "saved-token")); err != nil {
		t.Fatal(err)
	}
	state(false)
	if err = os.Rename(filepath.Join(dir, "saved-token"), filepath.Join(dir, "owner-pod.token")); err != nil {
		t.Fatal(err)
	}
	state(true)
	write("worker-controls.json", []byte(`{"format":"invalid","controls":[]}`))
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("invalid current catalog left runtime active")
		}
		done <- err
	case <-time.After(7 * time.Second):
		t.Fatal("catalog loss did not stop runtime")
	}
	if d.Runtime.Ready() {
		t.Fatal("stopped mounted runtime stayed ready")
	}
	t.Log("mounted scoped SQL/Kubernetes/S3/OpenBao providers established pre-Ready owner identity, current token loss/recovery and joined catalog-failure shutdown; initial recovery and mount delivery remain fixture-owned")
}
