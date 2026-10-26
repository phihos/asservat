package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

func TestHelmBootstrapWithRealServices(t *testing.T) {
	if os.Getenv("ASSERVAT_CONTEXT_FIXTURES") == "" || os.Getenv("ASSERVAT_HELM_BOOTSTRAP_NATIVE") != "1" {
		t.Skip("run owned --helm-bootstrap with empty SQL and authenticated registry")
	}
	var f fixture
	raw, err := os.ReadFile(os.Getenv("ASSERVAT_CONTEXT_FIXTURES"))
	if err != nil || json.Unmarshal(raw, &f) != nil || len(f.Clusters) != 1 || f.WorkerImage == "" || f.NativeProviders.Postgres == "" {
		t.Fatal("owned single-cluster/native services unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	var pristine bool
	if err = admin.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')`).Scan(&pristine); err != nil || !pristine {
		t.Fatal("product must initialize actually empty SQL")
	}
	kc, err := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	api, err := kubernetes.NewForConfig(kc)
	if err != nil {
		t.Fatal(err)
	}
	self, err := api.AuthenticationV1().SelfSubjectReviews().Create(ctx, &auth.SelfSubjectReview{}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	namespace := "bootstrap-helm-" + custodyID()[:8]
	ns, err := api.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: namespace, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	desired := initialBootstrapGuardDesired(t, kc, namespace, self.Status.UserInfo.Username)
	desired.Image = f.WorkerImage
	// Use the same reachable, certificate-covered origin from host and original
	// activation Pod. This is the existing owned node fixture, never discovery
	// authority imported into product state.
	node, err := api.CoreV1().Nodes().Get(ctx, f.Clusters[0].Pod.NodeName, meta.GetOptions{})
	if err != nil || string(node.UID) != f.Clusters[0].NodeUID {
		t.Fatal("owned node identity unavailable")
	}
	for _, a := range node.Status.Addresses {
		if a.Type == core.NodeInternalIP {
			desired.Kubernetes.Endpoint = "https://" + net.JoinHostPort(a.Address, "6443")
			break
		}
	}
	if desired.Kubernetes.Endpoint == kc.Host {
		t.Fatal("shared API origin missing")
	}
	direct := rest.CopyConfig(kc)
	direct.Host = desired.Kubernetes.Endpoint
	directAPI, err := kubernetes.NewForConfig(direct)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := directAPI.CoreV1().Nodes().Get(ctx, node.Name, meta.GetOptions{})
	if err != nil || actual.UID != node.UID {
		t.Fatal("shared exact API origin invalid", err)
	}
	host, portText, err := net.SplitHostPort(f.NativeProviders.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	desired.Postgres = contracts.OwnerPostgresEndpoint{Host: host, Port: port, Database: "custody_test", MaxConnections: 2, Roots: [][]byte{f.NativeProviders.Root}}
	desired.AuditStore = contracts.OwnerAuditStore{Endpoint: f.NativeProviders.S3, Roots: [][]byte{f.NativeProviders.Root}, Region: "us-east-1", Bucket: "initial-bootstrap-chain"}
	desired.KeyService = contracts.ConfigurationKeyService{Endpoint: f.NativeProviders.KMS, Roots: [][]byte{f.NativeProviders.Root}, AuditMount: "bootstrap-chain-transit", AuditKey: "audit"}
	desired.Providers = contracts.InitialBootstrapProviders{IssuerPolicy: "bootstrap-chain-issuer", WrapRole: "bootstrap-chain-wrap", WrapPolicy: "bootstrap-chain-encrypt", UnwrapRole: "bootstrap-chain-unwrap", UnwrapPolicy: "bootstrap-chain-decrypt"}
	var extras struct {
		HelmBootstrap helmBootstrapFixture `json:"helmBootstrap"`
	}
	if json.Unmarshal(raw, &extras) != nil || extras.HelmBootstrap.ChartArchive == "" || extras.HelmBootstrap.ProductBinary == "" || extras.HelmBootstrap.NodeA == extras.HelmBootstrap.NodeB {
		t.Fatal("owned Helm/registry inputs unavailable")
	}
	x := extras.HelmBootstrap
	publicInput := helmBootstrapPublicInput(desired)
	compiled, err := providerconfig.CompileInitialBootstrapInput(publicInput, kc.CAData, []byte(f.Clusters[0].Token), time.Now())
	if err != nil {
		t.Fatal("fixture public compiler", err)
	}
	desired = compiled
	t.Cleanup(func() { helmBootstrapCleanup(t, api, desired, ns.UID) })
	rootCert, err := x509.ParseCertificate(f.NativeProviders.Root)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	providerHTTP := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	issuer := initialBootstrapChainProvider(t, ctx, f, desired)
	store := s3.New(s3.Options{Region: desired.AuditStore.Region, BaseEndpoint: aws.String(desired.AuditStore.Endpoint), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", ""), HTTPClient: providerHTTP})
	if _, err = store.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &desired.AuditStore.Bucket}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: &desired.AuditStore.Bucket, VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); err != nil {
		t.Fatal(err)
	}
	values := helmBootstrapValues(publicInput)
	valuesPath := filepath.Join(t.TempDir(), "values.json")
	helmBootstrapWriteValues(t, valuesPath, values)
	registryBytes, err := json.Marshal(x.RegistryConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(registryBytes)
	if _, err = api.CoreV1().Secrets(namespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "operator-pull"}, Type: core.SecretTypeDockerConfigJson, Immutable: ptr.To(true), Data: map[string][]byte{core.DockerConfigJsonKey: registryBytes}}, meta.CreateOptions{}); err != nil {
		t.Fatal("operator pull input", err)
	}
	sql := admin.Config().ConnConfig
	credentialsJSON, _ := json.Marshal(contracts.OwnerSQLCredential{Username: sql.User, Password: sql.Password})
	defer clear(credentialsJSON)
	providerJSON, _ := json.Marshal(contracts.InitialBootstrapMaterial{Format: contracts.InitialBootstrapMaterialFormat, IssuerToken: issuer, Storage: contracts.OwnerStorageCredential{AccessKeyID: "synthetic-only", SecretAccessKey: "synthetic-only-secret"}, StorageUseUntil: time.Now().UTC().Add(time.Hour)})
	defer clear(providerJSON)
	for name, data := range map[string]map[string][]byte{"operator-producer": {"postgres-administrator.json": credentialsJSON, "provider-material.json": providerJSON}, "operator-ddl": {"postgres-ddl.json": credentialsJSON}, "operator-retirement": {"postgres-administrator.json": credentialsJSON}} {
		if _, err = api.CoreV1().Secrets(namespace).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: name}, Immutable: ptr.To(true), Type: core.SecretTypeOpaque, Data: data}, meta.CreateOptions{}); err != nil {
			t.Fatal("explicit operator input", err)
		}
	}
	// The watch starts before any product target CREATE. It retains the actual
	// original terminal Pod even after the supervisor's positive cleanup deletes it.
	watch, err := api.CoreV1().Pods("").Watch(ctx, meta.ListOptions{FieldSelector: "metadata.name=" + desired.Name})
	if err != nil {
		t.Fatal(err)
	}
	terminals := make(chan *core.Pod, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		for event := range watch.ResultChan() {
			p, ok := event.Object.(*core.Pod)
			if ok && p.Namespace == desired.TargetNamespace && (p.Status.Phase == core.PodSucceeded || p.Status.Phase == core.PodFailed) {
				select {
				case terminals <- p.DeepCopy():
				default:
				}
				return
			}
		}
	}()
	defer func() { watch.Stop(); <-joined }()
	retirement := initialBootstrapWatchRetirement(t, ctx, api, desired)
	defer retirement.Close()
	providerUID := helmBootstrapWatchProvider(t, ctx, api, desired, registryBytes)
	defer providerUID.Close()
	first := helmBootstrapRun(t, ctx, api, f.Clusters[0].Config, desired, x, valuesPath, true, true)
	var terminal *core.Pod
	select {
	case terminal = <-terminals:
	case <-ctx.Done():
		t.Fatal("original activation terminal missing")
	}
	originalSeed := retirement.Take(t, ctx)
	state, configuration, root := initialBootstrapChainState(t, ctx, api, desired, originalSeed)
	if root.Schema == nil || root.Schema.CompletedAt == nil || state.Manager == nil || state.Manager.Receipt == nil || state.Manager.RetiredAt == nil {
		t.Fatal("product schema/manager lifecycle incomplete")
	}
	if root.Schema.Manager != *state.Manager.Receipt || configuration.Plan.HistoryManager == nil || *configuration.Plan.HistoryManager != *state.Manager.Receipt {
		t.Fatal("manager was replaced or fixture-injected")
	}
	bundle, err := postgres.EmbeddedInitialSchema()
	if err != nil || bundle.Digest != root.Schema.BundleDigest || bundle.Head != root.Schema.Head {
		t.Fatal("compiled schema binding differs")
	}
	if root.Activation == nil || root.Activation.Pod == nil || root.Activation.Pod.Receipt == nil || string(terminal.UID) != root.Activation.Pod.Receipt.UID {
		t.Fatal("wrong original activation Pod")
	}
	initialBootstrapChainImage(t, terminal, f.WorkerImage)
	if first.Spec.NodeName != x.NodeA || terminal.Spec.NodeName != x.NodeB || len(terminal.Spec.ImagePullSecrets) != 1 || terminal.Spec.ImagePullSecrets[0].Name != configuration.Plan.Workload.Credentials {
		t.Fatal("authenticated pulls did not occur in distinct unchanged original placements")
	}
	if root.Activation.Handover == nil || root.Activation.Handover.Credentials.UID != providerUID.Take(t, ctx) {
		t.Fatal("pull Secret not exact original independently observed provider projection")
	}
	for _, v := range terminal.Spec.Volumes {
		if v.Projected != nil {
			for _, s := range v.Projected.Sources {
				if s.Secret != nil {
					if len(s.Secret.Items) != 7 {
						t.Fatal("activation mounted registry credentials")
					}
					for _, k := range s.Secret.Items {
						if k.Key == core.DockerConfigJsonKey {
							t.Fatal("registry file mounted into activation process")
						}
					}
				}
			}
		}
	}
	if root.Activation.Handover == nil || root.Activation.Handover.Cleanup == nil || len(root.Activation.Handover.Cleanup.Steps) != 8 {
		t.Fatal("actual handover cleanup incomplete")
	}
	if _, err = api.CoreV1().Pods(desired.TargetNamespace).Get(ctx, desired.Name, meta.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("product did not remove original activation Pod", err)
	}
	initialBootstrapChainAudit(t, ctx, admin, store, providerHTTP, f, desired, state, root)
	var login, create bool
	var sessions int
	if err = admin.QueryRow(ctx, "SELECT rolcanlogin,rolcreaterole FROM pg_roles WHERE oid=$1 AND rolname=$2", state.Manager.Receipt.OID, state.Manager.Receipt.Name).Scan(&login, &create); err != nil || login || create {
		t.Fatal("original manager not retired", err)
	}
	if err = admin.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE usesysid=$1", state.Manager.Receipt.OID).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatal("original manager sessions remain", err)
	}
	denied, err := pgx.ParseConfig(f.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	denied.User = state.Manager.Receipt.Name
	denied.Password = state.Passwords.Manager
	attempt, stop := context.WithTimeout(ctx, 2*time.Second)
	connection, e := pgx.ConnectConfig(attempt, denied)
	stop()
	if e == nil {
		connection.Close(context.Background())
		t.Fatal("original retired manager still logs in")
	}
	state.Passwords.Manager = ""
	originalSeed.State.Passwords.Manager = ""
	// The compiled chart input names the runner account as the only trusted
	// bootstrap administrator, so closure checks act as that runner (as the
	// chain's unified path does). The cluster administrator matches neither
	// the guard's administrator CREATE nor its probe-token exception.
	closureConfig := installedUnifiedRunnerConfig(kc, desired)
	closureAPI, err := kubernetes.NewForConfig(closureConfig)
	if err != nil {
		t.Fatal(err)
	}
	finalSeed := initialBootstrapVerifyCopyClosure(t, ctx, closureAPI, closureConfig, desired, originalSeed)
	// Remove only operator fixture inputs. Product copies must already have
	// positively closed; a fresh runner receives no setup SQL/provider inputs.
	for _, name := range []string{"operator-producer", "operator-ddl", "operator-retirement"} {
		object, e := api.CoreV1().Secrets(namespace).Get(ctx, name, meta.GetOptions{})
		if e != nil {
			t.Fatal(e)
		}
		if e = api.CoreV1().Secrets(namespace).Delete(ctx, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &object.UID, ResourceVersion: &object.ResourceVersion}}); e != nil {
			t.Fatal(e)
		}
	}
	request(t, f.KMS, "synthetic-root", "auth/token/revoke", map[string]any{"token": issuer}, 204)
	t.Run("all-four-commands-passive-without-setup-files", func(t *testing.T) {
		second := helmBootstrapRun(t, ctx, api, f.Clusters[0].Config, desired, x, valuesPath, false, true)
		if second.UID == first.UID {
			t.Fatal("replay reused old runner result")
		}
		after, configAfter, rootAfter := initialBootstrapChainState(t, ctx, api, desired, originalSeed)
		afterSeed := initialBootstrapVerifyCopyClosure(t, ctx, closureAPI, closureConfig, desired, originalSeed)
		if afterSeed.UID != finalSeed.UID || afterSeed.ResourceVersion != finalSeed.ResourceVersion || !equalJSONForBootstrap(finalSeed.Annotations, afterSeed.Annotations) {
			t.Fatal("completed replay changed original copy closure")
		}
		a, _ := json.Marshal(state)
		b, _ := json.Marshal(after)
		defer clear(a)
		defer clear(b)
		ra, _ := json.Marshal(root)
		rb, _ := json.Marshal(rootAfter)
		ca, _ := json.Marshal(configuration)
		cb, _ := json.Marshal(configAfter)
		if !bytes.Equal(a, b) || !bytes.Equal(ra, rb) || !bytes.Equal(ca, cb) {
			t.Fatal("passive fixed commands changed original identities/progress")
		}
		var count int
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM fleet_initial_activation WHERE installation_id=$1", state.InstallationID).Scan(&count); err != nil || count != 1 {
			t.Fatal("passive replay repeated activation", err)
		}
	})
	t.Run("failed-hook-original-revision-resume", func(t *testing.T) {
		var bad map[string]any
		encoded, _ := json.Marshal(values)
		_ = json.Unmarshal(encoded, &bad)
		bad["bootstrap"].(map[string]any)["postgres"].(map[string]any)["rootsPEM"] = "invalid-first-input"
		helmBootstrapWriteValues(t, valuesPath, bad)
		failed := helmBootstrapRun(t, ctx, api, f.Clusters[0].Config, desired, x, valuesPath, false, false)
		helmBootstrapWriteValues(t, valuesPath, values)
		if err := helmBootstrapCommand(ctx, x, f.Clusters[0].Config, namespace, valuesPath); err == nil {
			t.Fatal("Helm blindly replaced failed retained hook")
		}
		still, e := api.CoreV1().Pods(namespace).Get(ctx, failed.Name, meta.GetOptions{})
		if e != nil || still.UID != failed.UID {
			t.Fatal("changed chart input replaced original failed hook", e)
		}
		command := exec.CommandContext(ctx, x.ProductBinary, "installer-resume", "--kubeconfig", f.Clusters[0].Config, "--namespace", namespace, "--name", desired.Name)
		output, e := command.CombinedOutput()
		if e != nil || !bytes.Contains(output, []byte(string(failed.UID))) {
			t.Fatal("actual CLI failed exact terminal resume", e)
		}
		_ = helmBootstrapRun(t, ctx, api, f.Clusters[0].Config, desired, x, valuesPath, false, true)
		after, _, afterRoot := initialBootstrapChainState(t, ctx, api, desired, originalSeed)
		if after.InstallationID != state.InstallationID || !equalJSONForBootstrap(afterRoot, root) {
			t.Fatal("public-input correction reset original installation")
		}
		configmaps, e := api.CoreV1().ConfigMaps(namespace).List(ctx, meta.ListOptions{})
		if e != nil {
			t.Fatal(e)
		}
		retained := 0
		for _, cm := range configmaps.Items {
			if strings.HasPrefix(cm.Name, desired.Name+"-bootstrap-input.") {
				retained++
				if cm.Immutable == nil || !*cm.Immutable || cm.Annotations["helm.sh/resource-policy"] != "keep" {
					t.Fatal("chart input snapshot not retained")
				}
			}
		}
		if retained != 2 {
			t.Fatal("original and failed revision inputs were not preserved", retained)
		}
	})
	t.Run("helm-uninstall-preserves-original-product-state", func(t *testing.T) {
		command := exec.CommandContext(ctx, "helm", "uninstall", "asservat", "--kubeconfig", f.Clusters[0].Config, "--namespace", namespace, "--timeout", "1m")
		if out, e := command.CombinedOutput(); e != nil {
			t.Fatal("owned chart uninstall", e, string(out))
		}
		after, _, afterRoot := initialBootstrapChainState(t, ctx, api, desired, originalSeed)
		if after.InstallationID != state.InstallationID || !equalJSONForBootstrap(afterRoot, root) {
			t.Fatal("Helm erased original product progress")
		}
		// Uninstall removes the chart's runner account and its RBAC, so no
		// identity remains that the guard accepts as administrator; the full
		// closure check (runner-only probe token) ran before uninstall. Here
		// the cluster administrator confirms that the sanitized seed and the
		// product-created permanent tombstone survived unchanged.
		seed, e := api.CoreV1().Secrets(desired.BootstrapNamespace).Get(ctx, desired.Name+"-bootstrap-state", meta.GetOptions{})
		if e != nil || seed.UID != finalSeed.UID || seed.ResourceVersion != finalSeed.ResourceVersion {
			t.Fatal("Helm changed original sanitized seed", e)
		}
		claim, e := contracts.DecodeInitialBootstrapCopyClaim(strings.NewReader(seed.Annotations["asservat.io/bootstrap-copy-claim"]))
		if e != nil {
			t.Fatal("copy claim unavailable", e)
		}
		tombstone := desired
		tombstone.Format = contracts.InitialBootstrapVersionedAuditFormat
		want, wantBinding, e := kube.InitialBootstrapCopyAdmission(tombstone, claim)
		if e != nil {
			t.Fatal(e)
		}
		policyReceipt, e := contracts.DecodeInitialBootstrapCopyReceipt(strings.NewReader(seed.Annotations["asservat.io/bootstrap-copy-policy"]))
		if e != nil {
			t.Fatal(e)
		}
		bindingReceipt, e := contracts.DecodeInitialBootstrapCopyReceipt(strings.NewReader(seed.Annotations["asservat.io/bootstrap-copy-binding"]))
		if e != nil {
			t.Fatal(e)
		}
		p, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, want.Name, meta.GetOptions{})
		if e != nil || string(p.UID) != policyReceipt.UID || p.Generation != 1 {
			t.Fatal("Helm uninstall removed or changed the copy tombstone policy", e)
		}
		b, e := api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Get(ctx, wantBinding.Name, meta.GetOptions{})
		if e != nil || string(b.UID) != bindingReceipt.UID || b.ResourceVersion != bindingReceipt.ResourceVersion {
			t.Fatal("Helm uninstall removed or changed the copy tombstone binding", e)
		}
	})
	t.Log("actual Helm package, authenticated cold exact-image pulls on two owned nodes, original manager/schema/activation/audit/retirement, positive v3 copy closure, setup-free hook replay, bounded terminal CLI resume and retained public revision inputs; no public runtime/restore/backup claim")
}

type helmBootstrapFixture struct {
	RegistryConfig map[string]any `json:"registryConfig"`
	ProductBinary  string         `json:"productBinary"`
	ChartArchive   string         `json:"chartArchive"`
	NodeA          string         `json:"nodeA"`
	NodeAUID       string         `json:"nodeAUID"`
	NodeB          string         `json:"nodeB"`
	NodeBUID       string         `json:"nodeBUID"`
}

func helmBootstrapPublicInput(d contracts.InitialBootstrap) contracts.InitialBootstrapInput {
	pemRoots := func(roots [][]byte) string {
		var b bytes.Buffer
		for _, r := range roots {
			_ = pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: r})
		}
		return b.String()
	}
	return contracts.InitialBootstrapInput{Format: contracts.InitialBootstrapInputFormat, Name: d.Name, BootstrapNamespace: d.BootstrapNamespace, TargetNamespace: d.TargetNamespace, RunnerAccount: d.Name + "-bootstrap-runner", Image: d.Image, RegistryAuthentication: contracts.InitialRegistryAuthentication,
		Kubernetes: contracts.InitialBootstrapEndpointInput{Endpoint: d.Kubernetes.Endpoint},
		Postgres:   contracts.InitialBootstrapPostgresInput{Host: d.Postgres.Host, Port: d.Postgres.Port, Database: d.Postgres.Database, MaxConnections: d.Postgres.MaxConnections, RootsPEM: pemRoots(d.Postgres.Roots)},
		AuditStore: contracts.InitialBootstrapAuditStoreInput{Endpoint: d.AuditStore.Endpoint, Region: d.AuditStore.Region, Bucket: d.AuditStore.Bucket, RootsPEM: pemRoots(d.AuditStore.Roots)},
		KeyService: contracts.InitialBootstrapKeyServiceInput{Endpoint: d.KeyService.Endpoint, AuditMount: d.KeyService.AuditMount, AuditKey: d.KeyService.AuditKey, RootsPEM: pemRoots(d.KeyService.Roots)}, Fleet: d.Fleet, Providers: d.Providers}
}
func helmBootstrapValues(input contracts.InitialBootstrapInput) map[string]any {
	b, _ := json.Marshal(input)
	var values map[string]any
	_ = json.Unmarshal(b, &values)
	for _, k := range []string{"format", "bootstrapNamespace", "runnerAccount", "registryAuthentication"} {
		delete(values, k)
	}
	values["enabled"] = true
	values["registrySecret"] = "operator-pull"
	values["secrets"] = map[string]any{"producer": "operator-producer", "schema": "operator-ddl", "retirement": "operator-retirement"}
	return map[string]any{"mode": "hub", "runtime": map[string]any{"enabled": false}, "bootstrap": values}
}
func helmBootstrapWriteValues(t *testing.T, path string, values map[string]any) {
	t.Helper()
	b, e := json.Marshal(values)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func helmBootstrapCommand(ctx context.Context, x helmBootstrapFixture, kubeconfig, namespace, values string) error {
	command := exec.CommandContext(ctx, "helm", "upgrade", "--install", "asservat", x.ChartArchive, "--kubeconfig", kubeconfig, "--namespace", namespace, "--values", values, "--wait", "--timeout", "6m", "--history-max", "4")
	// Helm only receives public values and references; its output is not a
	// credential transport. Keep even unexpected diagnostics bounded.
	output := &helmBootstrapOutput{}
	command.Stdout = output
	command.Stderr = output
	if e := command.Run(); e != nil {
		return fmt.Errorf("Helm command: %w: %s", e, output.Bytes())
	}
	return nil
}

type helmBootstrapOutput struct{ bytes.Buffer }

func (b *helmBootstrapOutput) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len() < 32<<10 {
		p = p[:min(len(p), (32<<10)-b.Len())]
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}

func helmBootstrapRun(t *testing.T, ctx context.Context, api kubernetes.Interface, kubeconfig string, d contracts.InitialBootstrap, x helmBootstrapFixture, values string, flipNodes, wantSuccess bool) *core.Pod {
	t.Helper()
	runCtx, stop := context.WithTimeout(ctx, 6*time.Minute)
	defer stop()
	name := d.Name + "-bootstrap"
	list, e := api.CoreV1().Pods(d.BootstrapNamespace).List(runCtx, meta.ListOptions{FieldSelector: "metadata.name=" + name})
	if e != nil || len(list.Items) != 0 {
		t.Fatal("expected no prior fixed hook before invocation", e)
	}
	watcher, e := api.CoreV1().Pods(d.BootstrapNamespace).Watch(runCtx, meta.ListOptions{FieldSelector: "metadata.name=" + name, ResourceVersion: list.ResourceVersion})
	if e != nil {
		t.Fatal(e)
	}
	defer watcher.Stop()
	done := make(chan error, 1)
	go func() { done <- helmBootstrapCommand(runCtx, x, kubeconfig, d.BootstrapNamespace, values) }()
	commandJoined := false
	defer func() {
		stop()
		if !commandJoined {
			<-done
		}
	}()
	var original types.UID
	var terminal *core.Pod
	var commandErr error
	flipped := false
	defer func() {
		if t.Failed() && original != "" {
			helmBootstrapFailureLogs(t, api, d, name, original)
		}
	}()
	for !commandJoined || terminal == nil {
		select {
		case commandErr = <-done:
			commandJoined = true
			if commandErr != nil && wantSuccess {
				t.Fatal(commandErr)
			}
			if commandErr == nil && !wantSuccess {
				t.Fatal("invalid public input unexpectedly succeeded")
			}
			// A failed Helm invocation without a terminal Pod is not the expected
			// malformed-input regression; do not invent a terminal receipt.
		case event, ok := <-watcher.ResultChan():
			if !ok {
				t.Fatal("original hook watch ended before joined terminal")
			}
			pod, ok := event.Object.(*core.Pod)
			if !ok {
				t.Fatal("unexpected original hook watch object")
			}
			if original == "" {
				original = pod.UID
			}
			if pod.UID != original {
				t.Fatal("fixed hook was replaced during one invocation")
			}
			running := false
			for _, s := range append(append([]core.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...) {
				running = running || s.State.Running != nil
			}
			if flipNodes && !flipped && running {
				if pod.Spec.NodeName != x.NodeA {
					t.Fatal("original runner did not use initially sole schedulable owned node")
				}
				cmd := exec.CommandContext(runCtx, x.ProductBinary, "installer-resume", "--kubeconfig", kubeconfig, "--namespace", d.BootstrapNamespace, "--name", d.Name)
				if err := cmd.Run(); err == nil {
					t.Fatal("actual resume CLI removed live hook")
				}
				current, err := api.CoreV1().Pods(d.BootstrapNamespace).Get(runCtx, name, meta.GetOptions{})
				if err != nil || current.UID != original {
					t.Fatal("live CLI refusal changed original hook", err)
				}
				// Only owned fixture scheduling availability changes. The product Pod,
				// activation template and admission digest remain byte-for-byte intact.
				for _, n := range []struct {
					name, uid string
					cordon    bool
				}{{x.NodeB, x.NodeBUID, false}, {x.NodeA, x.NodeAUID, true}} {
					node, err := api.CoreV1().Nodes().Get(runCtx, n.name, meta.GetOptions{})
					if err != nil || string(node.UID) != n.uid {
						t.Fatal("owned scheduling identity changed", err)
					}
					node.Spec.Unschedulable = n.cordon
					if _, err = api.CoreV1().Nodes().Update(runCtx, node, meta.UpdateOptions{}); err != nil {
						t.Fatal("owned scheduling CAS", err)
					}
				}
				flipped = true
			}
			if pod.Status.Phase == core.PodSucceeded || pod.Status.Phase == core.PodFailed {
				terminal = pod.DeepCopy()
			}
		case <-runCtx.Done():
			t.Fatal("original Helm invocation did not join terminal", runCtx.Err(), commandErr)
		}
	}
	if wantSuccess && (terminal.Status.Phase != core.PodSucceeded || flipNodes && !flipped) {
		t.Fatal("original hook failed its fixed chain")
	}
	if !wantSuccess && terminal.Status.Phase != core.PodFailed {
		t.Fatal("malformed-input hook lacked positive failed terminal")
	}
	if wantSuccess {
		statuses := append(append([]core.ContainerStatus{}, terminal.Status.InitContainerStatuses...), terminal.Status.ContainerStatuses...)
		if len(statuses) != 4 {
			t.Fatal("fixed four commands were not all observed")
		}
		digest := strings.Split(d.Image, "@")[1]
		for _, s := range statuses {
			if s.RestartCount != 0 || s.State.Terminated == nil || s.State.Terminated.ExitCode != 0 || !strings.HasSuffix(s.ImageID, digest) {
				t.Fatal("fixed command identity/positive exit mismatch", s.Name)
			}
		}
		if _, e := api.CoreV1().Pods(d.BootstrapNamespace).Get(runCtx, name, meta.GetOptions{}); !apierrors.IsNotFound(e) {
			t.Fatal("hook-succeeded cleanup not observed", e)
		}
	}
	return terminal
}

// Capture bounded diagnostics before the owned fixture cleanup removes the
// failed hook. Helm's generic failed-Pod error does not identify which command
// failed. This reads only the same original Pod and its fixed product commands;
// it never reads provider Secrets or treats a diagnostic as a test outcome.
func helmBootstrapFailureLogs(t *testing.T, api kubernetes.Interface, d contracts.InitialBootstrap, name string, uid types.UID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pod, err := api.CoreV1().Pods(d.BootstrapNamespace).Get(ctx, name, meta.GetOptions{})
	if err != nil || pod.UID != uid {
		t.Logf("original hook diagnostic unavailable: %v", err)
		return
	}
	containers := append(append([]core.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...)
	statuses := append(append([]core.ContainerStatus{}, pod.Status.InitContainerStatuses...), pod.Status.ContainerStatuses...)
	if len(containers) != 4 || len(statuses) > 4 {
		t.Log("original hook diagnostic has unexpected command count")
		return
	}
	for _, status := range statuses {
		valid := false
		for _, c := range containers {
			valid = valid || c.Name == status.Name && c.Image == d.Image
		}
		if !valid {
			t.Log("original hook diagnostic has unexpected image or command identity")
			return
		}
		if status.State.Terminated != nil {
			t.Logf("original hook command %s terminated: exit=%d reason=%s", status.Name, status.State.Terminated.ExitCode, status.State.Terminated.Reason)
		} else if status.State.Waiting != nil {
			t.Logf("original hook command %s waiting: reason=%s", status.Name, status.State.Waiting.Reason)
			continue
		}
		out, err := api.CoreV1().Pods(d.BootstrapNamespace).GetLogs(name, &core.PodLogOptions{Container: status.Name, TailLines: ptr.To(int64(32)), LimitBytes: ptr.To(int64(8192))}).DoRaw(ctx)
		if err != nil {
			t.Logf("original hook command %s logs unavailable: %v", status.Name, err)
			continue
		}
		t.Logf("original hook command %s bounded output: %s", status.Name, out)
	}
}

type helmBootstrapProviderWatch struct {
	stop   func()
	values chan string
	errors chan error
	joined chan struct{}
}

func helmBootstrapWatchProvider(t *testing.T, ctx context.Context, api kubernetes.Interface, d contracts.InitialBootstrap, registry []byte) *helmBootstrapProviderWatch {
	t.Helper()
	list, e := api.CoreV1().Secrets("").List(ctx, meta.ListOptions{FieldSelector: "metadata.name=" + d.Name + "-providers", Limit: 2})
	if e != nil || list.Continue != "" || len(list.Items) > 1 {
		t.Fatal("bounded original provider observation unavailable", e)
	}
	for _, s := range list.Items {
		for _, b := range s.Data {
			clear(b)
		}
		if s.Namespace == d.TargetNamespace {
			t.Fatal("provider copy existed before product admission")
		}
	}
	watch, e := api.CoreV1().Secrets("").Watch(ctx, meta.ListOptions{FieldSelector: "metadata.name=" + d.Name + "-providers", ResourceVersion: list.ResourceVersion})
	if e != nil {
		t.Fatal(e)
	}
	w := &helmBootstrapProviderWatch{stop: watch.Stop, values: make(chan string, 1), errors: make(chan error, 1), joined: make(chan struct{})}
	expected := bytes.Clone(registry)
	go func() {
		defer close(w.joined)
		defer clear(expected)
		for event := range watch.ResultChan() {
			s, ok := event.Object.(*core.Secret)
			if !ok {
				w.errors <- fmt.Errorf("provider watch returned unexpected object")
				return
			}
			match := s.Namespace == d.TargetNamespace
			valid := s.Type == core.SecretTypeDockerConfigJson && s.Immutable != nil && *s.Immutable && len(s.Data) == 8 && bytes.Equal(s.Data[core.DockerConfigJsonKey], expected)
			for _, b := range s.Data {
				clear(b)
			}
			if match {
				if !valid {
					w.errors <- fmt.Errorf("original provider copy does not contain exact closed registry input")
				} else {
					w.values <- string(s.UID)
				}
				return
			}
		}
	}()
	return w
}
func (w *helmBootstrapProviderWatch) Close() { w.stop(); <-w.joined }
func (w *helmBootstrapProviderWatch) Take(t *testing.T, ctx context.Context) string {
	t.Helper()
	select {
	case v := <-w.values:
		return v
	case e := <-w.errors:
		t.Fatal(e)
	case <-ctx.Done():
		t.Fatal("original provider Secret event missing")
	}
	return ""
}
func helmBootstrapCleanup(t *testing.T, api kubernetes.Interface, d contracts.InitialBootstrap, namespaceUID types.UID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	name := d.Name + "-bootstrap"
	p, e := api.CoreV1().Pods(d.BootstrapNamespace).Get(ctx, name, meta.GetOptions{})
	if e == nil {
		e = api.CoreV1().Pods(d.BootstrapNamespace).Delete(ctx, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &p.UID, ResourceVersion: &p.ResourceVersion}})
	}
	if e != nil && !apierrors.IsNotFound(e) {
		t.Error("owned hook cleanup", e)
		return
	}
	for ctx.Err() == nil {
		current, err := api.CoreV1().Pods(d.BootstrapNamespace).Get(ctx, name, meta.GetOptions{})
		if apierrors.IsNotFound(err) {
			break
		}
		if err != nil || p == nil || current.UID != p.UID {
			t.Error("owned original hook cleanup observation", err)
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(50 * time.Millisecond):
		}
	}
	if ctx.Err() != nil {
		t.Error("owned hook cleanup did not join")
		return
	}
	role := d.BootstrapNamespace + "-" + d.Name + "-bootstrap-runner"
	binding, err := api.RbacV1().ClusterRoleBindings().Get(ctx, role, meta.GetOptions{})
	if err == nil {
		if binding.Annotations["meta.helm.sh/release-name"] != "asservat" || binding.Annotations["meta.helm.sh/release-namespace"] != d.BootstrapNamespace {
			t.Error("refuse unrelated chart binding cleanup")
			return
		}
		err = api.RbacV1().ClusterRoleBindings().Delete(ctx, role, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &binding.UID}})
	}
	if err != nil && !apierrors.IsNotFound(err) {
		t.Error(err)
	}
	r, err := api.RbacV1().ClusterRoles().Get(ctx, role, meta.GetOptions{})
	if err == nil {
		if r.Annotations["meta.helm.sh/release-name"] != "asservat" || r.Annotations["meta.helm.sh/release-namespace"] != d.BootstrapNamespace {
			t.Error("refuse unrelated chart role cleanup")
			return
		}
		err = api.RbacV1().ClusterRoles().Delete(ctx, role, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &r.UID}})
	}
	if err != nil && !apierrors.IsNotFound(err) {
		t.Error(err)
	}
	// Existing fixture helper removes only this installation's current pinned
	// guards and namespaces. Its old fixture-only administrator names are absent.
	initialBootstrapChainCleanup(t, api, d, namespaceUID, "", "")
}
