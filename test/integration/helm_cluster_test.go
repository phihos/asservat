package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	"github.com/google/uuid"
	authn "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// TestHelmClusterInstallWithRealServices installs the packaged chart in
// mode=cluster (ADR-193 step 6). Its post-install hook runs the product
// `installer-cluster --in-cluster` from the authenticated registry with a
// synthetic offer and bootstrap record: the chart's installer account becomes
// the guards' administrator, both guards are proven with the connector token,
// the Deployment is ungated, an upgrade reruns unchanged and a connector
// source write is denied. No hub runs, so the connector does not enroll.
func TestHelmClusterInstallWithRealServices(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" || os.Getenv("ASSERVAT_HELM_BOOTSTRAP_NATIVE") != "1" {
		t.Skip("owned Helm registry fixture required")
	}
	raw, err := os.ReadFile(path)
	var f fixture
	var extras struct {
		HelmBootstrap helmBootstrapFixture `json:"helmBootstrap"`
	}
	if err != nil || json.Unmarshal(raw, &f) != nil || json.Unmarshal(raw, &extras) != nil || len(f.Clusters) != 1 || f.WorkerImage == "" || extras.HelmBootstrap.ChartArchive == "" {
		t.Fatal("owned Helm fixture unavailable")
	}
	x := extras.HelmBootstrap
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	config, err := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	api, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	const release, connectorNamespace = "asservat-region", "asservat-connector"
	if _, err = api.CoreV1().Namespaces().Create(ctx, &core.Namespace{ObjectMeta: meta.ObjectMeta{Name: release, Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, end := context.WithTimeout(context.Background(), 30*time.Second)
		defer end()
		for _, ns := range []string{release, connectorNamespace} {
			_ = api.CoreV1().Namespaces().Delete(c, ns, meta.DeleteOptions{})
		}
		for _, name := range []string{connectorNamespace + "-connector", release + "-asservat-cluster-installer"} {
			_ = api.RbacV1().ClusterRoleBindings().Delete(c, name, meta.DeleteOptions{})
			_ = api.RbacV1().ClusterRoles().Delete(c, name, meta.DeleteOptions{})
		}
		for _, name := range []string{connectorNamespace, connectorNamespace + "-source"} {
			_ = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(c, name, meta.DeleteOptions{})
			_ = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(c, name, meta.DeleteOptions{})
		}
	})
	registry, err := json.Marshal(x.RegistryConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(registry)
	if _, err = api.CoreV1().Secrets(release).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "operator-pull"}, Type: core.SecretTypeDockerConfigJson, Immutable: ptr.To(true), Data: map[string][]byte{core.DockerConfigJsonKey: registry}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	installation, root, epoch, bootstrap := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	ca := directNativeCA(t)
	backing, err := json.Marshal(syntheticConnectorBacking(t, root, installation))
	if err != nil {
		t.Fatal(err)
	}
	offer, err := json.Marshal(contracts.RegionalOffer{Format: contracts.RegionalOfferFormat, InstallationID: installation, HubClusterID: uuid.NewString(), PermissionRootID: root, IssuerEpoch: epoch,
		Federation:            contracts.RegionalHubEndpoint{Endpoint: "https://192.0.2.10:31446", ServerName: "federation.synthetic.invalid", Roots: [][]byte{ca.DER}},
		ConnectorServerSuffix: contracts.ConnectorServerSuffix(installation), ConnectorIssuerRoots: [][]byte{ca.DER},
		Roles:            contracts.ConnectorIdentityRoles{Source: "as_source", Journal: "as_journal", Acknowledgement: "as_ack", Cleanup: "as_cleanup", Verifier: "as_verifier", Finalizer: "as_finalizer"},
		ConnectorBacking: backing, Image: f.WorkerImage})
	if err != nil {
		t.Fatal(err)
	}
	// The operator's KV record, exactly as the bootstrap channel stores it.
	now := time.Now().UTC().Truncate(time.Millisecond)
	record, err := json.Marshal(map[string]any{"binding": map[string]string{"format": "asservat-bootstrap-secret/v1", "installationID": installation, "bootstrapID": bootstrap, "clusterID": uuid.NewString(), "peerID": uuid.NewString(), "issuerEpoch": epoch,
		"deliveryProfile": "regional-installer", "requestSHA256": hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), "notBefore": now.Format(time.RFC3339Nano), "notAfter": now.Add(5 * time.Minute).Format(time.RFC3339Nano)},
		"secret": base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(record)
	if _, err = api.CoreV1().Secrets(release).Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: "operator-bootstrap"}, Immutable: ptr.To(true), Type: core.SecretTypeOpaque, Data: map[string][]byte{"bootstrap.json": record}}, meta.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	values := filepath.Join(t.TempDir(), "values.json")
	v, _ := json.Marshal(map[string]any{"mode": "cluster", "cluster": map[string]any{"enabled": true, "namespace": connectorNamespace, "image": f.WorkerImage, "registrySecret": "operator-pull", "offer": string(offer), "bootstrapSecret": "operator-bootstrap"}})
	if err = os.WriteFile(values, v, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = helmBootstrapCommand(ctx, x, f.Clusters[0].Config, release, values); err != nil {
		helmClusterLogs(t, ctx, api, release)
		t.Fatal("helm install mode=cluster:", err)
	}
	d, err := api.AppsV1().Deployments(connectorNamespace).Get(ctx, kube.RegionalDeployment, meta.GetOptions{})
	if err != nil || d.Spec.Replicas == nil || *d.Spec.Replicas != 1 {
		t.Fatal("connector not ungated by the hook", err)
	}
	policy, err := api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Get(ctx, connectorNamespace, meta.GetOptions{})
	if err != nil || !strings.Contains(policy.Spec.Validations[0].Expression, "system:serviceaccount:"+release+":asservat-cluster-installer") {
		t.Fatal("the chart's installer account is not the guard administrator", err)
	}
	inputs, err := api.CoreV1().ConfigMaps(connectorNamespace).Get(ctx, kube.RegionalInputs, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// An upgrade reruns the hook; the installer reopens every object unchanged.
	if err = helmBootstrapCommand(ctx, x, f.Clusters[0].Config, release, values); err != nil {
		helmClusterLogs(t, ctx, api, release)
		t.Fatal("helm upgrade mode=cluster:", err)
	}
	again, err := api.CoreV1().ConfigMaps(connectorNamespace).Get(ctx, kube.RegionalInputs, meta.GetOptions{})
	if err != nil || again.UID != inputs.UID || again.Data["regional.json"] != inputs.Data["regional.json"] {
		t.Fatal("hook rerun changed the installation", err)
	}
	// Here the guard administrator is the chart's installer account, so even
	// the cluster administrator is not an installation administrator: its
	// token request and source write are both denied.
	if _, err = api.CoreV1().ServiceAccounts(connectorNamespace).CreateToken(ctx, kube.RegionalAccount, &authn.TokenRequest{Spec: authn.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600))}}, meta.CreateOptions{}); !apierrors.IsForbidden(err) && !apierrors.IsInvalid(err) {
		t.Fatal("non-administrator token request not denied", err)
	}
	source, err := api.CoreV1().ConfigMaps(connectorNamespace).Get(ctx, kube.RegionalSource, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source.Labels = map[string]string{"changed": "true"}
	if _, err = api.CoreV1().ConfigMaps(connectorNamespace).Update(ctx, source, meta.UpdateOptions{}); !apierrors.IsForbidden(err) && !apierrors.IsInvalid(err) {
		t.Fatal("non-administrator source write not denied", err)
	}
	t.Log("helm mode=cluster: hook ran installer-cluster from the registry; installer account administers both guards; ungated; upgrade rerun unchanged; cluster-admin token request and source write denied")
}

// helmClusterLogs prints the installer hook's own stop lines: a fixed step
// and a closed cause, never inputs.
func helmClusterLogs(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace string) {
	t.Helper()
	pods, err := api.CoreV1().Pods(namespace).List(ctx, meta.ListOptions{LabelSelector: "job-name=asservat-cluster-installer"})
	if err != nil {
		return
	}
	for _, p := range pods.Items {
		for _, s := range p.Status.ContainerStatuses {
			if s.State.Waiting != nil {
				t.Logf("installer pod %s waiting: %s", p.Name, s.State.Waiting.Reason)
			}
		}
		stream, err := api.CoreV1().Pods(namespace).GetLogs(p.Name, &core.PodLogOptions{LimitBytes: ptr.To(int64(4 << 10))}).Stream(ctx)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(stream, 4<<10))
		stream.Close()
		t.Logf("installer pod %s: %s", p.Name, strings.TrimSpace(string(b)))
	}
}
