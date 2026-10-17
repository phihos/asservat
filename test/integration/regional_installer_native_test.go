package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/google/uuid"
	authn "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/ptr"
)

// TestRegionalInstallerWithRealKubernetes installs the ADR-193 regional
// connector objects with InstallRegionalConnector into one owned cluster
// from a synthetic offer and envelope. No hub is needed: the installation,
// both guards' proof with the connector account's minted token, the ungating,
// an idempotent rerun and a denied non-administrator source write are the
// installer's own behavior. Enrollment is qualified by the continuation run.
func TestRegionalInstallerWithRealKubernetes(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("owned context fixture required")
	}
	raw, err := os.ReadFile(path)
	var f fixture
	if err != nil || json.Unmarshal(raw, &f) != nil || len(f.Clusters) < 1 || f.WorkerImage == "" {
		t.Fatal("owned fixture unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	config, err := clientcmd.BuildConfigFromFlags("", f.Clusters[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	api, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	installation, root, epoch := uuid.NewString(), uuid.NewString(), uuid.NewString()
	ca := directNativeCA(t)
	backing, err := json.Marshal(syntheticConnectorBacking(t, root, installation))
	if err != nil {
		t.Fatal(err)
	}
	offer := contracts.RegionalOffer{Format: contracts.RegionalOfferFormat, InstallationID: installation, HubClusterID: uuid.NewString(), PermissionRootID: root, IssuerEpoch: epoch,
		Federation:            contracts.RegionalHubEndpoint{Endpoint: "https://192.0.2.10:31446", ServerName: "federation.synthetic.invalid", Roots: [][]byte{ca.DER}},
		ConnectorServerSuffix: contracts.ConnectorServerSuffix(installation), ConnectorIssuerRoots: [][]byte{ca.DER},
		Roles:            contracts.ConnectorIdentityRoles{Source: "as_source", Journal: "as_journal", Acknowledgement: "as_ack", Cleanup: "as_cleanup", Verifier: "as_verifier", Finalizer: "as_finalizer"},
		ConnectorBacking: backing, Image: f.WorkerImage}
	now := time.Now().UTC().Truncate(time.Microsecond)
	envelope := value.BootstrapEnvelope{BootstrapID: uuid.NewString(), Binding: value.PeerBinding{InstallationID: installation, ClusterID: uuid.NewString(), PeerID: uuid.NewString(), IssuerEpoch: epoch, Role: value.ConnectorPeer},
		DeliveryProfile: "regional-installer", RequestDigest: artifact.Digest{1}, NotBefore: now, NotAfter: now.Add(5 * time.Minute), Secret: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))}
	namespace := "asservat-connector-" + installation[:8]
	t.Cleanup(func() {
		c, end := context.WithTimeout(context.Background(), 20*time.Second)
		defer end()
		_ = api.CoreV1().Namespaces().Delete(c, namespace, meta.DeleteOptions{})
		_ = api.RbacV1().ClusterRoleBindings().Delete(c, namespace+"-connector", meta.DeleteOptions{})
		_ = api.RbacV1().ClusterRoles().Delete(c, namespace+"-connector", meta.DeleteOptions{})
		for _, name := range []string{namespace, namespace + "-source"} {
			_ = api.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().Delete(c, name, meta.DeleteOptions{})
			_ = api.AdmissionregistrationV1().ValidatingAdmissionPolicies().Delete(c, name, meta.DeleteOptions{})
		}
	})
	plan := kube.RegionalInstallPlan{Offer: offer, Bootstrap: envelope, Namespace: namespace}
	first, err := kube.InstallRegionalConnector(ctx, config, plan)
	if err != nil {
		t.Fatal("installer-cluster:", err)
	}
	again, err := kube.InstallRegionalConnector(ctx, config, plan)
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(again)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("rerun changed the installation:", err)
	}
	d, err := api.AppsV1().Deployments(namespace).Get(ctx, kube.RegionalDeployment, meta.GetOptions{})
	if err != nil || d.Spec.Replicas == nil || *d.Spec.Replicas != 1 {
		t.Fatal("connector not ungated", err)
	}
	token, err := api.CoreV1().ServiceAccounts(namespace).CreateToken(ctx, kube.RegionalAccount, &authn.TokenRequest{Spec: authn.TokenRequestSpec{ExpirationSeconds: ptr.To(int64(600))}}, meta.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	minted := rest.AnonymousClientConfig(config)
	minted.BearerToken = token.Status.Token
	connector, err := kubernetes.NewForConfig(minted)
	if err != nil {
		t.Fatal(err)
	}
	source, err := connector.CoreV1().ConfigMaps(namespace).Get(ctx, kube.RegionalSource, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	source.Labels = map[string]string{"changed": "true"}
	if _, err = connector.CoreV1().ConfigMaps(namespace).Update(ctx, source, meta.UpdateOptions{}); !apierrors.IsForbidden(err) && !apierrors.IsInvalid(err) {
		t.Fatal("non-administrator source write not denied", err)
	}
	t.Logf("installer-cluster: objects created, both guards proven with the connector token, ungated, rerun unchanged, source write denied")
}

// syntheticConnectorBacking is a valid prepaid-retirement backing for root.
func syntheticConnectorBacking(t *testing.T, root, installation string) app.ConnectorIdentityBacking {
	t.Helper()
	q := audit.OperationHistoryQualification{ID: uuid.NewString(), Digest: artifact.Digest{2}, Layout: audit.ConnectorRetirementHistoryLayout, MaximumRowFootprintBytes: 1 << 20, MaximumTransitionWALBytes: 1 << 20, BackupCopies: 1, WALCopies: 1}
	b := app.ConnectorIdentityBacking{AccountVersion: "account-v1", AccountLimit: 2, RecordsPerAccount: 256, RetainedSeconds: 3600, ProfileLimit: 2, SourceTransitionLimit: 64,
		Policy: audit.OperationLifecyclePolicy{RootID: root, Lane: "identity", InstallationID: installation, StoreID: uuid.NewString(), PolicyID: uuid.NewString(), BackupProfileID: uuid.NewString(), PolicyDigest: artifact.Digest{3}, BackupProfileDigest: artifact.Digest{4},
			BackingRevision: 1, MetadataSlots: 512, MaxPurgeLeases: 2, CleanupBudgetSeconds: 60, ProofWindowSeconds: 60, ValidUntil: time.Now().UTC().Truncate(time.Microsecond).Add(time.Hour), History: &q, OverdueTerminal: audit.OperationOverdueTerminal}}
	bb, ww := q.SlotBacking(b.Policy.MaxPurgeLeases)
	b.Policy.BackupReservedBytes, b.Policy.WALReservedBytes = bb*b.Policy.MetadataSlots, ww*b.Policy.MetadataSlots
	rows := 1 + b.ProfileLimit + b.ProfileLimit*(b.SourceTransitionLimit+1)
	b.SourceBackupReservedBytes = rows * 2 * q.MaximumRowFootprintBytes * q.BackupCopies
	b.SourceWALReservedBytes = (2*b.SourceTransitionLimit + app.ConnectorRetirementTicketTransitions*b.ProfileLimit*(b.SourceTransitionLimit+1)) * q.MaximumTransitionWALBytes * q.WALCopies
	if !b.Valid() {
		t.Fatal("synthetic backing invalid")
	}
	return b
}
