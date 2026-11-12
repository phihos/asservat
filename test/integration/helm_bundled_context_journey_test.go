package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

// This joins the same installed workflow after its actual
// login. No provider administration, extra bootstrap issue, credential mint or
// fixture SQL activation occurs; the selected product hook consumes its KV.
func qualifyHelmBundledContext(t *testing.T, ctx context.Context, api kubernetes.Interface, config *rest.Config, f fixture, x helmBootstrapFixture, desired contracts.InitialBootstrap, original contracts.InitialPreparer, sql *pgxpool.Pool, originalStore *s3.Client, public *helmBundledPublic, identity *installedIdentity, browser *installedBrowser) {
	t.Helper()
	t.Setenv("ASSERVAT_JOURNEY_FOCUS", "journey")
	if browser == nil || identity.SubjectID == "" || len(f.Clusters) != 1 || original.Plan.InstallationID == "" {
		t.Fatal("actual bundled context prerequisites")
	}
	installation := original.Plan.InstallationID
	owner, err := kube.OwnerInputs(ctx, config, desired.TargetNamespace, installation)
	if err != nil {
		t.Fatal("actual installed owner", err)
	}
	offer, err := kube.ReadRegionalOffer(ctx, config, desired.TargetNamespace, installation)
	if err != nil || offer.PermissionRootID != owner.PermissionRootID {
		t.Fatal("actual original public offer", err)
	}
	// Create the one real target BEFORE starting the original five-minute fleet
	// slot. No renamed Pod/namespace or invented UID enters the request.
	workload := createRegionalWorkload(t, ctx, api, desired.Image, "apps-regional", false)
	issued := issueInstalledFleetBootstrap(t, ctx, sql, browser, installation)
	if issued.ClusterID == owner.ClusterID {
		t.Fatal("same physical API reused the hub's logical cluster ID")
	}
	budget := newRegionalBudget(t, ctx, api, desired.TargetNamespace, identity.Issuer, issued.ClusterID, 1)
	budget.subjectKind, budget.subjectID = "User", identity.SubjectID
	budget.addPolicy()
	budget.addBinding(workload)
	installed := runHelmBundledRegion(t, ctx, api, f.Clusters[0].Config, x, desired, issued)
	if installed.Join == nil || installed.Join.ClusterID != issued.ClusterID || installed.Join.PeerID != issued.PeerID || installed.Join.InstallationID != installation || installed.Join.IssuerEpoch != issued.IssuerEpoch {
		t.Fatal("actual selected regional result changed the browser-issued binding")
	}
	waitHelmBundledRegionLeaves(t, ctx, api, sql, offer, issued)
	qualifyRegionalExecutor(t, ctx, sql, api, offer, installed, issued.PeerID)
	prefix := "asservat-" + strings.ReplaceAll(installation, "-", "")
	diagnose := installedHubDiagnose(t, ctx, sql, api, offer.PermissionRootID, installation, desired.TargetNamespace, prefix)
	deletion, auditRead := bundledContextObservationStores(t, ctx, api, desired.TargetNamespace, installation, originalStore)
	deleted := installedJourneyDeletionWithStores(t, ctx, sql, deletion, auditRead, offer.EvidenceStore.Bucket, desired.AuditStore.Bucket, offer.PermissionRootID, nil, diagnose)
	installedPublisherSettled = func(current context.Context) {
		waitInstalledPublisherSettled(t, current, api, desired.TargetNamespace, installation)
	}
	installedContextStandbyWindow(t, ctx, api, desired.TargetNamespace, prefix+"-owner")
	journey := installedJourney(t, ctx, sql, offer.PermissionRootID, identity, public.root, net.JoinHostPort(public.nodeIP, "31450"), browser.base, diagnose, deleted, installedProjectionSQLCheck(t, ctx, sql, api, offer.PermissionRootID), nil)
	qualifyRegionalCapacity(t, ctx, sql, api, api, api, desired.TargetNamespace, identity.Issuer, journey, installation, offer, installed, 1, &regionalPrepared{workload: workload, budget: budget}, "", true)
	t.Log("actual bundled same-API context: one browser-issued slot, product-selected regional Helm, new logical cluster, real User binding, native/range download and read-only managed deletion proof; no synthetic policy-denial injection")
}

func runHelmBundledRegion(t *testing.T, ctx context.Context, api kubernetes.Interface, kubeconfig string, x helmBootstrapFixture, desired contracts.InitialBootstrap, issued installedFleetBootstrapReceipt) kube.RegionalInstallation {
	t.Helper()
	const release = "asservat-region"
	values := helmBundledRegionValues(desired, issued)
	file := filepath.Join(t.TempDir(), "regional-values.json")
	helmBootstrapWriteValues(t, file, values)
	// The hook's own operation remains bounded by issued.NotAfter; this test's
	// command timeout cannot extend its original product authority.
	run, end := context.WithDeadline(ctx, issued.NotAfter)
	defer end()
	command := exec.CommandContext(run, "helm", "upgrade", "--install", release, x.ChartArchive, "--kubeconfig", kubeconfig, "--namespace", desired.BootstrapNamespace, "--values", file, "--skip-crds", "--wait", "--timeout", "5m", "--history-max", "2")
	out := &helmBootstrapOutput{}
	command.Stdout = out
	command.Stderr = out
	if err := command.Run(); err != nil {
		helmClusterLogs(t, ctx, api, desired.BootstrapNamespace)
		t.Fatalf("bundled regional/helm: %v %s", err, out.Bytes())
	}
	job, err := api.BatchV1().Jobs(desired.BootstrapNamespace).Get(ctx, release+"-cluster-installer", meta.GetOptions{})
	if err != nil || job.Status.Succeeded != 1 || job.Status.Failed != 0 || job.UID == "" {
		t.Fatal("actual selected regional Job did not complete once", err)
	}
	pods, err := api.CoreV1().Pods(desired.BootstrapNamespace).List(ctx, meta.ListOptions{LabelSelector: "job-name=" + job.Name})
	if err != nil || len(pods.Items) != 1 {
		t.Fatal("actual regional Job has additional/missing Pods", err)
	}
	pod := pods.Items[0]
	if len(pod.OwnerReferences) != 1 || pod.OwnerReferences[0].UID != job.UID || pod.OwnerReferences[0].Kind != "Job" || pod.Status.Phase != core.PodSucceeded || len(pod.Spec.Containers) != 1 || len(pod.Status.ContainerStatuses) != 1 || pod.Spec.ServiceAccountName != desired.Name+"-bootstrap-runner" || pod.Spec.Containers[0].Image != desired.Image {
		t.Fatal("regional hook identity or terminal mismatch")
	}
	status := pod.Status.ContainerStatuses[0]
	if status.RestartCount != 0 || status.State.Terminated == nil || status.State.Terminated.ExitCode != 0 || !strings.HasSuffix(status.ImageID, strings.Split(desired.Image, "@")[1]) {
		t.Fatal("actual regional product command did not exit positively")
	}
	raw, err := api.CoreV1().Pods(desired.BootstrapNamespace).GetLogs(pod.Name, &core.PodLogOptions{Container: "installer", LimitBytes: ptr.To(int64(contracts.RegionalJoinMaxBytes + 1))}).DoRaw(ctx)
	if err != nil || len(raw) > contracts.RegionalJoinMaxBytes {
		t.Fatal("bounded actual regional result unavailable", err)
	}
	var installed kube.RegionalInstallation
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&installed) != nil || decoder.Decode(new(any)) != io.EOF || installed.Join == nil || installed.Secret.UID == "" {
		t.Fatal("actual regional result shape")
	}
	return installed
}
func helmBundledRegionValues(desired contracts.InitialBootstrap, issued installedFleetBootstrapReceipt) map[string]any {
	return map[string]any{"mode": "cluster", "cluster": map[string]any{"enabled": true, "namespace": "asservat-connector", "image": desired.Image, "registrySecret": "operator-pull", "bundledHub": desired.Name, "bootstrapID": issued.BootstrapID}}
}

func waitHelmBundledRegionLeaves(t *testing.T, ctx context.Context, api kubernetes.Interface, sql *pgxpool.Pool, offer contracts.RegionalOffer, issued installedFleetBootstrapReceipt) {
	t.Helper()
	bounded, end := context.WithTimeout(ctx, 3*time.Minute)
	defer end()
	observed := false
	checkpoint := time.Now().Add(30 * time.Second)
	for bounded.Err() == nil {
		var ready bool
		err := sql.QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM connector_identity_process p WHERE p.root_id=$1 AND p.peer_id=$2 AND p.accepted_at IS NOT NULL
AND EXISTS(SELECT 1 FROM connector_credential_attempt c WHERE c.id=p.client_current_id AND c.activated_at IS NOT NULL)
AND EXISTS(SELECT 1 FROM connector_credential_attempt c WHERE c.id=p.server_current_id AND c.activated_at IS NOT NULL))`, offer.PermissionRootID, issued.PeerID).Scan(&ready)
		if err == nil && ready {
			return
		}
		if !observed && time.Now().After(checkpoint) {
			regionalEnrollmentDiagnostics(t, bounded, sql, offer.InstallationID, issued.BootstrapID, offer.PermissionRootID, issued.PeerID)
			observed = true
		}
		if installedJourneyPause(bounded, time.Second) != nil {
			break
		}
	}
	regionalLogs(t, ctx, api)
	regionalEnrollmentDiagnostics(t, ctx, sql, offer.InstallationID, issued.BootstrapID, offer.PermissionRootID, issued.PeerID)
	t.Fatal("bundled regional/enrollment: both exact credential leaves unavailable")
}

func bundledContextObservationStores(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace, installation string, original *s3.Client) (*s3.Client, *s3.Client) {
	t.Helper()
	prefix := "asservat-" + strings.ReplaceAll(installation, "-", "")
	config, err := api.CoreV1().ConfigMaps(namespace).Get(ctx, prefix+"-worker-inputs", meta.GetOptions{})
	if err != nil {
		t.Fatal("actual worker audit selection", err)
	}
	worker, err := contracts.DecodeHubWorkerDeployment(strings.NewReader(config.Data["deployment.json"]))
	if err != nil || worker.InstallationID != installation || worker.ProviderAuthentication == nil || worker.ProviderAuthentication.AuditCredentials.UID == "" {
		t.Fatal("actual worker provider input", err)
	}
	audit := bundledRuntimeObservationStore(t, ctx, api, namespace, worker.ProviderAuthentication.AuditCredentials, contracts.ConfigurationProviderAuditCredentialFile, original)
	deletionName := contracts.EvidenceDeleteCredentialName(installation)
	deletion, err := api.CoreV1().Secrets(namespace).Get(ctx, deletionName, meta.GetOptions{})
	if err != nil {
		t.Fatal("actual retained deletion reader", err)
	}
	ref := contracts.WorkerObjectReference{Name: deletion.Name, UID: string(deletion.UID)}
	for _, raw := range deletion.Data {
		clear(raw)
	}
	return bundledRuntimeObservationStore(t, ctx, api, namespace, ref, contracts.EvidenceDeleteCredentialFile, original), audit
}

func bundledRuntimeObservationStore(t *testing.T, ctx context.Context, api kubernetes.Interface, namespace string, ref contracts.WorkerObjectReference, key string, original *s3.Client) *s3.Client {
	t.Helper()
	source, err := api.CoreV1().Secrets(namespace).Get(ctx, ref.Name, meta.GetOptions{})
	if err != nil || source.Namespace != namespace || source.Name != ref.Name || source.Type != core.SecretTypeOpaque || source.ResourceVersion == "" || string(source.UID) != ref.UID || source.DeletionTimestamp != nil {
		t.Fatal("actual retained observation credential changed", err)
	}
	// Match each ACTUAL retained source contract. The provider audit Secret is
	// protected mutable material; the evidence-delete Secret is immutable.
	if key == contracts.ConfigurationProviderAuditCredentialFile {
		if source.Immutable != nil && *source.Immutable {
			t.Fatal("worker audit source has unsupported immutable shape")
		}
	} else if key == contracts.EvidenceDeleteCredentialFile {
		if source.Immutable == nil || !*source.Immutable {
			t.Fatal("evidence-delete source is not original immutable material")
		}
	} else {
		t.Fatal("unsupported observation credential purpose")
	}
	credential, err := contracts.DecodeOwnerStorageCredential(bytes.NewReader(source.Data[key]))
	for _, raw := range source.Data {
		clear(raw)
	}
	if err != nil || credential.AccessKeyID == "" || credential.SecretAccessKey == "" {
		t.Fatal("actual observation credential unavailable", err)
	}
	options := original.Options()
	options.Credentials = credentials.NewStaticCredentialsProvider(credential.AccessKeyID, credential.SecretAccessKey, credential.SessionToken)
	options.RetryMaxAttempts = 1
	return s3.New(options)
}
