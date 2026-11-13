package integration

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5/pgxpool"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

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
