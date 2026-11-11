package integration

import (
	"encoding/json"
	"strings"
	"testing"

	kube "asservat.local/asservat/internal/adapters/kubernetes"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/privacy"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestInstalledReportUsesProjectedProcessingSource(t *testing.T) {
	installation := consoleCaptureID(1)
	const namespace = "synthetic-control"
	plan := kube.OwnerWorkloadPlan{InstallationID: installation, Namespace: namespace, Name: "synthetic-owner", ServiceAccount: "synthetic-owner",
		Configuration: "synthetic-owner-inputs", Credentials: "synthetic-owner-credentials", WorkloadGuard: "synthetic-owner-guard", Image: "registry.example.test/asservat@sha256:" + strings.Repeat("a", 64)}
	workload, err := kube.BuildOwnerWorkload(plan)
	if err != nil {
		t.Fatal("actual owner projection producer", err)
	}
	processing := contracts.WorkerObjectReference{Name: "synthetic-processing-source", UID: consoleCaptureID(2)}
	download := contracts.WorkerObjectReference{Name: contracts.OwnerDownloadEnvironmentName(installation), UID: consoleCaptureID(3)}
	deployment := contracts.OwnerDeployment{Format: contracts.OwnerDeploymentFormat, InstallationID: installation, Public: &contracts.OwnerPublicDeployment{
		Processing: &contracts.OwnerPublicEnvironment{Source: processing}, DownloadEnvironment: contracts.OwnerPublicEnvironment{Source: download},
	}}
	encoded, err := json.Marshal(deployment)
	if err != nil {
		t.Fatal(err)
	}
	// Identical configuration has a different source identity in the two
	// actual projections. Comparing only settings/digest cannot detect selection.
	settings := `{"format":"synthetic-same-settings"}`
	client := fake.NewClientset(workload.Deployment,
		&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: namespace, Name: plan.Configuration}, Data: map[string]string{"deployment.json": string(encoded)}},
		&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: namespace, Name: processing.Name, UID: types.UID(processing.UID)}, Data: map[string]string{contracts.DownloadEnvironmentFile: settings}},
		&core.ConfigMap{ObjectMeta: meta.ObjectMeta{Namespace: namespace, Name: download.Name, UID: types.UID(download.UID)}, Data: map[string]string{contracts.DownloadEnvironmentFile: settings}},
	)
	selected, err := installedProcessingReportSource(t.Context(), client, namespace, installation)
	if err != nil || selected.Name != processing.Name || string(selected.UID) != processing.UID {
		t.Fatal("report provenance selected the download source instead of the actual projected processing source", err)
	}
	header := value.ProcessingReportPage{PolicyRevision: value.ProcessingReportRevision{UID: processing.UID}}
	expected := header
	expected.PolicyRevision.UID = string(selected.UID)
	if mismatch := installedReportProvenanceMismatch(header, expected); mismatch != "" {
		t.Fatal("actual selected processing header mismatched independent source projection", mismatch)
	}
	// A retained source with the right name but another UID is unavailable;
	// selecting the download object cannot silently repair the original pin.
	changed, err := client.CoreV1().ConfigMaps(namespace).Get(t.Context(), processing.Name, meta.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	changed.UID = types.UID(download.UID)
	if _, err = client.CoreV1().ConfigMaps(namespace).Update(t.Context(), changed, meta.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err = installedProcessingReportSource(t.Context(), client, namespace, installation); err == nil {
		t.Fatal("changed actual processing source UID was adopted")
	}
}
