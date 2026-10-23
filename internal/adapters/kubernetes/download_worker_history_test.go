package kubernetes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestWorkerCleanupUsesAdmittedHistoricalTemplate(t *testing.T) {
	id := "10000000-0000-4000-8000-000000000001"
	// Use a complete admitted record whose original authority and worker lifetime
	// have both expired. Historical cleanup consumes its identity/specs, not a
	// fresh admission or today's launch template.
	admittedAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	until := admittedAt.Add(5 * time.Second)
	revision := identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}
	principal := identity.Principal{Issuer: "https://id.example.test", Subject: "developer", ClientID: "console", Kind: identity.Human}
	p := value.DownloadWorkerProfile{
		Configuration: revision, InstallationID: id, ClusterID: id,
		Namespace: "workers", NamespaceUID: "workers-uid", ServiceAccount: "acquisition", ServiceAccountUID: "acquisition-uid",
		Image: "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "control", ControlConfigUID: "control-uid",
		PriorityClass: "workers", PriorityClassUID: "priority-uid", ControlDigest: artifact.Digest{2},
		CPUMillis: 100, MemoryBytes: 64 << 20, MaxRuntime: time.Minute,
	}
	scope := artifact.DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "target-namespace", WorkloadUID: "target-workload", PodUID: "target-pod", Version: artifact.Digest{3}, Principal: principal}
	location := artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}
	path := artifact.DownloadPath{ID: id, TargetClusterID: id, StoreID: id, StorageRegion: "local", AcquisitionClusterID: id, AcquisitionRegion: "local", ConnectorClusterID: id, ConnectorRegion: "local", HubClusterID: id, HubRegion: "local", WorkerConfiguration: revision, HubConfiguration: revision}
	processing := artifact.DownloadProcessingProof{RootID: id, Epoch: id, CaptureID: id, Location: location, Sequence: 1, StateDigest: artifact.Digest{4}, ObservedAt: admittedAt, ValidUntil: until}
	environment := artifact.DownloadEnvironment{RootID: id, InstallationID: id, Region: "local", StoreID: id, RecoveryEpoch: id, Location: location, Principal: principal, Revision: revision, RecoveryRevision: revision, Path: path, Processing: processing, ObservedAt: admittedAt, ValidUntil: until}
	retention := artifact.RetentionProof{RootID: id, ClusterID: id, NamespaceUID: scope.NamespaceUID, WorkloadUID: scope.WorkloadUID, PodUID: scope.PodUID, Topology: revision, Policy: revision, Selectors: revision, SourceCount: 1, Sources: [2]artifact.RetentionSourceVersion{{ClusterID: id, ControlNamespaceUID: "control-uid", Epoch: id, Hub: true, ProtectionDigest: artifact.Digest{5}, SnapshotDigest: artifact.Digest{6}, Acceptance: revision}}, ObservedAt: admittedAt, ValidUntil: until}
	authority := artifact.DownloadAuthority{Environment: environment, Retention: retention, Scope: scope, PermissionEpoch: id, PermissionSequence: 1, ProjectionDigest: artifact.Digest{7}, DecisionDigest: artifact.Digest{8}, IdentityRevision: revision, CheckedAt: admittedAt, ValidUntil: until, AccessUntil: admittedAt.Add(time.Minute), DeleteBy: admittedAt.Add(2 * time.Minute)}
	i := value.DownloadWorkerIntent{ID: id, SessionID: id, Generation: 1, Profile: p, Authority: authority, CreatedAt: admittedAt, RunUntil: admittedAt.Add(time.Minute)}
	job := workerJob(i)
	job.UID = "historical-job"
	// The pre-startup-contract template had no Downward API environment and no
	// created-at/installation/cluster/digest flags. Cleanup still owns its exact
	// originally stored IDs/spec digests, never a guessed replacement template.
	job.Spec.Template.Spec.Containers[0].Env = nil
	job.Spec.Template.Spec.Containers[0].Args = []string{"download-worker", "--dispatch", id, "--session", id, "--until", i.RunUntil.UTC().Format(time.RFC3339Nano), "--control", "/run/asservat/control/worker.json", "--token", DownloadWorkerTokenPath}
	jraw, _ := json.Marshal(job)
	jd, err := WorkerSpecDigest("Job", specBytes(jraw))
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	pod := core.Pod{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta.ObjectMeta{Name: "old-worker", Namespace: p.Namespace, UID: types.UID(id), Labels: job.Spec.Template.Labels, OwnerReferences: []meta.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: &yes}}}, Spec: *job.Spec.Template.Spec.DeepCopy()}
	praw, _ := json.Marshal(pod)
	pd, err := WorkerSpecDigest("Pod", specBytes(praw))
	if err != nil {
		t.Fatal(err)
	}
	w := value.DownloadWorker{Intent: i, Job: value.DownloadWorkerJob{IntentID: id, UID: string(job.UID), Spec: jd}, Binding: value.KeyWorkerBinding{InstallationID: p.InstallationID, DownloadID: i.SessionID, ClusterID: p.ClusterID, Namespace: p.Namespace, NamespaceUID: p.NamespaceUID, ServiceAccount: p.ServiceAccount, ServiceAccountUID: p.ServiceAccountUID, Job: job.Name, JobUID: string(job.UID), JobSpec: jd, Pod: pod.Name, PodUID: id, PodSpec: pd}}
	if !w.Valid() || !w.Acquisition().Valid() || !environment.CurrentValid(admittedAt) || !retention.Valid(admittedAt) {
		t.Fatal("invalid original admitted worker fixture")
	}
	if authority.Valid(time.Now()) || time.Now().Before(i.RunUntil) {
		t.Fatal("historical cleanup fixture is still current")
	}
	driver := &DownloadWorkerJobs{profile: p}
	if _, _, err = driver.checkedJob(i, jraw); err == nil {
		t.Fatal("legacy launch accepted as new template")
	}
	if _, _, err = checkedWorkerPod(i, w.Job, praw); err == nil {
		t.Fatal("legacy Pod accepted for new binding")
	}
	if _, err = checkedHistoricalJob(w, jraw); err != nil {
		t.Fatal("original historical Job rejected", err)
	}
	if _, err = checkedHistoricalPod(w, praw); err != nil {
		t.Fatal("original historical Pod rejected", err)
	}
	bad := w
	bad.Binding.PodSpec = artifact.Digest{7}
	if _, err = checkedHistoricalPod(bad, praw); err == nil {
		t.Fatal("substituted spec accepted")
	}
	bad = w
	bad.Job.UID = "replacement"
	bad.Binding.JobUID = "replacement"
	if _, err = checkedHistoricalJob(bad, jraw); err == nil {
		t.Fatal("replacement Job accepted")
	}
	if _, err = checkedHistoricalPod(bad, praw); err == nil {
		t.Fatal("changed Pod owner accepted")
	}
	pod.Spec.Containers[0].Args = append(pod.Spec.Containers[0].Args, "arbitrary")
	praw, _ = json.Marshal(pod)
	if _, err = checkedHistoricalPod(w, praw); err == nil {
		t.Fatal("changed historical spec accepted")
	}
}
