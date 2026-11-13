package kubernetes

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

func TestWorkerCleanupUsesAdmittedHistoricalTemplate(t *testing.T) {
	w, _, pod, jraw, praw := historicalWorkerFixture(t)
	i := w.Intent
	driver := &DownloadWorkerJobs{profile: i.Profile}
	if _, _, err := driver.checkedJob(i, jraw); err == nil {
		t.Fatal("legacy launch accepted as new template")
	}
	if _, _, err := checkedWorkerPod(i, w.Job, praw); err == nil {
		t.Fatal("legacy Pod accepted for new binding")
	}
	if _, err := checkedHistoricalJob(w, jraw); err != nil {
		t.Fatal("original historical Job rejected", err)
	}
	if _, err := checkedHistoricalPod(w, praw); err != nil {
		t.Fatal("original historical Pod rejected", err)
	}
	bad := w
	bad.Binding.PodSpec = artifact.Digest{7}
	if _, err := checkedHistoricalPod(bad, praw); err == nil {
		t.Fatal("substituted spec accepted")
	}
	bad = w
	bad.Job.UID = "replacement"
	bad.Binding.JobUID = "replacement"
	if _, err := checkedHistoricalJob(bad, jraw); err == nil {
		t.Fatal("replacement Job accepted")
	}
	if _, err := checkedHistoricalPod(bad, praw); err == nil {
		t.Fatal("changed Pod owner accepted")
	}
	pod.Spec.Containers[0].Args = append(pod.Spec.Containers[0].Args, "arbitrary")
	praw, _ = json.Marshal(pod)
	if _, err := checkedHistoricalPod(w, praw); err == nil {
		t.Fatal("changed historical spec accepted")
	}
}

// native90: activeDeadlineSeconds killed the shared query worker and the Job
// controller deleted its Pod. The Job's accounted terminal record is positive
// termination evidence; Pod absence alone never is.
func TestWorkerTerminationAcceptsJobControllerRemovedPod(t *testing.T) {
	w, job, pod, _, _ := historicalWorkerFixture(t)
	zero := int32(0)
	killed := func() *batch.Job {
		j := job.DeepCopy()
		j.Status = batch.JobStatus{Failed: 1, Ready: &zero, Terminating: &zero, UncountedTerminatedPods: &batch.UncountedTerminatedPods{}, Conditions: []batch.JobCondition{
			{Type: batch.JobFailureTarget, Status: core.ConditionTrue, Reason: batch.JobReasonDeadlineExceeded},
			{Type: batch.JobFailed, Status: core.ConditionTrue, Reason: batch.JobReasonDeadlineExceeded, LastTransitionTime: meta.Now()},
		}}
		return j
	}
	terminalPod := func(phase core.PodPhase) []json.RawMessage {
		p := pod.DeepCopy()
		p.Status = core.PodStatus{Phase: phase, ContainerStatuses: []core.ContainerStatus{{Name: "acquisition", State: core.ContainerState{Terminated: &core.ContainerStateTerminated{ContainerID: "containerd://worker", FinishedAt: meta.NewTime(time.Now().Add(-time.Second)), Reason: "Error", ExitCode: 143}}}}}
		raw, _ := json.Marshal(p)
		return []json.RawMessage{raw}
	}
	for _, tc := range []struct {
		name  string
		edit  func(*batch.Job)
		items []json.RawMessage
		want  bool
	}{
		{"deadline-killed-pod-deleted", func(*batch.Job) {}, nil, true},
		{"backoff-pod-deleted", func(j *batch.Job) { j.Status.Conditions[1].Reason = batch.JobReasonBackoffLimitExceeded }, nil, true},
		{"completed-pod-deleted", func(j *batch.Job) {
			j.Status.Failed, j.Status.Succeeded = 0, 1
			j.Status.Conditions = []batch.JobCondition{{Type: batch.JobComplete, Status: core.ConditionTrue}}
		}, nil, true},
		{"deadline-killed-pod-terminal", func(*batch.Job) {}, terminalPod(core.PodFailed), true},
		{"pod-absent-job-active", func(j *batch.Job) { j.Status.Active, j.Status.Conditions = 1, nil }, nil, false},
		{"pod-absent-job-active-counted", func(j *batch.Job) { j.Status.Active = 1 }, nil, false},
		{"pod-absent-no-condition", func(j *batch.Job) { j.Status.Conditions = nil }, nil, false},
		{"pod-absent-failure-target-only", func(j *batch.Job) { j.Status.Conditions = j.Status.Conditions[:1] }, nil, false},
		{"pod-absent-other-failure", func(j *batch.Job) { j.Status.Conditions[1].Reason = "PodFailurePolicy" }, nil, false},
		{"pod-absent-condition-false", func(j *batch.Job) { j.Status.Conditions[1].Status = core.ConditionFalse }, nil, false},
		{"pod-absent-terminating", func(j *batch.Job) { one := int32(1); j.Status.Terminating = &one }, nil, false},
		{"pod-absent-ready", func(j *batch.Job) { one := int32(1); j.Status.Ready = &one }, nil, false},
		{"pod-absent-uncounted", func(j *batch.Job) { j.Status.UncountedTerminatedPods.Failed = []types.UID{"x"} }, nil, false},
		{"pod-absent-never-counted", func(j *batch.Job) { j.Status.Failed = 0 }, nil, false},
		{"pod-absent-job-uid-mismatch", func(j *batch.Job) { j.UID = "replacement" }, nil, false},
		{"pod-present-running", func(*batch.Job) {}, terminalPod(core.PodRunning), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := killed()
			tc.edit(j)
			driver := &DownloadWorkerJobs{profile: w.Intent.Profile, client: &PermissionClient{now: time.Now}}
			got, err := driver.acquisitionTermination(context.Background(), w.Acquisition(), time.Now(), j, tc.items)
			if (err == nil) != tc.want || tc.want && (!got.Valid(got.ObservedAt) || got.Worker != w.Acquisition() || got.TerminationDigest == (artifact.Digest{})) {
				t.Fatal("termination evidence", tc.want, err)
			}
		})
	}
}

func historicalWorkerFixture(t *testing.T) (value.DownloadWorker, *batch.Job, core.Pod, []byte, []byte) {
	t.Helper()
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
		PriorityClass: "workers", PriorityClassUID: "priority-uid",
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
	return w, job, pod, jraw, praw
}

// Actual client-go GET/LIST and original UID/spec checks; synthetic API objects
// establish observer behavior only, not installed termination or SQL release.
func TestProjectionEarlyTerminationRequiresExactBoundPositiveObjects(t *testing.T) {
	for _, mode := range []string{"terminal", "unbound", "live", "replacement-job", "replacement-pod", "missing-job"} {
		t.Run(mode, func(t *testing.T) {
			old, _, _, _, _ := historicalWorkerFixture(t)
			i := old.Acquisition().Intent
			i.Parent = value.AcquisitionParent{Purpose: value.AcquisitionProjection, ID: i.ID}
			now := time.Now().UTC().Truncate(time.Second)
			i.CreatedAt, i.RunUntil = now.Add(-time.Second), now.Add(59*time.Second)
			job := acquisitionJob(i)
			job.UID = "original-query-job"
			job.Status = batch.JobStatus{Succeeded: 1, Conditions: []batch.JobCondition{{Type: batch.JobComplete, Status: core.ConditionTrue}}}
			jraw, _ := json.Marshal(job)
			driver := &DownloadWorkerJobs{profile: i.Profile}
			_, receipt, err := driver.checkedAcquisitionJob(i, jraw)
			if err != nil {
				t.Fatal(err)
			}
			yes := true
			pod := core.Pod{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta.ObjectMeta{Name: "query-pod", Namespace: i.Profile.Namespace, UID: types.UID(i.ID), Labels: job.Spec.Template.Labels, OwnerReferences: []meta.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: &yes}}}, Spec: *job.Spec.Template.Spec.DeepCopy()}
			pod.Status = core.PodStatus{Phase: core.PodSucceeded, ContainerStatuses: []core.ContainerStatus{{Name: "acquisition", State: core.ContainerState{Terminated: &core.ContainerStateTerminated{ContainerID: "containerd://original", FinishedAt: meta.NewTime(now), Reason: "Completed"}}}}}
			praw, _ := json.Marshal(pod)
			_, digest, err := checkedAcquisitionPod(i, receipt, praw)
			if err != nil {
				t.Fatal(err)
			}
			worker := value.AcquisitionWorker{Intent: i, Job: receipt, Binding: value.AcquisitionWorkerBinding{Parent: i.Parent, InstallationID: i.Profile.InstallationID, ClusterID: i.Profile.ClusterID, Namespace: i.Profile.Namespace, NamespaceUID: i.Profile.NamespaceUID, ServiceAccount: i.Profile.ServiceAccount, ServiceAccountUID: i.Profile.ServiceAccountUID, Job: job.Name, JobUID: string(job.UID), JobSpec: receipt.Spec, Pod: pod.Name, PodUID: string(pod.UID), PodSpec: digest}}
			if !worker.Valid() {
				t.Fatal("invalid bound early fixture")
			}
			gets, lists := 0, 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method != http.MethodGet {
					t.Error("early termination attempted mutation")
					w.WriteHeader(500)
					return
				}
				switch {
				case strings.Contains(r.URL.Path, "/jobs/"):
					gets++
					current := job.DeepCopy()
					if mode == "missing-job" {
						w.WriteHeader(404)
						_ = json.NewEncoder(w).Encode(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Reason: meta.StatusReasonNotFound, Code: 404})
						return
					}
					if mode == "replacement-job" {
						current.UID = "replacement"
					}
					_ = json.NewEncoder(w).Encode(current)
				case strings.HasSuffix(r.URL.Path, "/pods"):
					lists++
					current := pod.DeepCopy()
					if mode == "live" {
						current.Status = core.PodStatus{Phase: core.PodRunning}
					}
					if mode == "replacement-pod" {
						current.UID = "replacement"
					}
					_ = json.NewEncoder(w).Encode(core.PodList{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "PodList"}, ListMeta: meta.ListMeta{ResourceVersion: "1"}, Items: []core.Pod{*current}})
				default:
					t.Errorf("unexpected observer request %s", r.URL.Path)
					w.WriteHeader(500)
				}
			}))
			defer server.Close()
			client, err := NewPermissionClient(&rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})}}, i.Profile.ClusterID, cfg.NamespaceRef{Name: i.Profile.Namespace, UID: i.Profile.NamespaceUID}, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			driver.client = client
			if mode == "unbound" {
				worker = value.AcquisitionWorker{}
			}
			proof, err := driver.ObserveExpiredProjectionWorker(t.Context(), i, receipt, worker)
			if mode == "terminal" {
				if err != nil || !proof.Valid(time.Now()) || proof.Worker != worker || gets != 1 || lists != 1 || !time.Now().Before(i.RunUntil) {
					t.Fatal("exact positive early bound worker refused", err, gets, lists)
				}
			} else if err == nil {
				t.Fatal("nonpositive early termination accepted", mode)
			}
			if mode == "unbound" && gets+lists != 0 {
				t.Fatal("unbound worker triggered early discovery")
			}
		})
	}
}
