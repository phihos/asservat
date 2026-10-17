package kubernetes

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestWorkerCleanupUsesAdmittedHistoricalTemplate(t *testing.T) {
	p := value.DownloadWorkerProfile{Namespace: "workers", ServiceAccount: "acquisition", Image: "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "control", CPUMillis: 100, MemoryBytes: 64 << 20}
	id := "10000000-0000-4000-8000-000000000001"
	i := value.DownloadWorkerIntent{ID: id, SessionID: id, Profile: p, CreatedAt: time.Now().UTC(), RunUntil: time.Now().UTC().Add(time.Minute)}
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
	w := value.DownloadWorker{Intent: i, Job: value.DownloadWorkerJob{IntentID: id, UID: string(job.UID), Spec: jd}, Binding: value.KeyWorkerBinding{Namespace: p.Namespace, Job: job.Name, JobUID: string(job.UID), JobSpec: jd, Pod: pod.Name, PodUID: id, PodSpec: pd}}
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
