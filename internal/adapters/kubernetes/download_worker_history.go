package kubernetes

import (
	"context"
	"encoding/json"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// Cleanup authenticates the original admitted spec digests. It must not
// regenerate today's launch template and strand a worker from an older image.
// These helpers cannot launch, bind or authorize an acquisition worker.
func checkedHistoricalJob(w value.DownloadWorker, raw []byte) (*batch.Job, error) {
	if !w.Valid() {
		return nil, artifact.ErrInvalid
	}
	return checkedHistoricalAcquisitionJob(w.Acquisition(), raw)
}
func checkedHistoricalAcquisitionJob(w value.AcquisitionWorker, raw []byte) (*batch.Job, error) {
	var j batch.Job
	if !w.Valid() || permissionJSON(raw, 256<<10, 32768) != nil || json.Unmarshal(raw, &j) != nil || j.APIVersion != "batch/v1" || j.Kind != "Job" || j.Namespace != w.Binding.Namespace || j.Name != w.Binding.Job || string(j.UID) != w.Binding.JobUID || j.Labels[acquisitionWorkerLabel(w.Intent.Parent.Purpose)] != w.Intent.ID {
		return nil, artifact.ErrIntegrity
	}
	d, err := WorkerSpecDigest("Job", specBytes(raw))
	if err != nil || d != w.Job.Spec || d != w.Binding.JobSpec {
		return nil, artifact.ErrIntegrity
	}
	b, _ := json.Marshal(j.Spec)
	typed, err := WorkerSpecDigest("Job", b)
	if err != nil || typed != d {
		return nil, artifact.ErrIntegrity
	}
	return &j, nil
}

func (s *DownloadWorkerJobs) historicalJob(ctx context.Context, w value.DownloadWorker) (*batch.Job, error) {
	if !w.Valid() {
		return nil, artifact.ErrInvalid
	}
	return s.historicalAcquisitionJob(ctx, w.Acquisition())
}
func (s *DownloadWorkerJobs) historicalAcquisitionJob(ctx context.Context, w value.AcquisitionWorker) (*batch.Job, error) {
	b, e := s.client.api.Get().AbsPath("/apis/batch/v1/namespaces/" + s.profile.Namespace + "/jobs/" + w.Binding.Job).MaxRetries(0).DoRaw(ctx)
	if e != nil {
		if apierrors.IsNotFound(e) {
			return nil, errWorkerJobMissing
		}
		return nil, artifact.ErrDownloadUnavailable
	}
	defer clear(b)
	return checkedHistoricalAcquisitionJob(w, b)
}

func checkedHistoricalPod(w value.DownloadWorker, raw []byte) (*core.Pod, error) {
	if !w.Valid() {
		return nil, artifact.ErrInvalid
	}
	return checkedHistoricalAcquisitionPod(w.Acquisition(), raw)
}
func checkedHistoricalAcquisitionPod(w value.AcquisitionWorker, raw []byte) (*core.Pod, error) {
	var p core.Pod
	if !w.Valid() || permissionJSON(raw, 256<<10, 32768) != nil || json.Unmarshal(raw, &p) != nil || (p.APIVersion != "" && p.APIVersion != "v1") || (p.Kind != "" && p.Kind != "Pod") || p.Namespace != w.Binding.Namespace || p.Name != w.Binding.Pod || string(p.UID) != w.Binding.PodUID || p.Labels[acquisitionWorkerLabel(w.Intent.Parent.Purpose)] != w.Intent.ID {
		return nil, artifact.ErrIntegrity
	}
	controllers := 0
	for _, o := range p.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			controllers++
			if o.Kind != "Job" || o.APIVersion != "batch/v1" || o.Name != w.Binding.Job || string(o.UID) != w.Binding.JobUID {
				return nil, artifact.ErrIntegrity
			}
		}
	}
	if controllers != 1 {
		return nil, artifact.ErrIntegrity
	}
	d, err := WorkerSpecDigest("Pod", specBytes(raw))
	if err != nil || d != w.Binding.PodSpec {
		return nil, artifact.ErrIntegrity
	}
	b, _ := json.Marshal(p.Spec)
	typed, err := WorkerSpecDigest("Pod", b)
	if err != nil || typed != d {
		return nil, artifact.ErrIntegrity
	}
	return &p, nil
}

// ObserveExpiredProjectionWorker handles abandoned query work that never
// reached human-driven binding. It can only prove termination of the exact
// original deterministic Job and its sole real Pod; it grants no live binding.
func (s *DownloadWorkerJobs) ObserveExpiredProjectionWorker(ctx context.Context, i value.AcquisitionWorkerIntent, receipt value.DownloadWorkerJob, worker value.AcquisitionWorker) (value.AcquisitionWorkerTermination, error) {
	var out value.AcquisitionWorkerTermination
	if s == nil || s.client == nil || ctx == nil || ctx.Err() != nil || !i.Valid() || i.Parent.Purpose != value.AcquisitionProjection || i.Profile != s.profile || s.client.now().Before(i.RunUntil) {
		return out, artifact.ErrInvalid
	}
	if worker.Valid() {
		if worker.Intent != i || worker.Job != receipt {
			return out, artifact.ErrIntegrity
		}
		return s.ObserveAcquisitionWorkerTermination(ctx, worker)
	}
	call, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	start := s.client.now()
	job, actual, err := s.getAcquisitionJob(call, i)
	if err != nil || !workerJobTerminal(job) || receipt != (value.DownloadWorkerJob{}) && receipt != actual {
		return out, artifact.ErrDownloadUnavailable
	}
	items, err := s.acquisitionPods(call, i)
	if err != nil || len(items) != 1 {
		return out, artifact.ErrDownloadUnavailable
	}
	pod, digest, err := checkedAcquisitionPod(i, actual, items[0])
	if err != nil {
		return out, err
	}
	binding := value.AcquisitionWorkerBinding{Parent: i.Parent, InstallationID: i.Profile.InstallationID, ClusterID: i.Profile.ClusterID, Namespace: i.Profile.Namespace, NamespaceUID: i.Profile.NamespaceUID, ServiceAccount: i.Profile.ServiceAccount, ServiceAccountUID: i.Profile.ServiceAccountUID, Job: i.JobName(), JobUID: actual.UID, JobSpec: actual.Spec, Pod: pod.Name, PodUID: string(pod.UID), PodSpec: digest}
	worker = value.AcquisitionWorker{Intent: i, Job: actual, Binding: binding}
	if !worker.Valid() {
		return out, artifact.ErrIntegrity
	}
	return s.acquisitionTermination(call, worker, start, items)
}
