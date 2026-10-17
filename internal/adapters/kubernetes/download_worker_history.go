package kubernetes

import (
	"context"
	"encoding/json"

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
	var j batch.Job
	if permissionJSON(raw, 256<<10, 32768) != nil || json.Unmarshal(raw, &j) != nil || j.APIVersion != "batch/v1" || j.Kind != "Job" || j.Namespace != w.Binding.Namespace || j.Name != w.Binding.Job || string(j.UID) != w.Binding.JobUID || j.Labels[workerLabel] != w.Intent.ID {
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
	b, e := s.client.api.Get().AbsPath("/apis/batch/v1/namespaces/" + s.profile.Namespace + "/jobs/" + w.Binding.Job).MaxRetries(0).DoRaw(ctx)
	if e != nil {
		if apierrors.IsNotFound(e) {
			return nil, errWorkerJobMissing
		}
		return nil, artifact.ErrDownloadUnavailable
	}
	defer clear(b)
	return checkedHistoricalJob(w, b)
}

func checkedHistoricalPod(w value.DownloadWorker, raw []byte) (*core.Pod, error) {
	var p core.Pod
	if permissionJSON(raw, 256<<10, 32768) != nil || json.Unmarshal(raw, &p) != nil || (p.APIVersion != "" && p.APIVersion != "v1") || (p.Kind != "" && p.Kind != "Pod") || p.Namespace != w.Binding.Namespace || p.Name != w.Binding.Pod || string(p.UID) != w.Binding.PodUID || p.Labels[workerLabel] != w.Intent.ID {
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
