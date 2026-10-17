package kubernetes

import (
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestWorkerStartupWaitExcludesKnownExecutionAndTermination(t *testing.T) {
	for _, mode := range []string{"no-pod", "pending", "scheduled", "running", "unknown", "succeeded", "failed", "deleted-pod", "deleted-job", "job-failed", "job-completed", "job-active-overlap", "job-condition", "container-terminated", "container-restarted"} {
		t.Run(mode, func(t *testing.T) {
			j := &batch.Job{}
			p := &core.Pod{Status: core.PodStatus{Phase: core.PodPending}}
			at := meta.Now()
			want := false
			switch mode {
			case "no-pod":
				p = nil
				want = true
			case "pending":
				want = true
			case "scheduled":
				p.Spec.NodeName = "node"
				want = true
			case "running":
				p.Status.Phase = core.PodRunning
			case "unknown":
				p.Status.Phase = core.PodUnknown
			case "succeeded":
				p.Status.Phase = core.PodSucceeded
			case "failed":
				p.Status.Phase = core.PodFailed
			case "deleted-pod":
				p.DeletionTimestamp = &at
			case "deleted-job":
				j.DeletionTimestamp = &at
			case "job-failed":
				j.Status.Failed = 1
			case "job-completed":
				j.Status.CompletionTime = &at
			case "job-active-overlap":
				j.Status.Active = 2
			case "job-condition":
				j.Status.Conditions = []batch.JobCondition{{Type: batch.JobFailed, Status: core.ConditionTrue}}
			case "container-terminated":
				p.Status.ContainerStatuses = []core.ContainerStatus{{State: core.ContainerState{Terminated: &core.ContainerStateTerminated{}}}}
			case "container-restarted":
				p.Status.ContainerStatuses = []core.ContainerStatus{{RestartCount: 1}}
			}
			if workerStartupPending(j, p) != want {
				t.Fatal("incorrect scheduling classification", mode)
			}
		})
	}
}
