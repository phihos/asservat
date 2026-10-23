package integration

import (
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func TestInstalledProjectionWorkerRequiresOriginalLifetimeAndPositiveTermination(t *testing.T) {
	now := time.Now()
	w := value.AcquisitionWorker{Intent: value.AcquisitionWorkerIntent{RunUntil: now}, Binding: value.AcquisitionWorkerBinding{Namespace: "workers", Job: "query-original", JobUID: "original-job", Pod: "query-original-pod", PodUID: "original-pod"}}
	job := &batch.Job{ObjectMeta: meta.ObjectMeta{Namespace: w.Binding.Namespace, Name: w.Binding.Job, UID: types.UID(w.Binding.JobUID)}, Status: batch.JobStatus{Conditions: []batch.JobCondition{{Type: batch.JobComplete, Status: core.ConditionTrue}}}}
	pod := &core.Pod{ObjectMeta: meta.ObjectMeta{Namespace: w.Binding.Namespace, Name: w.Binding.Pod, UID: types.UID(w.Binding.PodUID), OwnerReferences: []meta.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: ptr.To(true)}}}, Status: core.PodStatus{Phase: core.PodSucceeded, ContainerStatuses: []core.ContainerStatus{{Name: "acquisition", State: core.ContainerState{Terminated: &core.ContainerStateTerminated{ContainerID: "containerd://original", FinishedAt: meta.NewTime(now), Reason: "Completed"}}}}}}
	for _, tc := range []struct {
		name string
		edit func(*value.AcquisitionWorker, *batch.Job, *core.Pod)
		want bool
	}{
		{"completed", func(*value.AcquisitionWorker, *batch.Job, *core.Pod) {}, true},
		{"failed-terminal", func(_ *value.AcquisitionWorker, j *batch.Job, p *core.Pod) {
			j.Status.Conditions[0].Type = batch.JobFailed
			p.Status.Phase = core.PodFailed
			p.Status.ContainerStatuses[0].State.Terminated.ExitCode = 1
		}, true},
		{"original-interval-live", func(w *value.AcquisitionWorker, _ *batch.Job, _ *core.Pod) {
			w.Intent.RunUntil = now.Add(time.Nanosecond)
		}, false},
		{"job-replaced", func(_ *value.AcquisitionWorker, j *batch.Job, _ *core.Pod) { j.UID = "replacement" }, false},
		{"pod-replaced", func(_ *value.AcquisitionWorker, _ *batch.Job, p *core.Pod) { p.UID = "replacement" }, false},
		{"wrong-owner", func(_ *value.AcquisitionWorker, _ *batch.Job, p *core.Pod) { p.OwnerReferences[0].UID = "replacement" }, false},
		{"job-not-terminal", func(_ *value.AcquisitionWorker, j *batch.Job, _ *core.Pod) { j.Status.Conditions = nil }, false},
		{"pod-running", func(_ *value.AcquisitionWorker, _ *batch.Job, p *core.Pod) { p.Status.Phase = core.PodRunning }, false},
		{"container-live", func(_ *value.AcquisitionWorker, _ *batch.Job, p *core.Pod) {
			p.Status.ContainerStatuses[0].State.Terminated = nil
		}, false},
		{"unknown-container", func(_ *value.AcquisitionWorker, _ *batch.Job, p *core.Pod) {
			p.Status.ContainerStatuses[0].State.Terminated.Reason = "ContainerStatusUnknown"
		}, false},
		{"lost-node", func(_ *value.AcquisitionWorker, _ *batch.Job, p *core.Pod) {
			p.Status.ContainerStatuses[0].State.Terminated.Reason = "NodeLost"
		}, false},
		{"missing-container-id", func(_ *value.AcquisitionWorker, _ *batch.Job, p *core.Pod) {
			p.Status.ContainerStatuses[0].State.Terminated.ContainerID = ""
		}, false},
		{"future-finish", func(_ *value.AcquisitionWorker, _ *batch.Job, p *core.Pod) {
			p.Status.ContainerStatuses[0].State.Terminated.FinishedAt = meta.NewTime(now.Add(time.Nanosecond))
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual, j, p := w, job.DeepCopy(), pod.DeepCopy()
			tc.edit(&actual, j, p)
			if got := installedProjectionWorkerTerminal(actual, j, p, now); got != tc.want {
				t.Fatal("terminal observation", got, tc.want)
			}
		})
	}
	if installedProjectionWorkerTerminal(w, nil, pod, now) || installedProjectionWorkerTerminal(w, job, nil, now) {
		t.Fatal("absence substituted for positive termination")
	}
	// native90: activeDeadlineSeconds killed the worker and the Job controller
	// deleted its Pod. Only the exact Job's accounted terminal record counts.
	killed := job.DeepCopy()
	killed.Status = batch.JobStatus{Failed: 1, Ready: ptr.To[int32](0), Conditions: []batch.JobCondition{{Type: batch.JobFailed, Status: core.ConditionTrue, Reason: batch.JobReasonDeadlineExceeded}}}
	if !installedProjectionWorkerTerminal(w, killed, nil, now) {
		t.Fatal("deadline-killed Job with removed Pod not terminal")
	}
	active := killed.DeepCopy()
	active.Status.Active = 1
	replaced := killed.DeepCopy()
	replaced.UID = "replacement"
	if installedProjectionWorkerTerminal(w, active, nil, now) || installedProjectionWorkerTerminal(w, replaced, nil, now) || installedProjectionWorkerTerminal(value.AcquisitionWorker{Intent: value.AcquisitionWorkerIntent{RunUntil: now.Add(time.Second)}, Binding: w.Binding}, killed, nil, now) {
		t.Fatal("active, replaced or live Job accepted with absent Pod")
	}
}

func TestInstalledApprovedScopeSelection(t *testing.T) {
	for _, tc := range []struct {
		scope string
		want  bool
	}{
		{"openid evidence:read", true}, {"evidence:read evidence:download", false}, {"evidence:read evidence:capture", false}, {"openid", false}, {"evidence:read-other", false},
	} {
		if got := installedApprovedScopes(tc.scope); got != tc.want {
			t.Fatal(tc.scope, got)
		}
	}
}
func TestInstalledProjectionPollsStayWithinOneOriginalLifetime(t *testing.T) {
	start := time.Now()
	until := start.Add(time.Minute)
	for poll := 0; poll < 4; poll++ {
		now := start.Add(time.Duration(poll) * 12 * time.Second)
		next, err := installedProjectionPollTime(start, until, now, time.Second, poll)
		if err != nil || !next.Equal(start.Add(time.Duration(poll+1)*12*time.Second)) {
			t.Fatal("cold startup poll spacing", poll, next, err)
		}
	}
	for _, tc := range []struct {
		name  string
		now   time.Time
		retry time.Duration
		poll  int
	}{
		{"expired", until, time.Second, 0}, {"too-late", until.Add(-time.Second), time.Second, 3}, {"exhausted", start, time.Second, 4}, {"clock-rollback", start.Add(-time.Nanosecond), time.Second, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := installedProjectionPollTime(start, until, tc.now, tc.retry, tc.poll); err == nil {
				t.Fatal("invalid poll renewed query or spent another slot")
			}
		})
	}
	now := start.Add(20 * time.Second)
	next, err := installedProjectionPollTime(start, until, now, 3*time.Second, 0)
	if err != nil || !next.Equal(now.Add(3*time.Second)) {
		t.Fatal("server not-before was ignored")
	}
}
