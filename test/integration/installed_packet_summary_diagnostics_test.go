package integration

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// Failure-only operator read, under the caller's existing20s diagnostic bound.
// Existing installedPodDiagnostics captures bounded current/previous Pod logs;
// this adds the query Job's actual identity/status without args/env/inputs.
func installedPacketSummaryJobDiagnostics(ctx context.Context, api kubernetes.Interface, namespace string, logf func(string, ...any)) {
	jobs, err := api.BatchV1().Jobs(namespace).List(ctx, meta.ListOptions{LabelSelector: "asservat.io/query-worker", Limit: 16})
	if err != nil {
		logf("packet query Job diagnostics unavailable: %v", err)
		return
	}
	logf("packet query Job diagnostics: count=%d truncated=%t", len(jobs.Items), jobs.Continue != "")
	for _, job := range jobs.Items {
		deadline := "unknown"
		if job.Spec.ActiveDeadlineSeconds != nil {
			deadline = fmt.Sprint(*job.Spec.ActiveDeadlineSeconds)
		}
		logf("packet query Job: namespace=%s name=%s uid=%s worker=%s active=%d succeeded=%d failed=%d started=%v completed=%v deadline=%v", job.Namespace, job.Name, job.UID, job.Labels["asservat.io/query-worker"], job.Status.Active, job.Status.Succeeded, job.Status.Failed, job.Status.StartTime, job.Status.CompletionTime, deadline)
		for _, c := range job.Status.Conditions {
			logf("packet query Job condition: type=%s status=%s reason=%s", c.Type, c.Status, c.Reason)
		}
	}
}

// The operator report must contain real Job identity/status while excluding
// template credentials, work arguments and arbitrary condition-message text.
func TestInstalledPacketSummaryJobDiagnosticsExcludePrivateInputs(t *testing.T) {
	const secret = "synthetic-private-input-must-not-log"
	n := meta.NewTime(time.Now().UTC())
	deadline := int64(60)
	job := &batch.Job{ObjectMeta: meta.ObjectMeta{Name: "original-query", Namespace: "workers", UID: types.UID("original-job-uid"), Labels: map[string]string{"asservat.io/query-worker": "original-worker"}}, Spec: batch.JobSpec{ActiveDeadlineSeconds: &deadline, Template: core.PodTemplateSpec{Spec: core.PodSpec{Containers: []core.Container{{Name: "worker", Args: []string{secret}, Env: []core.EnvVar{{Name: "PRIVATE", Value: secret}}}}}}}, Status: batch.JobStatus{Active: 1, StartTime: &n, Conditions: []batch.JobCondition{{Type: batch.JobFailureTarget, Status: core.ConditionTrue, Reason: "DeadlineExceeded", Message: secret}}}}
	api := fake.NewClientset(job)
	var out strings.Builder
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	installedPacketSummaryJobDiagnostics(ctx, api, "workers", func(f string, a ...any) { fmt.Fprintf(&out, f+"\n", a...) })
	s := out.String()
	if !strings.Contains(s, "original-job-uid") || !strings.Contains(s, "original-worker") || !strings.Contains(s, "active=1") || !strings.Contains(s, "deadline=60") || !strings.Contains(s, "DeadlineExceeded") || strings.Contains(s, secret) {
		t.Fatal("diagnostic omitted status or disclosed private inputs", s)
	}
	actions := api.Actions()
	if len(actions) != 1 || actions[0].GetVerb() != "list" || actions[0].GetResource().Resource != "jobs" || actions[0].GetNamespace() != "workers" {
		t.Fatal("unexpected diagnostic operations", actions)
	}
}
