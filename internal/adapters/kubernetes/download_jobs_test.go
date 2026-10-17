package kubernetes

import (
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"encoding/json"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"strings"
	"testing"
	"time"
)

func TestDownloadWorkerRejectsInjectedExecution(t *testing.T) {
	p := value.DownloadWorkerProfile{Namespace: "workers", ServiceAccount: "acquisition", Image: "example.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "control", CPUMillis: 100, MemoryBytes: 64 << 20}
	i := value.DownloadWorkerIntent{ID: "11111111-1111-4111-8111-111111111111", SessionID: "22222222-2222-4222-8222-222222222222", Profile: p, CreatedAt: time.Now().UTC(), RunUntil: time.Now().UTC().Add(time.Minute)}
	for _, mode := range []string{"valid", "valid-listed", "wrong-kind", "image", "command", "env", "pod-uid", "original-start", "control-digest", "sidecar", "init", "privileged", "host", "token-audience", "volume", "service-account", "owner", "priority-class", "preemption", "unknown-spec"} {
		t.Run(mode, func(t *testing.T) {
			job := workerJob(i)
			job.UID = "job-uid"
			job.ResourceVersion = "1"
			b, _ := json.Marshal(job)
			driver := &DownloadWorkerJobs{profile: p}
			_, receipt, e := driver.checkedJob(i, b)
			if e != nil {
				t.Fatal("base Job shape", e)
			}
			yes := true
			pod := core.Pod{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: meta.ObjectMeta{Name: "worker", Namespace: p.Namespace, UID: types.UID("33333333-3333-4333-8333-333333333333"), Labels: job.Spec.Template.Labels, OwnerReferences: []meta.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: job.Name, UID: job.UID, Controller: &yes}}}, Spec: *job.Spec.Template.Spec.DeepCopy()}
			pod.Spec.NodeName = "worker-node"
			switch mode {
			case "valid-listed":
				// PodList items omit the per-item TypeMeta on the wire.
				pod.TypeMeta = meta.TypeMeta{}
			case "wrong-kind":
				pod.Kind = "Node"
			case "priority-class":
				pod.Spec.PriorityClassName = "system-cluster-critical"
			case "preemption":
				policy := core.PreemptLowerPriority
				pod.Spec.PreemptionPolicy = &policy
			case "image":
				pod.Spec.Containers[0].Image = "example.invalid/untrusted:latest"
			case "command":
				pod.Spec.Containers[0].Command = []string{"/bin/sh"}
			case "env":
				pod.Spec.Containers[0].Env = []core.EnvVar{{Name: "LD_PRELOAD", Value: "untrusted"}}
			case "pod-uid":
				pod.Spec.Containers[0].Env[0].ValueFrom.FieldRef.FieldPath = "metadata.name"
			case "original-start":
				pod.Spec.Containers[0].Args[10] = "2099-01-01T00:00:00Z"
			case "control-digest":
				pod.Spec.Containers[0].Args[14] = strings.Repeat("2", 64)
			case "sidecar":
				pod.Spec.Containers = append(pod.Spec.Containers, pod.Spec.Containers[0])
			case "init":
				pod.Spec.InitContainers = append(pod.Spec.InitContainers, pod.Spec.Containers[0])
			case "privileged":
				pod.Spec.Containers[0].SecurityContext.Privileged = &yes
			case "host":
				pod.Spec.HostNetwork = true
			case "token-audience":
				pod.Spec.Volumes[0].Projected.Sources[0].ServiceAccountToken.Audience = "https://kubernetes.default.svc"
			case "volume":
				pod.Spec.Volumes = append(pod.Spec.Volumes, core.Volume{Name: "root-key", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: "private"}}})
			case "service-account":
				pod.Spec.ServiceAccountName = "administrator"
			case "owner":
				pod.OwnerReferences[0].UID = "other-job"
			}
			b, _ = json.Marshal(pod)
			if mode == "unknown-spec" {
				var raw map[string]any
				_ = json.Unmarshal(b, &raw)
				raw["spec"].(map[string]any)["futureUnsafeField"] = true
				b, _ = json.Marshal(raw)
			}
			_, d, e := checkedWorkerPod(i, receipt, b)
			if mode == "valid" || mode == "valid-listed" {
				if e != nil || d == (artifact.Digest{}) {
					t.Fatal("valid worker", e)
				}
			} else if e == nil {
				t.Fatal("injected execution accepted")
			}
		})
	}
}
