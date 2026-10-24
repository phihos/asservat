package kubernetes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	batch "k8s.io/api/batch/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// This is a frozen compatibility oracle from 98f7e181, before ADR219. It is
// intentionally not updated when the shared builder changes: original admitted
// Jobs retain exact specification digests for live identity and retirement.
func originalDownloadJob219(i value.DownloadWorkerIntent) *batch.Job {
	p := i.Profile
	no, yes := false, true
	uid, grace, tokenLife, mode := int64(65532), int64(5), int64(600), int32(0440)
	zero, one := int32(0), int32(1)
	duration := int64(i.RunUntil.Sub(i.CreatedAt) / time.Second)
	completion, replacement, preempt := batch.NonIndexedCompletion, batch.Failed, core.PreemptNever
	cpu, mem := *resource.NewMilliQuantity(p.CPUMillis, resource.DecimalSI), *resource.NewQuantity(p.MemoryBytes, resource.BinarySI)
	resources := core.ResourceList{core.ResourceCPU: cpu, core.ResourceMemory: mem, core.ResourceEphemeralStorage: resource.MustParse("4Mi")}
	labels := map[string]string{"asservat.io/download-worker": i.ID}
	pod := core.PodSpec{
		PriorityClassName:  p.PriorityClass,
		ServiceAccountName: p.ServiceAccount, DeprecatedServiceAccount: p.ServiceAccount, AutomountServiceAccountToken: &no,
		RestartPolicy: core.RestartPolicyNever, TerminationGracePeriodSeconds: &grace, DNSPolicy: core.DNSClusterFirst, SchedulerName: core.DefaultSchedulerName, EnableServiceLinks: &no, PreemptionPolicy: &preempt,
		SecurityContext: &core.PodSecurityContext{RunAsNonRoot: &yes, RunAsUser: &uid, RunAsGroup: &uid, FSGroup: &uid, SeccompProfile: &core.SeccompProfile{Type: core.SeccompProfileTypeRuntimeDefault}},
		Volumes: []core.Volume{
			{Name: "identity", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{DefaultMode: &mode, Sources: []core.VolumeProjection{{ServiceAccountToken: &core.ServiceAccountTokenProjection{Audience: DownloadPeerAudience(p.InstallationID), ExpirationSeconds: &tokenLife, Path: "token"}}}}}},
			{Name: "control", VolumeSource: core.VolumeSource{ConfigMap: &core.ConfigMapVolumeSource{LocalObjectReference: core.LocalObjectReference{Name: p.ControlConfig}, DefaultMode: &mode}}},
		},
		Containers: []core.Container{{Name: "acquisition", Image: p.Image, ImagePullPolicy: core.PullIfNotPresent,
			Command: []string{"/asservat"}, Args: []string{"download-worker", "--installation", p.InstallationID, "--cluster", p.ClusterID, "--dispatch", i.ID, "--session", i.SessionID, "--created-at", i.CreatedAt.UTC().Format(time.RFC3339Nano), "--until", i.RunUntil.UTC().Format(time.RFC3339Nano), "--control-sha256", fmt.Sprintf("%x", p.ControlDigest), "--control", contracts.WorkerControlPath, "--token", DownloadWorkerTokenPath},
			Env:                    []core.EnvVar{{Name: contracts.WorkerPodUIDEnvironment, ValueFrom: &core.EnvVarSource{FieldRef: &core.ObjectFieldSelector{APIVersion: "v1", FieldPath: "metadata.uid"}}}},
			TerminationMessagePath: core.TerminationMessagePathDefault, TerminationMessagePolicy: core.TerminationMessageReadFile,
			Resources:       core.ResourceRequirements{Requests: resources, Limits: resources},
			SecurityContext: &core.SecurityContext{AllowPrivilegeEscalation: &no, ReadOnlyRootFilesystem: &yes, Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}},
			VolumeMounts:    []core.VolumeMount{{Name: "identity", MountPath: "/run/asservat/identity", ReadOnly: true}, {Name: "control", MountPath: "/run/asservat/control", ReadOnly: true}},
		}},
	}
	for _, name := range p.ImagePullSecrets {
		if name != "" {
			pod.ImagePullSecrets = append(pod.ImagePullSecrets, core.LocalObjectReference{Name: name})
		}
	}
	if p.StoreCredentialSecret != "" {
		pod.Volumes = append(pod.Volumes, core.Volume{Name: "native-store", VolumeSource: core.VolumeSource{Secret: &core.SecretVolumeSource{SecretName: p.StoreCredentialSecret, DefaultMode: &mode, Optional: &no, Items: []core.KeyToPath{{Key: "credentials.json", Path: "credentials.json"}}}}})
		pod.Containers[0].VolumeMounts = append(pod.Containers[0].VolumeMounts, core.VolumeMount{Name: "native-store", MountPath: "/run/asservat/native-store", ReadOnly: true})
	}
	return &batch.Job{TypeMeta: meta.TypeMeta{APIVersion: "batch/v1", Kind: "Job"}, ObjectMeta: meta.ObjectMeta{Name: i.JobName(), Namespace: p.Namespace, Labels: labels}, Spec: batch.JobSpec{Parallelism: &one, Completions: &one, BackoffLimit: &zero, ActiveDeadlineSeconds: &duration, CompletionMode: &completion, PodReplacementPolicy: &replacement, Suspend: &no, ManualSelector: &yes, Selector: &meta.LabelSelector{MatchLabels: labels}, Template: core.PodTemplateSpec{ObjectMeta: meta.ObjectMeta{Labels: labels}, Spec: pod}}}
}

func TestSharedAcquisitionPreservesOriginalDownloadJobBytes(t *testing.T) {
	now := time.Date(2026, 10, 23, 10, 0, 0, 123456000, time.UTC)
	id := "10000000-0000-4000-8000-000000000001"
	p := value.DownloadWorkerProfile{InstallationID: id, ClusterID: id, Namespace: "workers", ServiceAccount: "acquisition", Image: "synthetic.invalid/worker@sha256:" + strings.Repeat("1", 64), ControlConfig: "control", ControlDigest: artifact.Digest{3}, PriorityClass: "workers", CPUMillis: 100, MemoryBytes: 64 << 20}
	for _, native := range []bool{false, true} {
		if native {
			p.StoreCredentialSecret = "native-store"
			p.StoreCredentialSecretUID = id
			p.ImagePullSecrets[0] = "registry-pull"
		}
		intent := value.DownloadWorkerIntent{ID: id, SessionID: id, Profile: p, CreatedAt: now, RunUntil: now.Add(time.Minute)}
		before, err := json.Marshal(originalDownloadJob219(intent))
		if err != nil {
			t.Fatal(err)
		}
		after, err := json.Marshal(workerJob(intent))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("original Job bytes changed", native, err)
		}
		oldDigest, err := WorkerSpecDigest("Job", specBytes(before))
		if err != nil {
			t.Fatal(err)
		}
		newDigest, err := WorkerSpecDigest("Job", specBytes(after))
		if err != nil || oldDigest != newDigest {
			t.Fatal("original Job digest changed", native, err)
		}
	}
}

func TestSharedAcquisitionRejectsUnknownPurposeBeforeJobConstruction(t *testing.T) {
	for _, purpose := range []value.AcquisitionPurpose{"", "query", "arbitrary-query", "native-download/extra"} {
		if job := acquisitionJob(value.AcquisitionWorkerIntent{Parent: value.AcquisitionParent{Purpose: purpose, ID: "10000000-0000-4000-8000-000000000001"}}); job != nil {
			t.Fatal("unknown parent selected a Job template", purpose)
		}
	}
}
