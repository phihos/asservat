package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
)

func initialBootstrapRunnerFixture(t *testing.T) (InitialBootstrapRunnerPlan, *core.ConfigMap, *core.Pod) {
	t.Helper()
	input := contracts.InitialBootstrapInput{Format: contracts.InitialBootstrapInputFormat, Name: "install", BootstrapNamespace: "trusted-bootstrap", TargetNamespace: "asservat", RunnerAccount: "install-bootstrap-runner", Image: initialWorkloadPlan().Image}
	refs := contracts.InitialBootstrapRunnerInput{Format: contracts.InitialBootstrapRunnerInputFormat, ProducerSecret: "operator-producer", SchemaSecret: "operator-schema", RetirementSecret: "operator-retirement"}
	a, _ := json.Marshal(input)
	b, _ := json.Marshal(refs)
	sum := sha256.Sum256(append(append(append([]byte{}, a...), '\n'), b...))
	p := InitialBootstrapRunnerPlan{Namespace: input.BootstrapNamespace, Name: input.Name, Image: input.Image, InputDigest: hex.EncodeToString(sum[:]), ProducerSecret: refs.ProducerSecret, SchemaSecret: refs.SchemaSecret, RetirementSecret: refs.RetirementSecret}
	cm := &core.ConfigMap{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "ConfigMap"}, ObjectMeta: meta.ObjectMeta{Name: initialBootstrapRunnerInputName(p.Name, p.InputDigest), Namespace: p.Namespace, UID: types.UID(ownerID(1)), ResourceVersion: "1"}, Immutable: ptr.To(true), Data: map[string]string{"bootstrap.json": string(a), "runner.json": string(b)}}
	pod, err := BuildInitialBootstrapRunner(p)
	if err != nil {
		t.Fatal(err)
	}
	pod.UID = types.UID(ownerID(2))
	pod.ResourceVersion = "2"
	pod.Spec.NodeName = "node-original"
	pod.Status.Phase = core.PodSucceeded
	started, finished := meta.NewTime(time.Now().Add(-2*time.Minute)), meta.NewTime(time.Now().Add(-time.Minute))
	status := func(name string) core.ContainerStatus {
		id := "containerd://" + name
		return core.ContainerStatus{Name: name, Image: p.Image, ImageID: p.Image, ContainerID: id, State: core.ContainerState{Terminated: &core.ContainerStateTerminated{ContainerID: id, StartedAt: started, FinishedAt: finished, ExitCode: 0}}}
	}
	for _, name := range []string{"produce", "schema", "prepare"} {
		pod.Status.InitContainerStatuses = append(pod.Status.InitContainerStatuses, status(name))
	}
	pod.Status.ContainerStatuses = []core.ContainerStatus{status("retire")}
	return p, cm, pod
}

func TestInitialBootstrapRunnerResumeRequiresEveryActualProcessToHaveEnded(t *testing.T) {
	p, _, original := initialBootstrapRunnerFixture(t)
	want, _ := BuildInitialBootstrapRunner(p)
	if err := initialBootstrapRunnerTerminal(original, want, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"", "containerd://", "docker://"} {
		current := original.DeepCopy()
		current.Status.ContainerStatuses[0].ImageID = prefix + strings.Split(p.Image, "@")[1]
		if initialBootstrapRunnerTerminal(current, want, time.Now()) != nil {
			t.Fatal("actual supported digest identity was rejected", prefix)
		}
	}
	failed := original.DeepCopy()
	failed.Status.Phase = core.PodFailed
	failed.Status.InitContainerStatuses = failed.Status.InitContainerStatuses[:1]
	failed.Status.InitContainerStatuses[0].State.Terminated.ExitCode = 1
	failed.Status.ContainerStatuses = nil
	if err := initialBootstrapRunnerTerminal(failed, want, time.Now()); err != nil {
		t.Fatal("known first-phase exit required invented later completion", err)
	}
	for label, edit := range map[string]func(*core.Pod){
		"running":              func(p *core.Pod) { p.Status.Phase = core.PodRunning },
		"node-lost":            func(p *core.Pod) { p.Status.Reason = "NodeLost"; p.Status.Phase = core.PodFailed },
		"missing-first-status": func(p *core.Pod) { p.Status.InitContainerStatuses = p.Status.InitContainerStatuses[1:] },
		"restart":              func(p *core.Pod) { p.Status.InitContainerStatuses[0].RestartCount = 1 },
		"unknown-end":          func(p *core.Pod) { p.Status.ContainerStatuses[0].State.Terminated.FinishedAt = meta.Time{} },
		"future-end": func(p *core.Pod) {
			p.Status.ContainerStatuses[0].State.Terminated.FinishedAt = meta.NewTime(time.Now().Add(time.Hour))
		},
		"wrong-image": func(p *core.Pod) {
			p.Status.ContainerStatuses[0].ImageID = "registry.invalid/replacement@sha256:" + strings.Repeat("b", 64)
		},
		"wrong-status-category": func(p *core.Pod) {
			p.Status.InitContainerStatuses[0], p.Status.ContainerStatuses[0] = p.Status.ContainerStatuses[0], p.Status.InitContainerStatuses[0]
		},
		"different-command": func(p *core.Pod) { p.Spec.Containers[0].Command = []string{"/bin/sh"} },
		"different-source":  func(p *core.Pod) { p.Annotations[InitialBootstrapRunnerInputAnnotation] = strings.Repeat("b", 64) },
		"extra-mount": func(p *core.Pod) {
			p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, core.VolumeMount{Name: "x", MountPath: "/tmp"})
		},
		"extra-pull-secret": func(p *core.Pod) { p.Spec.ImagePullSecrets = []core.LocalObjectReference{{Name: "foreign"}} },
		"half-deleted":      func(p *core.Pod) { p.DeletionTimestamp = &meta.Time{Time: time.Now()} },
		"unexpected-owner":  func(p *core.Pod) { p.OwnerReferences = []meta.OwnerReference{{UID: types.UID(ownerID(99))}} },
	} {
		t.Run(label, func(t *testing.T) {
			next := original.DeepCopy()
			edit(next)
			if initialBootstrapRunnerTerminal(next, want, time.Now()) == nil {
				t.Fatal("unknown/changed process was replaceable")
			}
		})
	}
}

func TestInitialBootstrapRunnerResumeOnlyDeletesExactTerminalCAS(t *testing.T) {
	for _, mode := range []string{"terminal", "active", "absent", "changed-input", "lost-delete-reply", "canceled-final-read", "changed-original-bytes", "missing-original", "latest-only"} {
		t.Run(mode, func(t *testing.T) {
			plan, cm, pod := initialBootstrapRunnerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			inputReads, deletes, secretReads := 0, 0, 0
			removed := mode == "absent"
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/secrets/") {
					secretReads++
					http.Error(w, "denied", 403)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/configmaps/"+cm.Name) {
					inputReads++
					if mode == "missing-original" || mode == "latest-only" {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusNotFound)
						permissionReply(w, &meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Reason: meta.StatusReasonNotFound, Code: 404})
						return
					}
					if mode == "changed-original-bytes" {
						cm = cm.DeepCopy()
						cm.Data["bootstrap.json"] += " "
					}
					if inputReads == 2 && mode == "changed-input" {
						cm = cm.DeepCopy()
						cm.ResourceVersion = "3"
					}
					if inputReads == 2 && mode == "canceled-final-read" {
						cancel()
					}
					permissionReply(w, cm)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/pods/"+pod.Name) {
					if r.Method == http.MethodDelete {
						deletes++
						var body meta.DeleteOptions
						if json.NewDecoder(r.Body).Decode(&body) != nil || body.Preconditions == nil || body.Preconditions.UID == nil || *body.Preconditions.UID != pod.UID || body.Preconditions.ResourceVersion == nil || *body.Preconditions.ResourceVersion != pod.ResourceVersion {
							t.Error("delete omitted exact original UID/RV")
						}
						if mode == "lost-delete-reply" {
							http.Error(w, "unavailable", 503)
							return
						}
						removed = true
						permissionReply(w, &meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Success"})
						return
					}
					if removed {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(http.StatusNotFound)
						permissionReply(w, &meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Reason: meta.StatusReasonNotFound, Code: 404})
						return
					}
					if mode == "active" {
						pod.Status.Phase = core.PodRunning
					}
					permissionReply(w, pod)
					return
				}
				http.Error(w, "unexpected", 400)
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			result, err := ResumeInitialBootstrapRunner(ctx, &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: ca}}, plan.Namespace, plan.Name)
			if mode == "terminal" {
				if err != nil || result.RemovedUID != string(pod.UID) || deletes != 1 {
					t.Fatal("exact terminal deletion failed", err)
				}
			} else if mode == "absent" {
				if err != nil || !result.Absent || deletes != 0 || inputReads != 0 {
					t.Fatal("absence acquired effect authority", err)
				}
			} else if err == nil {
				t.Fatal("unknown state reported resumable")
			}
			if secretReads != 0 || mode != "terminal" && mode != "lost-delete-reply" && deletes != 0 {
				t.Fatal("resume read setup material or deleted unproven runner")
			}
		})
	}
}

func TestInitialBootstrapRunnerHasOnlyFiniteSeparatedInputCompartments(t *testing.T) {
	p, _, _ := initialBootstrapRunnerFixture(t)
	p.RegistrySecret = "original-pull"
	pod, err := BuildInitialBootstrapRunner(p)
	if err != nil {
		t.Fatal(err)
	}
	if pod.Spec.RestartPolicy != core.RestartPolicyNever || len(pod.Spec.InitContainers) != 3 || len(pod.Spec.Containers) != 1 || pod.Annotations["helm.sh/hook-delete-policy"] != "hook-succeeded" {
		t.Fatal("runner replaced original fixed chain")
	}
	for _, volume := range pod.Spec.Volumes {
		if volume.Secret != nil && (volume.Name != "ddl-input" || volume.Secret.Optional == nil || !*volume.Secret.Optional || len(volume.Secret.Items) != 1 || volume.Secret.Items[0].Key != "postgres-ddl.json") {
			t.Fatal("schema mount broadened or prevents passive start")
		}
		if volume.Projected != nil {
			if volume.Projected.Sources[0].ConfigMap == nil || volume.Projected.Sources[0].ConfigMap.Name != initialBootstrapRunnerInputName(p.Name, p.InputDigest) {
				t.Fatal("runner does not retain original revision-named public snapshot")
			}
			for _, source := range volume.Projected.Sources {
				if source.Secret != nil && (source.Secret.Optional == nil || !*source.Secret.Optional) {
					t.Fatal("setup input blocks credential-free replay")
				}
				if volume.Name == "retirement-input" && source.Secret != nil && source.Secret.Name == p.RegistrySecret {
					t.Fatal("registry file entered retirement")
				}
			}
		}
	}
	a, _ := json.Marshal(pod.Spec.InitContainers[1].VolumeMounts)
	if bytes.Contains(a, []byte("producer-input")) || bytes.Contains(a, []byte("retirement-input")) {
		t.Fatal("schema sees setup/provider compartment")
	}
}
