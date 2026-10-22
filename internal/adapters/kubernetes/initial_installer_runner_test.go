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

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

func TestInitialInstallerRunnerSharesProjectionWithoutSharingPhaseCredentials(t *testing.T) {
	p, _, combined, continuation := initialInstallerRunnerFixture(t, true)
	bootstrap := p
	bootstrap.ContinuationDigest = ""
	original, err := BuildInitialBootstrapRunner(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if len(combined.Spec.InitContainers) != 4 || len(combined.Spec.Containers) != 1 || combined.Spec.ActiveDeadlineSeconds == nil || *combined.Spec.ActiveDeadlineSeconds != 1800 || combined.Annotations["asservat.io/bootstrap-runner"] != InitialInstallerRunnerProfile {
		t.Fatal("installer is not one fixed five-command runner with the original outer deadline")
	}
	previous := append(append([]core.Container{}, original.Spec.InitContainers...), original.Spec.Containers...)
	for i := range previous {
		if !equalJSON(previous[i], combined.Spec.InitContainers[i]) {
			t.Fatalf("phase %s gained credentials or changed its command", previous[i].Name)
		}
	}
	last := combined.Spec.Containers[0]
	if last.Name != "continue" || !equalJSON(last.Command, []string{"/asservat", "installer-continue"}) || !equalJSON(last.VolumeMounts, []core.VolumeMount{
		{Name: "scratch", MountPath: "/run/asservat/initial-preparer", SubPath: "projection/preparer", ReadOnly: true},
		{Name: "continuation-input", MountPath: "/run/asservat/installer-continue", ReadOnly: true},
	}) {
		t.Fatal("continuation can see an earlier phase's private compartment")
	}
	scratch, producer := 0, 0
	for _, c := range combined.Spec.InitContainers {
		if c.Command[1] == "initial-bootstrap" {
			producer++
		}
	}
	for i, v := range combined.Spec.Volumes {
		if v.EmptyDir != nil {
			scratch++
		}
		if i < len(original.Spec.Volumes) && !equalJSON(v, original.Spec.Volumes[i]) {
			t.Fatal("earlier volume changed", v.Name)
		}
		if v.Name != "continuation-input" {
			continue
		}
		if v.Projected == nil || len(v.Projected.Sources) != 3 || v.Projected.DefaultMode == nil || *v.Projected.DefaultMode != 0440 {
			t.Fatal("continuation projection broadened")
		}
		sources := v.Projected.Sources
		if sources[0].ConfigMap == nil || sources[0].ConfigMap.Name != continuation.Name || !equalJSON(sources[0].ConfigMap.Items, []core.KeyToPath{{Key: "continuation.json", Path: "continuation.json"}}) {
			t.Fatal("continuation does not use its original public snapshot")
		}
		if sources[1].ServiceAccountToken == nil || sources[1].ServiceAccountToken.ExpirationSeconds == nil || *sources[1].ServiceAccountToken.ExpirationSeconds != 600 || sources[1].ServiceAccountToken.Path != "administrator-token" {
			t.Fatal("continuation lost its own rotating token")
		}
		if sources[2].Secret == nil || sources[2].Secret.Name != p.ProducerSecret || !equalJSON(sources[2].Secret.Items, []core.KeyToPath{{Key: "postgres-administrator.json", Path: "postgres-administrator.json"}}) {
			t.Fatal("provider, registry or DDL credentials entered continuation")
		}
	}
	if scratch != 1 || producer != 1 {
		t.Fatal("runner retained a duplicate producer or scratch volume", scratch, producer)
	}
	p.ContinuationDigest = strings.Repeat("a", 63)
	if _, err := BuildInitialBootstrapRunner(p); err == nil {
		t.Fatal("truncated continuation digest accepted")
	}
}

func TestInitialInstallerRunnerRequiresContinuationTermination(t *testing.T) {
	p, _, original, _ := initialInstallerRunnerFixture(t, true)
	want, _ := BuildInitialBootstrapRunner(p)
	if err := initialBootstrapRunnerTerminal(original, want, time.Now()); err != nil {
		t.Fatal(err)
	}
	for label, edit := range map[string]func(*core.Pod){
		"live-continuation": func(p *core.Pod) {
			p.Status.ContainerStatuses[0].State = core.ContainerState{Running: &core.ContainerStateRunning{}}
		},
		"missing-continuation": func(p *core.Pod) { p.Status.ContainerStatuses = nil },
		"missing-retirement":   func(p *core.Pod) { p.Status.InitContainerStatuses = p.Status.InitContainerStatuses[:3] },
		"retirement-in-main": func(p *core.Pod) {
			p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, p.Status.InitContainerStatuses[3])
		},
		"continuation-restarted":   func(p *core.Pod) { p.Status.ContainerStatuses[0].RestartCount = 1 },
		"unknown-continuation-end": func(p *core.Pod) { p.Status.ContainerStatuses[0].State.Terminated.FinishedAt = meta.Time{} },
		"node-lost":                func(p *core.Pod) { p.Status.Phase = core.PodFailed; p.Status.Reason = "NodeLost" },
	} {
		t.Run(label, func(t *testing.T) {
			pod := original.DeepCopy()
			edit(pod)
			if initialBootstrapRunnerTerminal(pod, want, time.Now()) == nil {
				t.Fatal("continuation may still own effects")
			}
		})
	}
	failed := original.DeepCopy()
	failed.Status.Phase = core.PodFailed
	failed.Status.InitContainerStatuses[3].State.Terminated.ExitCode = 1
	failed.Status.ContainerStatuses = nil
	if err := initialBootstrapRunnerTerminal(failed, want, time.Now()); err != nil {
		t.Fatal("failed retirement required an invented continuation receipt", err)
	}
}

func TestInitialInstallerRunnerResumeNeedsNoDownstreamContinuationRead(t *testing.T) {
	for _, mode := range []string{"missing-continuation", "unavailable-continuation", "changed-original-digest", "changed-projected-name", "changed-original-version", "canceled-final-read", "lost-delete-reply"} {
		t.Run(mode, func(t *testing.T) {
			plan, cm, pod, continuation := initialInstallerRunnerFixture(t, true)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			inputReads, downstreamReads, deletes, secrets := 0, 0, 0, 0
			removed := false
			if mode == "changed-projected-name" {
				pod.Spec.Volumes[len(pod.Spec.Volumes)-1].Projected.Sources[0].ConfigMap.Name = "replacement"
			}
			if mode == "changed-original-digest" {
				// The projected name retains the same first half; changing the full
				// digest still contradicts the original runner input annotation.
				changed := plan.ContinuationDigest[:32] + strings.Repeat("f", 32)
				cm.Data["runner.json"] = strings.Replace(cm.Data["runner.json"], plan.ContinuationDigest, changed, 1)
			}
			notFound := func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				permissionReply(w, &meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: "Failure", Reason: meta.StatusReasonNotFound, Code: 404})
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/secrets/"):
					secrets++
					http.Error(w, "denied", 403)
				case strings.HasSuffix(r.URL.Path, "/configmaps/"+cm.Name):
					inputReads++
					current := cm.DeepCopy()
					if inputReads == 2 {
						if mode == "changed-original-version" {
							current.ResourceVersion = "changed"
						}
						if mode == "canceled-final-read" {
							cancel()
						}
					}
					permissionReply(w, current)
				case strings.HasSuffix(r.URL.Path, "/configmaps/"+continuation.Name):
					downstreamReads++
					if mode == "missing-continuation" {
						notFound(w)
					} else {
						http.Error(w, "unavailable", 503)
					}
				case strings.HasSuffix(r.URL.Path, "/pods/"+pod.Name):
					if r.Method == http.MethodDelete {
						deletes++
						var body meta.DeleteOptions
						if json.NewDecoder(r.Body).Decode(&body) != nil || body.Preconditions == nil || body.Preconditions.UID == nil || *body.Preconditions.UID != pod.UID || body.Preconditions.ResourceVersion == nil || *body.Preconditions.ResourceVersion != pod.ResourceVersion {
							t.Error("delete omitted the original runner UID/RV")
						}
						if mode == "lost-delete-reply" {
							http.Error(w, "unavailable", 503)
							return
						}
						removed = true
						permissionReply(w, &meta.Status{Status: "Success"})
					} else if removed {
						notFound(w)
					} else {
						permissionReply(w, pod)
					}
				default:
					http.Error(w, "unexpected", 400)
				}
			}))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			got, err := ResumeInitialBootstrapRunner(ctx, &rest.Config{Host: server.URL, TLSClientConfig: rest.TLSClientConfig{CAData: ca}}, plan.Namespace, plan.Name)
			allowed := mode == "missing-continuation" || mode == "unavailable-continuation"
			if allowed {
				if err != nil || got.RemovedUID != string(pod.UID) || deletes != 1 || inputReads != 2 {
					t.Fatal("exact original terminal runner did not resume", got, err, inputReads, deletes)
				}
			} else if err == nil {
				t.Fatal("unproven runner reported resumable")
			}
			if secrets != 0 || downstreamReads != 0 || !allowed && mode != "lost-delete-reply" && deletes != 0 {
				t.Fatal("cleanup read downstream inputs or removed an unproven runner", secrets, downstreamReads, deletes)
			}
		})
	}
}
