package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func activationPreparerFixture(t *testing.T) (*preparerFixture, *InitialPreparer) {
	t.Helper()
	plan := preparerTestPlan()
	plan.Continuation = contracts.InitialPreparationActivationProtocol
	f := newPreparerFixturePlan(t, "", plan)
	p := f.preparer(t)
	if _, e := p.Declare(context.Background()); e != nil {
		t.Fatal(e)
	}
	return f, p
}
func TestInitialPreparationGatedPodKnownUIDNeverCreatesReplacement(t *testing.T) {
	for _, mode := range []string{"valid", "missing", "replacement", "changed-image", "ungated", "scheduled"} {
		t.Run(mode, func(t *testing.T) {
			f, p := activationPreparerFixture(t)
			first, e := p.PrepareGatedPod(context.Background())
			if e != nil || first.Activation == nil || first.Activation.Pod.Receipt == nil {
				t.Fatal("gated preparation", e)
			}
			path := "/api/v1/namespaces/initial-target/pods/initial"
			f.mu.Lock()
			before := f.posts[path]
			pod := f.objects[path]
			switch mode {
			case "missing":
				delete(f.objects, path)
			case "replacement":
				pod["metadata"].(map[string]any)["uid"] = ownerID(90)
			case "changed-image":
				pod["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)["image"] = "example.invalid/other:latest"
			case "ungated":
				delete(pod["spec"].(map[string]any), "schedulingGates")
			case "scheduled":
				pod["spec"].(map[string]any)["nodeName"] = "node-a"
			}
			f.mu.Unlock()
			replay, e := p.PrepareGatedPod(context.Background())
			if mode == "valid" {
				if e != nil || !equalJSON(first.Activation, replay.Activation) {
					t.Fatal("original receipt changed", e)
				}
			} else if e == nil {
				t.Fatal("missing/changed Pod accepted")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.posts[path] != before {
				t.Fatal("recorded Pod recreated")
			}
		})
	}
	f := newPreparerFixture(t, "")
	p := f.preparer(t)
	if _, e := p.Declare(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e := p.PrepareGatedPod(context.Background()); e == nil {
		t.Fatal("old declaration acquired Pod create authority")
	}
}

type prepActivationRoundTrip func(*http.Request) (*http.Response, error)

func (f prepActivationRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestInitialPreparationGatedPodPendingCreateKeepsOriginalIntent(t *testing.T) {
	f, _ := activationPreparerFixture(t)
	var original []byte
	first := true
	f.client.WrapTransport = func(next http.RoundTripper) http.RoundTripper {
		return prepActivationRoundTrip(func(r *http.Request) (*http.Response, error) {
			if r.Method == "POST" && r.URL.Path == "/api/v1/namespaces/initial-target/pods" && first {
				first = false
				original, _ = io.ReadAll(r.Body)
				b, _ := json.Marshal(meta.Status{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: meta.StatusFailure, Reason: meta.StatusReasonServiceUnavailable, Code: 503})
				return &http.Response{StatusCode: 503, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(b)), Request: r}, nil
			}
			return next.RoundTrip(r)
		})
	}
	p := f.preparer(t)
	if _, e := p.PrepareGatedPod(context.Background()); e == nil {
		t.Fatal("unknown first CREATE became success")
	}
	_, pending, e := p.read(context.Background())
	if e != nil || pending.Activation == nil || pending.Activation.Pod.Receipt != nil {
		t.Fatal("pending intent lost", e)
	}
	winner, e := p.PrepareGatedPod(context.Background())
	if e != nil || winner.Activation.Pod.OperationID != pending.Activation.Pod.OperationID || winner.Activation.Pod.Receipt == nil {
		t.Fatal("retry changed original intent", e)
	}
	req, e := http.NewRequest("POST", f.server.URL+"/api/v1/namespaces/initial-target/pods", bytes.NewReader(original))
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Authorization", "Bearer operator")
	req.Header.Set("Content-Type", "application/json")
	response, e := f.server.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.StatusCode != 409 {
		t.Fatal("late same-key CREATE did not remain occupied", response.StatusCode)
	}
	again, e := p.PrepareGatedPod(context.Background())
	if e != nil || !equalJSON(again.Activation, winner.Activation) {
		t.Fatal("late CREATE changed winner", e)
	}
}

func TestInitialPreparationRejectsExecutablePodInjection(t *testing.T) {
	f, p := activationPreparerFixture(t)
	for _, mode := range []string{"compiled", "known-defaults", "sidecar", "init", "ephemeral", "volume", "hostnetwork", "token-audience", "scheduled", "running", "started", "toleration", "image", "owner"} {
		t.Run(mode, func(t *testing.T) {
			w, _ := BuildInitialInstallerWorkload(preparerWorkload(f.plan))
			pod := w.Pod
			pod.UID = types.UID(ownerID(80))
			pod.ResourceVersion = "2"
			p.creator.stamp(&pod.ObjectMeta)
			pod.Annotations[initialPreparationOperationAnnotation] = ownerID(81)
			switch mode {
			case "known-defaults":
				pod.Spec.DNSPolicy = core.DNSClusterFirst
				pod.Spec.SchedulerName = "default-scheduler"
				pod.Spec.DeprecatedServiceAccount = pod.Spec.ServiceAccountName
				pod.Spec.Priority = ptr.To(int32(0))
				pod.Spec.PreemptionPolicy = ptr.To(core.PreemptLowerPriority)
				pod.Spec.Tolerations = []core.Toleration{{Key: "node.kubernetes.io/not-ready", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))}, {Key: "node.kubernetes.io/unreachable", Operator: core.TolerationOpExists, Effect: core.TaintEffectNoExecute, TolerationSeconds: ptr.To(int64(300))}}
				pod.Spec.Containers[0].TerminationMessagePath = core.TerminationMessagePathDefault
				pod.Spec.Containers[0].TerminationMessagePolicy = core.TerminationMessageReadFile
			case "sidecar":
				pod.Spec.Containers = append(pod.Spec.Containers, core.Container{Name: "extra", Image: "evil"})
			case "init":
				pod.Spec.InitContainers = []core.Container{{Name: "extra", Image: "evil"}}
			case "ephemeral":
				pod.Spec.EphemeralContainers = []core.EphemeralContainer{{EphemeralContainerCommon: core.EphemeralContainerCommon{Name: "extra", Image: "evil"}}}
			case "volume":
				pod.Spec.Volumes = append(pod.Spec.Volumes, core.Volume{Name: "extra"})
			case "hostnetwork":
				pod.Spec.HostNetwork = true
			case "token-audience":
				pod.Spec.Volumes[0].Projected.Sources[2].ServiceAccountToken.Audience = "unreviewed"
			case "scheduled":
				pod.Spec.NodeName = "node-a"
			case "running":
				pod.Status.Phase = core.PodRunning
			case "started":
				n := meta.NewTime(time.Now())
				pod.Status.StartTime = &n
			case "toleration":
				pod.Spec.Tolerations = []core.Toleration{{Operator: core.TolerationOpExists}}
			case "image":
				pod.Spec.Containers[0].Image = "evil:latest"
			case "owner":
				pod.OwnerReferences = []meta.OwnerReference{{APIVersion: "batch/v1", Kind: "Job", Name: "replacement", UID: types.UID(ownerID(90))}}
			}
			raw, _ := json.Marshal(pod)
			receipt, digest, e := p.verifiedGatedPod(raw, contracts.InitialPreparationPod{OperationID: ownerID(81)})
			want := mode == "compiled" || mode == "known-defaults"
			if (e == nil) != want || want && (receipt.UID != string(pod.UID) || !preparationDigestValid(digest)) {
				t.Fatal("inert specification qualification", e)
			}
		})
	}
}
