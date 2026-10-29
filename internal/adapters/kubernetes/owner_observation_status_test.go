package kubernetes

import (
	"testing"
	"time"

	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Actual HTTP/native readers; a deterministic synthetic API update, not a
// claim that every readiness probe writes Pod status or caused the Native run.
func TestOwnerObservationFinalPodStatusOnlyUpdate(t *testing.T) {
	for _, mode := range []string{"unchanged", "status-between-boundaries", "status-within-final", "uid", "spec", "labels", "annotation", "not-ready", "phase", "address", "node", "deletion", "controller", "finalizer"} {
		t.Run(mode, func(t *testing.T) {
			f := newOwnerOperationFixture(t)
			f.v.pod.Status.Conditions[0].LastProbeTime = meta.NewTime(f.start.Add(-2 * time.Second))
			op, ctx := f.begin(t)
			original, err := op.Original(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var first, last *core.Pod
			change := func(pod *core.Pod) {
				pod.ResourceVersion = "104"
				switch mode {
				case "status-between-boundaries", "status-within-final":
					pod.Status.Conditions[0].LastProbeTime = meta.NewTime(f.start.Add(-time.Second))
				case "uid":
					pod.UID = types.UID(ownerID(90))
				case "spec":
					pod.Spec.Containers[0].Args = append(pod.Spec.Containers[0].Args, "--changed")
				case "labels":
					pod.Labels["app"] = "changed"
				case "annotation":
					if pod.Annotations == nil {
						pod.Annotations = map[string]string{}
					}
					pod.Annotations["changed"] = "true"
				case "not-ready":
					pod.Status.Conditions[0].Status = core.ConditionFalse
				case "phase":
					pod.Status.Phase = core.PodPending
				case "address":
					pod.Status.PodIPs[0].IP = "10.99.99.99"
				case "node":
					pod.Spec.NodeName = "another-node"
				case "deletion":
					pod.DeletionTimestamp = &meta.Time{Time: f.start}
				case "controller":
					pod.OwnerReferences[0].UID = types.UID(ownerID(90))
				case "finalizer":
					pod.Finalizers = []string{"synthetic.invalid/finalizer"}
				}
			}
			f.mu.Lock()
			if mode == "status-between-boundaries" {
				change(&f.v.pod)
			}
			f.podReadChange = func(n int, pod *core.Pod) {
				if n == 3 {
					first = pod.DeepCopy()
				}
				if n == 4 {
					if mode != "unchanged" && mode != "status-between-boundaries" {
						change(pod)
					}
					last = pod.DeepCopy()
				}
			}
			f.mu.Unlock()
			final, err := op.Final(ctx)
			harmless := mode == "unchanged" || mode == "status-between-boundaries" || mode == "status-within-final"
			if harmless {
				if mode == "status-within-final" {
					f.mu.Lock()
					route := ownerOperationRoute{pod: first.Name, node: first.Spec.NodeName, addresses: original.Peers[0].Addresses}
					a, ea := f.reader.validateObjects(f.v.svc, f.v.deploy, f.v.rs, *first, f.v.binding, route, nil)
					b, eb := f.reader.validateObjects(f.v.svc, f.v.deploy, f.v.rs, *last, f.v.binding, route, nil)
					f.mu.Unlock()
					if ea != nil || eb != nil || a != b || first.UID != last.UID || first.ResourceVersion == last.ResourceVersion {
						t.Fatal("fixture changed actual native identity or behavioral projection", ea, eb)
					}
				}
				if err != nil {
					t.Fatal("same protected identity/spec/Ready observation rejected for status-only update", err)
				}
				if !final.Final || !sameOwnerNativePeers(original.Peers, final.Peers) || !final.ObservedAt.Equal(original.ObservedAt) || !final.FreshUntil.Equal(original.FreshUntil) {
					t.Fatal("final changed original facts or dates")
				}
			} else {
				if err == nil {
					t.Fatal("critical second Pod read mutation accepted")
				}
				reads := f.observer.Load()
				if _, err = op.Original(ctx); err == nil {
					t.Fatal("failed operation retained proof")
				}
				if _, err = op.Final(ctx); err == nil || f.observer.Load() != reads {
					t.Fatal("failed operation retried native reads")
				}
			}
		})
	}
}

func TestOwnerObservationInitialPodStatusOnlyUpdate(t *testing.T) {
	f := newOwnerOperationFixture(t)
	f.podReadChange = func(n int, pod *core.Pod) {
		if n == 2 {
			pod.ResourceVersion = "104"
			pod.Status.Conditions[0].LastProbeTime = meta.NewTime(f.start.Add(-time.Second))
		}
	}
	op, ctx := f.begin(t)
	original, err := op.Original(ctx)
	if err != nil {
		t.Fatal(err)
	}
	final, err := op.Final(ctx)
	if err != nil || !final.Final || !sameOwnerNativePeers(original.Peers, final.Peers) || !final.ObservedAt.Equal(original.ObservedAt) || !final.FreshUntil.Equal(original.FreshUntil) {
		t.Fatal("initial status-only update changed protected facts or dates", err)
	}
	if f.observer.Load() != 30 || f.probe.Load() != 6 {
		t.Fatal("status update added API reads", f.observer.Load(), f.probe.Load())
	}
}
