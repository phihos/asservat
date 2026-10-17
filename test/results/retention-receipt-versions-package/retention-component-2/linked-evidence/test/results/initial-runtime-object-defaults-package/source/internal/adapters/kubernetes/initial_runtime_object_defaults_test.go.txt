package kubernetes

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

// This reproduces API defaulting and controller metadata synthetically. The
// separate opt-in test qualifies actual Kubernetes responses for every kind.
func TestInitialRuntimeDeploymentDefaultsPreserveOriginalIdentity(t *testing.T) {
	for _, index := range []int{10, 11} {
		s, state := initialRuntimeResourceFixture(t)
		object, err := s.object(state, index)
		if err != nil {
			t.Fatal(err)
		}
		original := object.object.(*apps.Deployment)
		if original.Spec.Template.Spec.RestartPolicy != core.RestartPolicyAlways {
			t.Errorf("%s builder omitted explicit Always restart policy", state.Objects[index].Item)
		}
		original.UID = types.UID(state.Objects[index].Receipt.UID)
		original.ResourceVersion = "2"
		original.Generation = 1
		original.Annotations = map[string]string{initialRuntimeResourceMarker: state.Objects[index].OperationID}
		original.Spec.Template.Spec.RestartPolicy = core.RestartPolicyAlways
		original.Spec.Template.Spec.DNSPolicy = core.DNSClusterFirst
		original.Spec.Template.Spec.SchedulerName = core.DefaultSchedulerName
		original.Spec.RevisionHistoryLimit = ptr.To(int32(10))
		original.Spec.ProgressDeadlineSeconds = ptr.To(int32(600))
		original.Status.ObservedGeneration = 1
		original.Status.Conditions = []apps.DeploymentCondition{{Type: apps.DeploymentProgressing, Status: core.ConditionTrue, Reason: "NewReplicaSetCreated"}}
		check := func(t *testing.T, d *apps.Deployment, accept bool) {
			t.Helper()
			raw, e := json.Marshal(d)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			receipt, e := s.verified(ctx, raw, state, index)
			if (e == nil) != accept {
				t.Fatalf("%s receipt acceptance=%v, want %v: %v", state.Objects[index].Item, e == nil, accept, e)
			}
			if accept && (receipt.UID != string(d.UID) || receipt.Generation != 1 || receipt.ResourceVersion != d.ResourceVersion) {
				t.Fatal("original receipt identity changed")
			}
		}
		t.Run(state.Objects[index].Item+"/api defaults", func(t *testing.T) { check(t, original, true) })
		original.Annotations["deployment.kubernetes.io/revision"] = "1"
		t.Run(state.Objects[index].Item+"/original controller revision", func(t *testing.T) { check(t, original, true) })
		for name, mutate := range map[string]func(*apps.Deployment){
			"later revision":           func(d *apps.Deployment) { d.Annotations["deployment.kubernetes.io/revision"] = "2" },
			"noncanonical revision":    func(d *apps.Deployment) { d.Annotations["deployment.kubernetes.io/revision"] = "01" },
			"generation change":        func(d *apps.Deployment) { d.Generation++ },
			"missing generation":       func(d *apps.Deployment) { d.Generation = 0 },
			"missing restart policy":   func(d *apps.Deployment) { d.Spec.Template.Spec.RestartPolicy = "" },
			"Never restart policy":     func(d *apps.Deployment) { d.Spec.Template.Spec.RestartPolicy = core.RestartPolicyNever },
			"OnFailure restart policy": func(d *apps.Deployment) { d.Spec.Template.Spec.RestartPolicy = core.RestartPolicyOnFailure },
			"another annotation":       func(d *apps.Deployment) { d.Annotations["unqualified"] = "value" },
			"wrong operation":          func(d *apps.Deployment) { d.Annotations[initialRuntimeResourceMarker] = ownerID(999) },
			"changed template":         func(d *apps.Deployment) { d.Spec.Template.Annotations = map[string]string{"unqualified": "value"} },
			"changed replicas":         func(d *apps.Deployment) { d.Spec.Replicas = ptr.To(int32(1)) },
			"changed account":          func(d *apps.Deployment) { d.Spec.Template.Spec.ServiceAccountName = "other" },
			"changed volume":           func(d *apps.Deployment) { d.Spec.Template.Spec.Volumes[0].Projected.DefaultMode = ptr.To(int32(0777)) },
			"added init container": func(d *apps.Deployment) {
				d.Spec.Template.Spec.InitContainers = []core.Container{{Name: "extra", Image: "extra"}}
			},
			"privilege":         func(d *apps.Deployment) { d.Spec.Template.Spec.HostPID = true },
			"changed retention": func(d *apps.Deployment) { d.Spec.RevisionHistoryLimit = ptr.To(int32(11)) },
		} {
			t.Run(state.Objects[index].Item+"/"+name, func(t *testing.T) { bad := original.DeepCopy(); mutate(bad); check(t, bad, false) })
		}
	}
	s, state := initialRuntimeResourceFixture(t)
	object, err := s.object(state, 0)
	if err != nil {
		t.Fatal(err)
	}
	account := object.object.(*core.ServiceAccount)
	account.UID = types.UID(state.Objects[0].Receipt.UID)
	account.ResourceVersion = "2"
	account.Generation = 1
	account.Annotations = map[string]string{initialRuntimeResourceMarker: state.Objects[0].OperationID, "deployment.kubernetes.io/revision": "1"}
	raw, _ := json.Marshal(account)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = s.verified(ctx, raw, state, 0); err == nil {
		t.Fatal("Deployment revision permitted on another kind")
	}
}
