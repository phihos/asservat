package kubernetes

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

// These synthetic fixtures exercise the closed inventory and target decoder.
// They do not supply activation, native admission or an actual SQL effect guard.
func initialRuntimeResourceFixture(t *testing.T) (*InitialRuntimeResources, contracts.InitialRuntimeResourceState) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	plan := handoverTestPlan()
	s := &InitialRuntimeResources{preparer: &InitialPreparer{plan: plan, protection: &configMapProtection{observer: &PermissionClient{now: time.Now}}}, initial: contracts.InitialInstaller{InstallationID: plan.InstallationID, ClusterID: plan.ClusterID, IssuerEpoch: ownerID(701), Namespace: contracts.WorkerObjectReference{Name: plan.Workload.Namespace, UID: ownerID(702)}, Configuration: plan.Workload.Configuration, FleetSource: contracts.WorkerObjectReference{Name: plan.Workload.FleetSource, UID: ownerID(703)}, FleetGuard: contracts.OwnerDeploymentGuard{Name: plan.Workload.FleetGuard}}, ownerRoots: [][]byte{[]byte("synthetic-public-root")}, binding: strings.Repeat("a", 64)}
	s.names = runtimeResourceNames(s.initial.InstallationID)
	s.initial.Pod = contracts.WorkerObjectReference{Name: plan.Workload.Name, UID: ownerID(705)}
	s.initial.WriterAccount = contracts.WorkerObjectReference{Name: plan.Workload.WriterAccount, UID: ownerID(706)}
	s.initial.ProbeAccount = contracts.WorkerObjectReference{Name: plan.Workload.ProbeAccount, UID: ownerID(707)}
	s.initial.Witness = contracts.WorkerObjectReference{Name: plan.Workload.Witness, UID: ownerID(708)}
	s.initial.WorkloadGuard = contracts.OwnerDeploymentGuard{Name: plan.Workload.WorkloadGuard}
	s.initial.PodSpecDigest = strings.Repeat("c", 64)
	v := contracts.InitialRuntimeResourceState{Format: contracts.InitialRuntimeResourcesFormat, BindingDigest: s.binding, SetupID: ownerID(704), CreatedAt: now.Add(-time.Minute), Until: now.Add(29 * time.Minute), Objects: []contracts.InitialRuntimeResourceClaim{}}
	for i, item := range initialRuntimeResourceItems {
		want, e := s.object(v, i)
		if e != nil {
			t.Fatal(item, e)
		}
		v.Objects = append(v.Objects, contracts.InitialRuntimeResourceClaim{Item: item, OperationID: ownerID(710 + i), TemplateDigest: preparationDigest(want.object), ClaimedAt: now.Add(-10 * time.Second), Until: now.Add(-5 * time.Second), Receipt: &contracts.InitialRuntimeResourceReceipt{UID: ownerID(800 + i), ResourceVersion: "1", Generation: 1}})
	}
	return s, v
}

func TestInitialRuntimeResourceInventoryUsesOnlyRecordedOriginalReferences(t *testing.T) {
	s, v := initialRuntimeResourceFixture(t)
	in, e := s.inventory(v)
	if e != nil {
		t.Fatal(e)
	}
	if in.Namespace != s.initial.Namespace || in.FleetSource != s.initial.FleetSource || in.OwnerAccount.UID != v.Objects[0].Receipt.UID || in.OwnerDeployment.UID != v.Objects[10].Receipt.UID || in.OwnerSourceGuard.PolicyUID != v.Objects[15].Receipt.UID || in.WorkloadGuard.BindingResourceVersion != v.Objects[18].Receipt.ResourceVersion {
		t.Fatal("generated inventory selected new identities")
	}
	policy, _, e := OwnerWorkloadAdmission(in.BridgeAdministration.Owner)
	if e != nil {
		t.Fatal(e)
	}
	want, e := s.object(v, 17)
	if e != nil || !equalJSON(policy, want.object) {
		t.Fatal("inventory rebuilt another namespace guard", e)
	}
	v.Objects[18].Receipt = nil
	if _, e = s.inventory(v); e == nil {
		t.Fatal("incomplete guard became usable projection provenance")
	}
}

func TestInitialRuntimeResourcesRequireOriginalOrderedOneUseClaims(t *testing.T) {
	s, v := initialRuntimeResourceFixture(t)
	if !s.valid(v) {
		t.Fatal("completed exact historical claims rejected")
	}
	for name, change := range map[string]func(*contracts.InitialRuntimeResourceState){
		"binding":              func(v *contracts.InitialRuntimeResourceState) { v.BindingDigest = strings.Repeat("b", 64) },
		"refill setup":         func(v *contracts.InitialRuntimeResourceState) { v.Until = v.Until.Add(time.Minute) },
		"omitted sequence":     func(v *contracts.InitialRuntimeResourceState) { v.Objects = nil },
		"unclosed predecessor": func(v *contracts.InitialRuntimeResourceState) { v.Objects[0].Receipt = nil },
		"reordered": func(v *contracts.InitialRuntimeResourceState) {
			v.Objects[0], v.Objects[1] = v.Objects[1], v.Objects[0]
		},
		"second operation ID":     func(v *contracts.InitialRuntimeResourceState) { v.Objects[1].OperationID = v.Objects[0].OperationID },
		"adopt original setup ID": func(v *contracts.InitialRuntimeResourceState) { v.Objects[0].OperationID = v.SetupID },
		"reused object":           func(v *contracts.InitialRuntimeResourceState) { v.Objects[1].Receipt.UID = v.Objects[0].Receipt.UID },
		"long claim": func(v *contracts.InitialRuntimeResourceState) {
			v.Objects[0].Until = v.Objects[0].ClaimedAt.Add(6 * time.Second)
		},
		"future claim":           func(v *contracts.InitialRuntimeResourceState) { v.Objects[0].ClaimedAt = time.Now().Add(time.Hour) },
		"changed derived object": func(v *contracts.InitialRuntimeResourceState) { v.Objects[10].Receipt.UID = ownerID(998) },
		"new template":           func(v *contracts.InitialRuntimeResourceState) { v.Objects[0].TemplateDigest = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			b, _ := json.Marshal(v)
			var bad contracts.InitialRuntimeResourceState
			_ = json.Unmarshal(b, &bad)
			change(&bad)
			if s.valid(bad) {
				t.Fatal("changed/renewed inventory accepted")
			}
		})
	}
	// An unresolved last CREATE retains exactly its first identity/deadline.
	v.Objects = v.Objects[:1]
	v.Objects[0].Receipt = nil
	if !s.valid(v) {
		t.Fatal("unknown original claim lost its lookup-only representation")
	}
}

func TestInitialRuntimeResourceDecoderRejectsMissingAndInjectedWorkload(t *testing.T) {
	s, v := initialRuntimeResourceFixture(t)
	index := 10
	want, e := s.object(v, index)
	if e != nil {
		t.Fatal(e)
	}
	d := want.object.(*apps.Deployment)
	d.UID = types.UID(v.Objects[index].Receipt.UID)
	d.ResourceVersion = "2"
	d.Generation = 1
	d.Annotations = map[string]string{initialRuntimeResourceMarker: v.Objects[index].OperationID}
	ctx, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	encode := func(v any) []byte {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	if _, e = s.verified(ctx, encode(d), v, index); e != nil {
		t.Fatal("exact generated object", e)
	}
	for name, change := range map[string]func(*apps.Deployment){
		"unexpected replica": func(d *apps.Deployment) { d.Spec.Replicas = ptr.To(int32(1)) },
		"sidecar": func(d *apps.Deployment) {
			d.Spec.Template.Spec.Containers = append(d.Spec.Template.Spec.Containers, core.Container{Name: "injected", Image: "other"})
		},
		"privilege":              func(d *apps.Deployment) { d.Spec.Template.Spec.HostPID = true },
		"new operation":          func(d *apps.Deployment) { d.Annotations[initialRuntimeResourceMarker] = ownerID(999) },
		"new UID":                func(d *apps.Deployment) { d.UID = types.UID(ownerID(999)) },
		"different key mount":    func(d *apps.Deployment) { d.Spec.Template.Spec.Volumes[0].Projected.Sources[1].Secret.Name = "other" },
		"wrong account":          func(d *apps.Deployment) { d.Spec.Template.Spec.ServiceAccountName = "other" },
		"changed image":          func(d *apps.Deployment) { d.Spec.Template.Spec.Containers[0].Image = "other" },
		"unqualified annotation": func(d *apps.Deployment) { d.Annotations["other"] = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := d.DeepCopy()
			change(bad)
			if _, e := s.verified(ctx, encode(bad), v, index); e == nil {
				t.Fatal("mutated workload accepted")
			}
		})
	}
	// A populated destination must never fill missing JSON fields from the
	// expected template: missing spec, kind and UID all independently deny.
	for _, field := range []string{"spec", "kind", "apiVersion", "metadata"} {
		t.Run("missing "+field, func(t *testing.T) {
			var wire map[string]json.RawMessage
			_ = json.Unmarshal(encode(d), &wire)
			delete(wire, field)
			if _, e := s.verified(ctx, encode(wire), v, index); e == nil {
				t.Fatal("omitted wire field inherited expected template")
			}
		})
	}
	late, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Millisecond))
	defer stop()
	if _, e = s.verified(late, encode(d), v, index); e == nil {
		t.Fatal("expired decode returned usable receipt")
	}
}

func TestInitialRuntimeObjectsStayInertAndDoNotGrantSecretRead(t *testing.T) {
	s, v := initialRuntimeResourceFixture(t)
	seen := map[string]bool{}
	for i := range initialRuntimeResourceItems {
		o, e := s.object(v, i)
		if e != nil {
			t.Fatal(e)
		}
		m, _ := meta.Accessor(o.object)
		key := o.collection + "/" + m.GetName()
		if seen[key] {
			t.Fatal("duplicate target")
		}
		seen[key] = true
		if d, ok := o.object.(*apps.Deployment); ok {
			if d.Spec.Replicas == nil || *d.Spec.Replicas != 0 || d.Spec.Strategy.Type != apps.RecreateDeploymentStrategyType || d.Spec.Template.Spec.HostNetwork || d.Spec.Template.Spec.AutomountServiceAccountToken == nil || *d.Spec.Template.Spec.AutomountServiceAccountToken {
				t.Fatal("inert Restricted envelope lost")
			}
		}
		b, _ := json.Marshal(o.object)
		if strings.Contains(string(b), `"resources":["secrets"]`) || strings.Contains(string(b), `"resources":["*"]`) || strings.Contains(string(b), `"verbs":["*"]`) {
			t.Fatal("runtime credential or wildcard RBAC", initialRuntimeResourceItems[i])
		}
	}
	if len(seen) != contracts.InitialRuntimeResourceCount {
		t.Fatal("unbounded inventory")
	}
}
