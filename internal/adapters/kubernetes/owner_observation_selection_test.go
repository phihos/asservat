package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	admission "k8s.io/api/admissionregistration/v1"
	core "k8s.io/api/core/v1"
	rbac "k8s.io/api/rbac/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestObservationCapabilityIsOriginalResourceBinding(t *testing.T) {
	// Both roots are constructed from the identical fresh preparer, before any
	// later fixture effect; the operation fixture's subsequent API state would
	// otherwise fail the second constructor's own source-guard verification.
	f, p, original := handoverConflictProviderFixture(t, nil)
	effects := rootPinEffects(t, p, original)
	initial, err := p.inputConfiguration(original)
	if err != nil {
		t.Fatal(err)
	}
	names := runtimeResourceNames(original.InstallationID)
	worker := contracts.ConfigurationProviderSelection{AuthMount: "configuration-auth", AuthMountAccessor: "auth_configuration_original", AuditCredentials: contracts.WorkerObjectReference{Name: names.WorkerProviders, UID: ownerID(4480)}}
	owner := contracts.OwnerProviderSelection{AuthMount: "owner-auth", AuthMountAccessor: "auth_owner_original", AuditCredentials: contracts.WorkerObjectReference{Name: contracts.OwnerProviderAuditSecretName(original.InstallationID), UID: ownerID(4481)}}
	f.mu.Lock()
	for _, ref := range []contracts.WorkerObjectReference{worker.AuditCredentials, owner.AuditCredentials} {
		object := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: ref.Name, Namespace: initial.Namespace.Name, UID: types.UID(ref.UID), ResourceVersion: "1"}, Type: core.SecretTypeOpaque}
		raw, _ := json.Marshal(object)
		var value map[string]any
		_ = json.Unmarshal(raw, &value)
		f.objects["/api/v1/namespaces/"+initial.Namespace.Name+"/secrets/"+ref.Name] = value
	}
	f.mu.Unlock()
	roots := [][]byte{ownerConfigurationTestRoot(t, time.Now())}
	old, err := NewProviderInstalledRuntimeResources(context.Background(), p, effects, roots, worker, owner)
	if err != nil {
		t.Fatal("v1 constructor", err)
	}
	t.Cleanup(old.Close)
	selected, err := NewObservationProviderInstalledRuntimeResources(context.Background(), p, effects, roots, worker, owner)
	if err != nil {
		t.Fatal("v2 constructor", err)
	}
	t.Cleanup(selected.Close)
	if selected.binding == old.binding || selected.observationFormat != contracts.OwnerObservationOperationFormat || old.observationFormat != "" {
		t.Fatal("original capability not independently bound")
	}
	fleet, err := NewFleetProviderInstalledRuntimeResources(context.Background(), p, effects, roots, worker, owner)
	if err != nil {
		t.Fatal("fleet constructor", err)
	}
	t.Cleanup(fleet.Close)
	if fleet.binding == old.binding || fleet.binding == selected.binding {
		t.Fatal("fleet source rights not bound before resource claims")
	}
	for _, test := range []struct {
		name     string
		producer *InitialRuntimeResources
		want     bool
	}{{"disabled", old, false}, {"observation-only", selected, false}, {"fleet", fleet, true}} {
		t.Run(test.name+"-fleet-rbac", func(t *testing.T) {
			// Exercise the actual immutable resource producer, whose InitialInstaller
			// always names the fleet source even when public fleet issuance is absent.
			role, err := test.producer.object(contracts.InitialRuntimeResourceState{}, 2)
			if err != nil {
				t.Fatal(err)
			}
			guard, err := test.producer.object(contracts.InitialRuntimeResourceState{}, 4)
			if err != nil {
				t.Fatal(err)
			}
			sourceRead, guardRead := false, false
			for _, rule := range role.object.(*rbac.Role).Rules {
				sourceRead = sourceRead || slices.Contains(rule.ResourceNames, initial.FleetSource.Name)
			}
			for _, rule := range guard.object.(*rbac.ClusterRole).Rules {
				guardRead = guardRead || slices.Contains(rule.ResourceNames, initial.FleetGuard.Name)
			}
			if sourceRead != test.want || guardRead != test.want {
				t.Fatalf("fleet source/guard rights = %t/%t, want %t", sourceRead, guardRead, test.want)
			}
		})
	}
	// Refusal to adopt an existing v1 journal is checked through the same
	// valid() predicate Read uses, in the mixed-state test below; here no
	// journal exists, so a Read failure would not prove that property.
}

func TestProviderResourcesRejectLateFleetRoles(t *testing.T) {
	s, state := providerResourceFixture(t)
	if !s.valid(state) {
		t.Fatal("original resource claims rejected")
	}
	s.ownerFleet = true
	if s.valid(state) {
		t.Fatal("disabled fleet journal adopted expanded Role templates")
	}
}

func TestProviderFleetProbeComposition(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		name := "disabled"
		if enabled {
			name = "enabled"
		}
		t.Run(name, func(t *testing.T) {
			s, state := providerResourceFixture(t)
			s.ownerFleet = enabled
			for i := range state.Objects {
				obj, err := s.object(state, i)
				if err != nil {
					t.Fatal(err)
				}
				state.Objects[i].TemplateDigest = preparationDigest(obj.object)
			}
			inv, err := s.inventory(state)
			if err != nil {
				t.Fatal(err)
			}
			pair := cfg.OwnerConfigurationProbe{ConfigMap: s.initial.FleetSource.Name, ServiceAccount: inv.OwnerAccount.Name}
			plan := inv.BridgeAdministration.Owner
			if slices.Contains(plan.ConfigurationProbes, pair) != enabled || len(inv.BridgeAdministration.SourceProbes) != 3 {
				t.Fatal("fleet owner selection changed the worker's independent source probes")
			}
			built, err := s.object(state, 17)
			if err != nil {
				t.Fatal(err)
			}
			policy, _, err := OwnerWorkloadAdmission(plan)
			if err != nil || !reflect.DeepEqual(policy.Spec, built.object.(*admission.ValidatingAdmissionPolicy).Spec) {
				t.Fatal("inventory lost the originally selected owner namespace guard", err)
			}
			selected, err := s.preparer.originalOwnerFleet(s.initial, state)
			if err != nil || selected != enabled {
				t.Fatal("fresh preparer selected another fleet guard candidate", selected, err)
			}
			bad := state
			bad.Objects = slices.Clone(state.Objects)
			bad.Objects[2].TemplateDigest = strings.Repeat("0", 64)
			if _, err := s.preparer.originalOwnerFleet(s.initial, bad); err == nil {
				t.Fatal("unknown original Role interpreted as fleet capability")
			}
			retained, _, err := InitialRuntimeRetainedAdmission(inv.BridgeAdministration)
			if err != nil {
				t.Fatal(err)
			}
			ownerPair := "request.name == " + ownerCELString(pair.ConfigMap) + " && request.userInfo.username == " + ownerCELString("system:serviceaccount:"+inv.Namespace.Name+":"+pair.ServiceAccount) + " && request.userInfo.uid == " + ownerCELString(inv.OwnerAccount.UID)
			if strings.Contains(retained.Spec.Validations[0].Expression, ownerPair) != enabled {
				t.Fatal("retained initial guard does not preserve the exact selected owner/source/UID probe")
			}
			activation, err := BuildHubWorkerActivation(s.initial.InstallationID, contracts.InitialRuntimeResourceSnapshot{State: state, UID: ownerID(4490)}, inv)
			if err != nil {
				t.Fatal("worker activation rejected original optional fleet probe", err)
			}
			in := contracts.HubWorkerDeployment{InstallationID: s.initial.InstallationID, Namespace: inv.Namespace, FleetSource: inv.FleetSource, OwnerSource: inv.OwnerSource, OwnerGuard: inv.OwnerSourceGuard, LeaderLease: inv.LeaderLease, Activation: activation}
			if !hubWorkerActivationShapeBound(in) || !reflect.DeepEqual(capacityActivationAdministration(in), plan) {
				t.Fatal("worker activation lost original selected probe/guard")
			}
			if enabled {
				last := len(activation.ConfigurationProbes) - 1
				activation.ConfigurationProbes[last].ConfigMap = "unrelated"
				if hubWorkerActivationShapeBound(in) {
					t.Fatal("optional fleet probe accepted an unrelated source")
				}
			}
		})
	}
}

func TestObservationCapabilityRejectsMixedAndUnknownOriginalState(t *testing.T) {
	root, old := providerResourceFixture(t)
	before, _ := json.Marshal(old)
	if bytes.Contains(before, []byte(`"observationFormat"`)) {
		t.Fatal("legacy wire changed")
	}
	selected := old
	selected.ObservationFormat = contracts.OwnerObservationOperationFormat
	if root.valid(selected) {
		t.Fatal("existing resource root adopted later capability")
	}
	root.observationFormat = contracts.OwnerObservationOperationFormat
	if !root.valid(selected) || root.valid(old) {
		t.Fatal("exact original capability not required")
	}
	for _, bad := range []string{"owner-observation/v1", "owner-observation/v3", "unknown"} {
		changed := selected
		changed.ObservationFormat = bad
		if root.valid(changed) || initialRuntimeLayoutStateValid(changed) {
			t.Fatal("explicit unsupported capability accepted", bad)
		}
	}
	selected.OwnerLayout = contracts.OwnerInstalledLayout
	if initialRuntimeLayoutStateValid(selected) {
		t.Fatal("v2 capability selected in old layout")
	}
	after, _ := json.Marshal(old)
	if !bytes.Equal(before, after) {
		t.Fatal("selection mutated legacy source")
	}
}

func TestObservationOriginalSelectionPropagatesWithoutRuntimeActivation(t *testing.T) {
	f := newOwnerIdentityOperationObservationFixture(t, nil, true)
	startOwnerIdentityOperationAcceptedObserver(t, f)
	api := installOwnerBootstrapAPI(t, f)
	plan := ownerBootstrapPlanFixture(f)
	if _, err := NewOwnerBootstrapSelectionProducer(f.root, plan); err == nil {
		t.Fatal("omitted selection downgraded original v2")
	}
	plan.ObservationFormat = contracts.OwnerObservationOperationFormat
	producer, err := NewOwnerBootstrapSelectionProducer(f.root, plan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(producer.Close)
	out, err := producer.Complete(context.Background())
	if err != nil || out.Status != OwnerBootstrapComplete {
		t.Fatal("original v2 selection", out.Status, err)
	}
	if out.Input.Observation.Format != contracts.OwnerObservationOperationFormat || out.Selection.ObservationFormat != contracts.OwnerObservationOperationFormat || out.Snapshot.State.OwnerBootstrap.ObservationFormat != contracts.OwnerObservationOperationFormat || !ownerBootstrapDeploymentBound(out.Input, out.Snapshot.State) {
		t.Fatal("capability lost along original provenance")
	}
	if out.Snapshot.State.OwnerIdentity != nil || out.Snapshot.State.OwnerLaunch != nil || api.creates.Load() != 1 || api.writes.Load() != 3 {
		t.Fatal("public selection performed another phase")
	}
	changed := out.Snapshot.State
	changed.ObservationFormat = ""
	if ownerBootstrapDeploymentBound(out.Input, changed) || ownerBootstrapStateValid(out.Input.InstallationID, changed, f.resources.now()) {
		t.Fatal("v2 receipt reinterpreted through omitted capability")
	}
}

func TestObservationV2UnknownSelectionCreateDoesNotRepeat(t *testing.T) {
	f := newOwnerIdentityOperationObservationFixture(t, nil, true)
	startOwnerIdentityOperationAcceptedObserver(t, f)
	api := installOwnerBootstrapAPI(t, f)
	plan := ownerBootstrapPlanFixture(f)
	plan.ObservationFormat = contracts.OwnerObservationOperationFormat
	producer, err := NewOwnerBootstrapSelectionProducer(f.root, plan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(producer.Close)
	if _, err = producer.Advance(context.Background()); err != nil {
		t.Fatal(err)
	}
	api.loseCreate.Store(true)
	if _, err = producer.Advance(context.Background()); err == nil {
		t.Fatal("lost create reported acknowledged")
	}
	inspected, err := producer.Inspect(context.Background())
	if err != nil || inspected.Status != OwnerBootstrapPending || api.creates.Load() != 1 {
		t.Fatal("original exact lookup", err)
	}
	original := *inspected.Snapshot.State.OwnerBootstrap.Child
	complete, err := producer.Advance(context.Background())
	if err != nil || complete.Status != OwnerBootstrapComplete || api.creates.Load() != 1 || complete.Snapshot.State.OwnerBootstrap.Child.OperationID != original.OperationID || !complete.Snapshot.State.OwnerBootstrap.Child.Until.Equal(original.Until) {
		t.Fatal("uncertain original child replayed or renewed", err)
	}
}

// Synthetic predecessor receipts remain explicit in this existing fixture. The
// production native readers/selection producer execute, but this is neither an
// installed regional process nor proof that current runtime authority exists.
func TestObservationParticipantsBindExactDistinctOwnerAndCaller(t *testing.T) {
	f := newOwnerWorkerCallerObservationFixture(t, true)
	writes, creates := f.api.writes.Load(), f.api.creates.Load()
	var roleReads, selectionReads atomic.Int32
	f.f.api.mu.Lock()
	previous := f.f.api.extra
	f.f.api.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == f.rolePath {
			roleReads.Add(1)
		}
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/"+f.selection.Snapshot.State.OwnerBootstrap.Child.Receipt.Object.Name) {
			selectionReads.Add(1)
		}
		return previous != nil && previous(w, r)
	}
	f.f.api.mu.Unlock()
	end := time.Now().Add(4 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), end)
	defer cancel()
	got, err := f.producer.ReadObservationParticipants(ctx)
	if err != nil {
		t.Fatal("exact original participants", err)
	}
	if !got.Owner.Valid() || !got.Caller.Pin.Valid() || got.Owner.RootID != got.Caller.Pin.RootID || got.Owner.RootID != f.selection.Selection.PermissionRootID ||
		got.Owner.SourceUID != f.f.root.input.OwnerConfigurationUID || got.Owner.Pool.DeploymentUID != f.resources.State.Objects[10].Receipt.UID ||
		got.Owner.Pool.AccountUID != f.resources.State.Objects[0].Receipt.UID || got.Caller.Pin.DeploymentUID != f.resources.State.Objects[11].Receipt.UID ||
		got.Caller.Pin.AccountUID != f.resources.State.Objects[1].Receipt.UID || got.Owner.Pool.AccountUID == got.Caller.Pin.AccountUID ||
		got.Owner.Pool.DeploymentUID == got.Caller.Pin.DeploymentUID || got.Caller.FreshUntil.After(end) || !got.Caller.ObservedAt.Before(got.Caller.FreshUntil) {
		t.Fatal("original participant provenance or bound lost")
	}
	if roleReads.Load() != 2 || selectionReads.Load() != 2 || f.api.writes.Load() != writes || f.api.creates.Load() != creates {
		t.Fatal("participants added effects or nested native reads", roleReads.Load(), selectionReads.Load())
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range f.roles.State.Roles {
		if bytes.Contains(raw, []byte(role.Password)) {
			t.Fatal("public participant leaked credential")
		}
	}
	if bytes.Contains(raw, []byte("PodUID")) || bytes.Contains(raw, []byte("ReplicaSetUID")) {
		t.Fatal("invented runtime descendant")
	}
}

func TestObservationParticipantsRejectLegacySelectionBeforeNativeRead(t *testing.T) {
	f := newOwnerWorkerCallerFixture(t)
	var reads atomic.Int32
	f.f.api.mu.Lock()
	previous := f.f.api.extra
	f.f.api.extra = func(w http.ResponseWriter, r *http.Request) bool {
		reads.Add(1)
		return previous != nil && previous(w, r)
	}
	f.f.api.mu.Unlock()
	if out, err := f.producer.ReadObservationParticipants(context.Background()); err == nil || out.Owner.Valid() || reads.Load() != 0 {
		t.Fatal("legacy original acquired v2 capability")
	}
	if _, err := f.producer.ReadWorkerCaller(context.Background()); err != nil {
		t.Fatal("legacy caller path changed", err)
	}
}

func TestObservationParticipantsRejectOwnerReplacementAtFinalBoundary(t *testing.T) {
	f := newOwnerWorkerCallerObservationFixture(t, true)
	var reads atomic.Int32
	f.f.api.mu.Lock()
	previous := f.f.api.extra
	f.f.api.extra = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && r.URL.Path == f.rolePath && reads.Add(1) == 1 {
			permissionReply(w, f.f.api.objects[f.rolePath])
			path := "/apis/apps/v1/namespaces/" + f.f.root.input.Namespace.Name + "/deployments/" + f.f.root.input.Deployment.Name
			f.f.api.objects[path]["metadata"].(map[string]any)["uid"] = ownerID(23000)
			return true
		}
		return previous != nil && previous(w, r)
	}
	f.f.api.mu.Unlock()
	out, err := f.producer.ReadObservationParticipants(context.Background())
	if err == nil || out.Owner.Valid() || out.Caller.Pin.Valid() {
		t.Fatal("final replacement gained original participant provenance")
	}
}
