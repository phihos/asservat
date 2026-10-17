package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

type ownerWorkerCallerFixture struct {
	f          *ownerIdentityOperationFixture
	producer   *OwnerBootstrapSelectionProducer
	api        *ownerBootstrapAPIFixture
	selection  OwnerBootstrapAdvance
	resources  contracts.InitialRuntimeResourceSnapshot
	roles      contracts.ConfigurationRuntimeRoleSnapshot
	deployment apps.Deployment
	rolePath   string
}

// Only the new public selection uses its actual producer here. The original
// bridge/enforcement/accepted SQL observer and the positive SQL3/worker launch
// receipts are explicitly synthetic component prerequisites. This fixture
// cannot qualify an installed worker, native admission or SQL role creation.
func newOwnerWorkerCallerFixture(t *testing.T) *ownerWorkerCallerFixture {
	t.Helper()
	return newOwnerWorkerCallerObservationFixture(t, false)
}

func newOwnerWorkerCallerObservationFixture(t *testing.T, observation bool) *ownerWorkerCallerFixture {
	t.Helper()
	f := newOwnerIdentityOperationObservationFixture(t, nil, observation)
	startOwnerIdentityOperationAcceptedObserver(t, f)
	api := installOwnerBootstrapAPI(t, f)
	plan := ownerBootstrapPlanFixture(f)
	if observation {
		plan.ObservationFormat = contracts.OwnerObservationOperationFormat
	}
	p, err := NewOwnerBootstrapSelectionProducer(f.root, plan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	selection, err := p.Complete(context.Background())
	if err != nil || selection.Status != OwnerBootstrapComplete {
		t.Fatal("original selection", err)
	}
	var current ownerIdentityOperationNative
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = f.root.operation(ctx, func(call context.Context) error {
		var e error
		current, e = f.root.readOwnerIdentityOperationNative(call, f.root.input.LayoutDigest, false)
		return e
	})
	if err != nil {
		t.Fatal("synthetic predecessor current native", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	until := current.until.UTC().Truncate(time.Microsecond)
	proof := current.source.proof.observation
	input := f.source.input
	state := contracts.ConfigurationRuntimeRoleState{Format: contracts.ConfigurationRuntimeRoleStateFormat, Input: input,
		OperationID: ownerID(21800), CreatedAt: current.retained.resources.State.CreatedAt, Until: current.retained.resources.State.Until,
		Projection: &contracts.PublicRuntimeProjectionClaim{OperationID: ownerID(21801), ClaimedAt: now, Until: until, SecretUID: ownerID(21802)}}
	for i, purpose := range contracts.ConfigurationRuntimeRolePurposes() {
		key := make([]byte, 32)
		key[0] = byte(i + 1)
		state.Roles = append(state.Roles, contracts.ConfigurationRuntimeRoleMaterial{Purpose: purpose, Password: base64.RawURLEncoding.EncodeToString(key),
			Claim:   &contracts.ConfigurationRuntimeRoleClaim{OperationID: ownerID(21810 + i), ClaimedAt: now, Until: until, DatabaseOID: 42, PostmasterAt: now.Add(-time.Hour), Sources: proof},
			Receipt: &contracts.PublicRuntimeRoleReceipt{RoleName: fmt.Sprintf("as_%s_cfg_%02d", strings.ReplaceAll(input.InstallationID, "-", ""), i), RoleOID: uint32(21810 + i), LayoutDigest: input.LayoutDigest}})
	}
	roles := contracts.ConfigurationRuntimeRoleSnapshot{State: state, UID: ownerID(21803), ResourceVersion: "81", ObservedAt: now, ValidUntil: until, Sources: proof}
	resources := current.retained.resources
	workerInput, digest, _, err := f.resources.configurationWorkerInputMaterial(resources, roles, ownerID(21804), now)
	if err != nil {
		t.Fatal("synthetic launched input", err)
	}
	provenance := workerInput.ProviderInputs
	resources.State.WorkerInputs = &contracts.ConfigurationWorkerInputClaim{OperationID: provenance.OperationID, PublicDigest: digest,
		ConfigurationRoot: provenance.ConfigurationRoot, ConfigurationSetupID: provenance.ConfigurationSetupID, SQLProjection: provenance.SQLProjection,
		AuditCredentials: workerInput.ProviderAuthentication.AuditCredentials, ClaimedAt: now, Until: until,
		Receipt: &contracts.ConfigurationWorkerInputReceipt{Configuration: contracts.WorkerObjectReference{Name: f.resources.names.WorkerInputs, UID: ownerID(21805)}, ResourceVersion: "82", ObservedAt: now}}
	launch, err := configurationWorkerLaunchPlanFor(workerInput, resources, roles, current.source.deployment, ownerID(21806), now, until)
	if err != nil {
		t.Fatal("synthetic launch", err)
	}
	launch.claim.Receipt = &contracts.ConfigurationRuntimeLaunchReceipt{ResourceVersion: "83", ObservedAt: now}
	roles.State.Launch = &launch.claim
	roles.ResourceVersion = "84"
	deployment := launch.running
	deployment.ResourceVersion, deployment.Generation = "83", current.source.deployment.Generation+1
	if !configurationRoleStateValid(input, roles.State, now) || !f.resources.valid(resources.State) {
		t.Fatal("invalid explicit synthetic positive predecessor")
	}
	out := &ownerWorkerCallerFixture{f: f, producer: p, api: api, selection: selection, resources: resources, roles: roles, deployment: deployment,
		rolePath: "/api/v1/namespaces/" + input.Namespace.Name + "/secrets/" + configurationWorkerRoleRootName(input.InstallationID)}
	f.api.mu.Lock()
	defer f.api.mu.Unlock()
	out.store(t, out.rolePath, out.roleObject(t))
	out.store(t, "/apis/apps/v1/namespaces/"+input.Namespace.Name+"/deployments/"+input.Deployment.Name, deployment)
	resourceObject := f.api.objects[f.resources.path()]
	raw, _ := json.Marshal(resources.State)
	resourceObject["data"] = map[string]any{"state.json": base64.StdEncoding.EncodeToString(raw)}
	resourceObject["metadata"].(map[string]any)["resourceVersion"] = "85"
	return out
}

// Caller holds the synthetic API fixture mutex.
func (f *ownerWorkerCallerFixture) store(t *testing.T, path string, object any) {
	t.Helper()
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if json.Unmarshal(raw, &value) != nil {
		t.Fatal("fixture object encoding")
	}
	f.f.api.objects[path] = value
}

func (f *ownerWorkerCallerFixture) roleObject(t *testing.T) core.Secret {
	t.Helper()
	raw, err := json.Marshal(f.roles.State)
	if err != nil {
		t.Fatal(err)
	}
	return core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: meta.ObjectMeta{Name: configurationWorkerRoleRootName(f.roles.State.Input.InstallationID), Namespace: f.roles.State.Input.Namespace.Name, UID: types.UID(f.roles.UID), ResourceVersion: f.roles.ResourceVersion},
		Type:       core.SecretTypeOpaque, Data: map[string][]byte{"state.json": raw}}
}
