package kubernetes

import (
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	apps "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Pure original-body derivation only. SQL roles/source and resource receipts
// are synthetic; this helper cannot authorize a Deployment write or receipt.
func configurationWorkerLaunchPlanFixture(t *testing.T) (contracts.HubWorkerDeployment, contracts.InitialRuntimeResourceSnapshot, contracts.ConfigurationRuntimeRoleSnapshot, apps.Deployment, time.Time) {
	t.Helper()
	resources, snapshot, roles, now := configurationWorkerMaterialFixture(t)
	object, err := resources.object(snapshot.State, 11)
	if err != nil {
		t.Fatal(err)
	}
	inert := object.object.(*apps.Deployment).DeepCopy()
	inert.UID, inert.ResourceVersion, inert.Generation = types.UID(roles.State.Input.Deployment.UID), "17", 1
	roles.Sources.WorkloadDigest = configurationWorkerDeploymentDigest(*inert)
	for index := range roles.State.Roles {
		roles.State.Roles[index].Claim.Sources = roles.Sources
	}
	input, digest, _, err := resources.configurationWorkerInputMaterial(snapshot, roles, ownerID(17300), now)
	if err != nil {
		t.Fatal(err)
	}
	in := input.ProviderInputs
	snapshot.State.WorkerInputs = &contracts.ConfigurationWorkerInputClaim{OperationID: in.OperationID, PublicDigest: digest,
		ConfigurationRoot: in.ConfigurationRoot, ConfigurationSetupID: in.ConfigurationSetupID, SQLProjection: in.SQLProjection,
		AuditCredentials: input.ProviderAuthentication.AuditCredentials, ClaimedAt: now, Until: now.Add(5 * time.Second),
		Receipt: &contracts.ConfigurationWorkerInputReceipt{Configuration: contracts.WorkerObjectReference{Name: resources.names.WorkerInputs, UID: ownerID(17301)}, ResourceVersion: "18", ObservedAt: now}}
	if !resources.valid(snapshot.State) {
		t.Fatal("complete synthetic input receipt invalid")
	}
	return input, snapshot, roles, *inert, now
}

func TestConfigurationWorkerLaunchPlanPinsSoleEditAndOriginalDates(t *testing.T) {
	input, resources, roles, inert, now := configurationWorkerLaunchPlanFixture(t)
	original, _ := json.Marshal(inert)
	until := now.Add(4 * time.Second)
	plan, err := configurationWorkerLaunchPlanFor(input, resources, roles, inert, ownerID(17302), now, until)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.claim.Until.Equal(until) || plan.claim.InertResourceVersion != inert.ResourceVersion || plan.claim.Sources != roles.Sources ||
		plan.claim.Configuration != resources.State.WorkerInputs.Receipt.Configuration || plan.claim.Providers != input.ProviderAuthentication.AuditCredentials ||
		*plan.running.Spec.Replicas != 1 || plan.running.Annotations[configurationLaunchAnnotation] != plan.claim.OperationID {
		t.Fatal("launch replaced original claim/source/input")
	}
	after, _ := json.Marshal(inert)
	if string(original) != string(after) || *inert.Spec.Replicas != 0 {
		t.Fatal("pure launch derivation mutated original workload")
	}
	roles.State.Launch = &plan.claim
	running := plan.running.DeepCopy()
	running.ResourceVersion = "19"
	current := roles.Sources
	current.WorkloadDigest = plan.claim.RunningDigest
	current.ObservedAt, current.FreshUntil = now.Add(time.Second), now.Add(5*time.Second)
	old, ok := configurationWorkerOriginalLaunchSources(current, *running, roles)
	if !ok || old.WorkloadDigest != roles.Sources.WorkloadDigest || old.ObservedAt != current.ObservedAt || old.FreshUntil != current.FreshUntil || !roles.State.Launch.Until.Equal(until) {
		t.Fatal("exact later launch observation rewrote original dates or lost its current interval")
	}
	for _, change := range []func(*apps.Deployment){
		func(v *apps.Deployment) { *v.Spec.Replicas = 2 },
		func(v *apps.Deployment) { v.Spec.Template.Spec.Containers[0].Image = "example.test/foreign:immutable" },
		func(v *apps.Deployment) { v.Annotations[configurationLaunchAnnotation] = ownerID(17303) },
		func(v *apps.Deployment) { v.ResourceVersion = inert.ResourceVersion },
	} {
		bad := running.DeepCopy()
		change(bad)
		if _, ok := configurationWorkerOriginalLaunchSources(current, *bad, roles); ok {
			t.Fatal("journal digest normalized an unqualified actual running body")
		}
	}
}

func TestConfigurationWorkerLaunchPlanRejectsMissingPredecessorsAndExistingAttempt(t *testing.T) {
	for _, mode := range []string{"input receipt", "projection", "existing launch", "changed body", "expired bound", "zero operation", "input operation collision", "resource operation collision", "parent setup collision"} {
		t.Run(mode, func(t *testing.T) {
			input, resources, roles, inert, now := configurationWorkerLaunchPlanFixture(t)
			until, operation := now.Add(4*time.Second), ownerID(17302)
			switch mode {
			case "input receipt":
				resources.State.WorkerInputs.Receipt = nil
			case "projection":
				roles.State.Projection = nil
			case "existing launch":
				roles.State.Launch = &contracts.ConfigurationRuntimeLaunch{}
			case "changed body":
				inert.Spec.Template.Spec.Containers[0].Image = "example.test/foreign:immutable"
			case "expired bound":
				until = now
			case "zero operation":
				operation = ""
			case "input operation collision":
				operation = resources.State.WorkerInputs.OperationID
			case "resource operation collision":
				operation = resources.State.Objects[0].OperationID
			case "parent setup collision":
				operation = resources.State.SetupID
			}
			if _, err := configurationWorkerLaunchPlanFor(input, resources, roles, inert, operation, now, until); err == nil {
				t.Fatal("invalid predecessor selected original launch edit")
			}
		})
	}
}
