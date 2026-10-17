package kubernetes

import (
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	fleet "asservat.local/asservat/internal/domain/fleet"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

func providerResourceFixture(t *testing.T) (*InitialRuntimeResources, contracts.InitialRuntimeResourceState) {
	t.Helper()
	s, v := initialRuntimeResourceFixture(t)
	s.workerLayout, s.ownerLayout = contracts.HubWorkerProviderInstalledLayout, contracts.OwnerProviderInstalledLayout
	s.workerProvider = &contracts.ConfigurationProviderSelection{AuthMount: "configuration-auth", AuthMountAccessor: "auth_configuration_original", AuditCredentials: contracts.WorkerObjectReference{Name: s.names.WorkerProviders, UID: ownerID(14901)}}
	s.ownerProvider = &contracts.OwnerProviderSelection{AuthMount: "owner-auth", AuthMountAccessor: "auth_owner_original", AuditCredentials: contracts.WorkerObjectReference{Name: contracts.OwnerProviderAuditSecretName(s.initial.InstallationID), UID: ownerID(14902)}}
	v.WorkerLayout, v.OwnerLayout = s.workerLayout, s.ownerLayout
	worker, owner := *s.workerProvider, *s.ownerProvider
	v.WorkerProvider, v.OwnerProvider = &worker, &owner
	for i := range v.Objects {
		obj, err := s.object(v, i)
		if err != nil {
			t.Fatal(err)
		}
		v.Objects[i].TemplateDigest = preparationDigest(obj.object)
	}
	return s, v
}

func TestProviderResourcesFixCompletePairOriginalScopeAndCandidateLimit(t *testing.T) {
	s, state := providerResourceFixture(t)
	if !s.valid(state) {
		t.Fatal("complete fresh profile rejected")
	}
	obj, err := s.object(state, 14)
	if err != nil {
		t.Fatal(err)
	}
	var pool contracts.OwnerConfiguration
	if json.Unmarshal([]byte(obj.object.(*core.ConfigMap).Data["owner-pool.json"]), &pool) != nil || pool.NativeCandidateLimit != fleet.OwnerRegistrationsPerPool || pool.NativePort != contracts.OwnerInstalledNativePort || pool.NativeBootstrap != fleet.OwnerBootstrapProfile {
		t.Fatal("original v2 source lacks exact finite observation candidate bound")
	}
	legacy, old := initialRuntimeResourceFixture(t)
	before, _ := json.Marshal(old)
	if s.valid(old) || legacy.valid(state) {
		t.Fatal("original resource receipts adopted across layouts")
	}
	for _, change := range []func(*contracts.InitialRuntimeResourceState){
		func(v *contracts.InitialRuntimeResourceState) { v.WorkerLayout = contracts.HubWorkerInstalledLayout },
		func(v *contracts.InitialRuntimeResourceState) { v.OwnerLayout = contracts.OwnerInstalledLayout },
		func(v *contracts.InitialRuntimeResourceState) { v.WorkerProvider = nil },
		func(v *contracts.InitialRuntimeResourceState) { v.OwnerProvider = nil },
		func(v *contracts.InitialRuntimeResourceState) { v.OwnerProvider.AuthMountAccessor = "replaced" },
		func(v *contracts.InitialRuntimeResourceState) { v.WorkerProvider.AuditCredentials.UID = ownerID(14999) },
		func(v *contracts.InitialRuntimeResourceState) {
			v.OwnerProvider.AuditCredentials.UID = v.Objects[0].Receipt.UID
		},
	} {
		raw, _ := json.Marshal(state)
		var changed contracts.InitialRuntimeResourceState
		if json.Unmarshal(raw, &changed) != nil {
			t.Fatal("fixture")
		}
		change(&changed)
		if s.valid(changed) {
			t.Fatal("changed/mixed provider scope adopted original receipts")
		}
	}
	after, _ := json.Marshal(old)
	if string(before) != string(after) || !legacy.valid(old) {
		t.Fatal("fresh profile mutated legacy receipt bytes")
	}
}

func TestProviderSecretPlaceholderPinsIdentityWithoutAssertingMaterial(t *testing.T) {
	ref := contracts.WorkerObjectReference{Name: contracts.OwnerProviderAuditSecretName(ownerID(1)), UID: ownerID(149)}
	obj := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: ref.Name, Namespace: "hub", UID: types.UID(ref.UID), ResourceVersion: "1"}, Type: core.SecretTypeOpaque}
	if !initialProviderSecretIdentity(obj, "hub", ref, contracts.OwnerProviderAuditCredentialFile) {
		t.Fatal("original empty identity rejected")
	}
	// Shape-only identity validation deliberately does not assert usability.
	// The material decoder/publication/runtime checks must still reject empty
	// content. No synthetic usable credential is introduced at this stage.
	obj.Data = map[string][]byte{contracts.OwnerProviderAuditCredentialFile: nil}
	if !initialProviderSecretIdentity(obj, "hub", ref, contracts.OwnerProviderAuditCredentialFile) {
		t.Fatal("empty original fixed key cannot represent pending material")
	}
	for _, mutate := range []func(*core.Secret){
		func(v *core.Secret) { v.UID = types.UID(ownerID(150)) },
		func(v *core.Secret) { v.Name = "another" },
		func(v *core.Secret) { v.Kind = "ConfigMap" },
		func(v *core.Secret) { v.APIVersion = "unknown/v1" },
		func(v *core.Secret) { v.Immutable = ptr.To(true) },
		func(v *core.Secret) { v.Data["another-purpose"] = []byte("unusable") },
		func(v *core.Secret) { v.Data = map[string][]byte{"another-purpose": nil} },
		func(v *core.Secret) { now := meta.NewTime(time.Now()); v.DeletionTimestamp = &now },
	} {
		changed := obj.DeepCopy()
		mutate(changed)
		if initialProviderSecretIdentity(*changed, "hub", ref, contracts.OwnerProviderAuditCredentialFile) {
			t.Fatal("changed or ambiguous original provider Secret accepted")
		}
	}
}
