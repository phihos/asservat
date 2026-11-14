package kubernetes

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

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
