package contracts

import (
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

const BundledInitialProviderSafetyMargin = 10 * time.Second

const BundledInitialProviderIdentityFormat = "asservat-bundled-initial-identity/v1"

// BundledInitialProviderIdentity is private immutable bootstrap provenance from
// an independently checked original setup login. It grants no runtime rights.
// Namespace/account UIDs come from the trusted installer's native observations;
// the provider independently confirms the account UID, names, role and entity.
// The earlier setup expiry remains binding even if a child reports a later TTL.
type BundledInitialProviderIdentity struct {
	Format       string                `json:"format"`
	BackendName  string                `json:"backendName"`
	Namespace    WorkerObjectReference `json:"namespace"`
	SetupAccount WorkerObjectReference `json:"setupAccount"`
	EntityID     string                `json:"entityID"`
	SetupParent  InitialProviderParent `json:"setupParent"`
}

func (v BundledInitialProviderIdentity) Valid() bool {
	if v.Format != BundledInitialProviderIdentityFormat || len(v.BackendName) < 1 || len(v.BackendName) > 30 || len(validation.IsDNS1123Label(v.BackendName)) != 0 || len(validation.IsDNS1123Label(v.Namespace.Name)) != 0 || !routingUUID(v.Namespace.UID) || v.SetupAccount.Name != v.BackendName+"-bootstrap-runner" || !routingUUID(v.SetupAccount.UID) || !routingUUID(v.EntityID) || !bundledInitialASCII(v.SetupParent.Accessor, 128) || v.SetupParent.IssuedAt.IsZero() || v.SetupParent.ExpiresAt.IsZero() || !v.SetupParent.IssuedAt.Before(v.SetupParent.ExpiresAt) || v.SetupParent.ExpiresAt.Sub(v.SetupParent.IssuedAt) > 301*time.Second {
		return false
	}
	return true
}
func (v BundledInitialProviderIdentity) Endpoint() string {
	return "https://" + v.BackendName + "-openbao." + v.Namespace.Name + ".svc:8200"
}
func bundledInitialASCII(s string, max int) bool {
	if len(s) < 1 || len(s) > max {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
func (BundledInitialProviderIdentity) String() string {
	return "protected bundled initial provider identity"
}
func (BundledInitialProviderIdentity) GoString() string {
	return "protected bundled initial provider identity"
}
