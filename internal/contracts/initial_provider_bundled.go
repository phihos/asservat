package contracts

import (
	"time"
)

const BundledInitialProviderSafetyMargin = 10 * time.Second

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
