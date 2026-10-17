package contracts

import "time"

// OwnerIdentityActivation is public installation provenance, fixed before the
// identity ConfigMap and provider Secret are created. Their UIDs come from the
// independently read original resource journal, never from their own payload.
// None of these fields permits recovery activation or public investigation.
type OwnerIdentityActivation struct {
	Input              OwnerIdentityRoles    `json:"input"`
	RoleRoot           WorkerObjectReference `json:"roleRoot"`
	RoleSetupID        string                `json:"roleSetupID"`
	ResourcesCreatedAt time.Time             `json:"resourcesCreatedAt"`
	ResourcesUntil     time.Time             `json:"resourcesUntil"`
}

// The original resource journal retains a one-use identity projection claim.
// PublicDigest covers the public deployment input and role manifest only; it
// must never contain a digest of passwords or provider credentials.
type OwnerIdentityProjectionClaim struct {
	Credentials   *OwnerIdentityObjectAttempt     `json:"credentials,omitempty"`
	Configuration *OwnerIdentityObjectAttempt     `json:"configuration,omitempty"`
	OperationID   string                          `json:"operationID"`
	PublicDigest  string                          `json:"publicDigest"`
	RoleRoot      WorkerObjectReference           `json:"roleRoot"`
	RoleSetupID   string                          `json:"roleSetupID"`
	ClaimedAt     time.Time                       `json:"claimedAt"`
	Until         time.Time                       `json:"until"`
	Receipt       *OwnerIdentityProjectionReceipt `json:"receipt,omitempty"`
}

type OwnerIdentityProjectionReceipt struct {
	Configuration                WorkerObjectReference `json:"configuration"`
	Credentials                  WorkerObjectReference `json:"credentials"`
	ConfigurationResourceVersion string                `json:"configurationResourceVersion"`
	CredentialsResourceVersion   string                `json:"credentialsResourceVersion"`
	ObservedAt                   time.Time             `json:"observedAt"`
}

// Launch records only the original zero-to-one replica transition, after the
// complete immutable identity projection is acknowledged. An uncertain write
// permits lookup of its exact result, never a second scale operation.
type OwnerIdentityLaunchClaim struct {
	OperationID           string                      `json:"operationID"`
	ProjectionOperationID string                      `json:"projectionOperationID"`
	InertResourceVersion  string                      `json:"inertResourceVersion"`
	InertDigest           string                      `json:"inertDigest"`
	RunningDigest         string                      `json:"runningDigest"`
	ClaimedAt             time.Time                   `json:"claimedAt"`
	Until                 time.Time                   `json:"until"`
	Receipt               *OwnerIdentityLaunchReceipt `json:"receipt,omitempty"`
}

type OwnerIdentityLaunchReceipt struct {
	ResourceVersion string    `json:"resourceVersion"`
	Generation      int64     `json:"generation"`
	ObservedAt      time.Time `json:"observedAt"`
}

// Each field fixes the target kind/name. A positive first CAS is the sole CREATE
// grant; any existing attempt is exact lookup-only, including after expiry.
type OwnerIdentityObjectAttempt struct {
	OperationID string                      `json:"operationID"`
	ClaimedAt   time.Time                   `json:"claimedAt"`
	Until       time.Time                   `json:"until"`
	Receipt     *OwnerIdentityObjectReceipt `json:"receipt,omitempty"`
}
type OwnerIdentityObjectReceipt struct {
	Object          WorkerObjectReference `json:"object"`
	ResourceVersion string                `json:"resourceVersion"`
	ObservedAt      time.Time             `json:"observedAt"`
}
