package contracts

import (
	"io"
	"time"
)

const SmallSeaweedBindingFormat = "asservat-small-seaweed-binding/v1"
const SmallSeaweedBindingFile = "binding.json"
const SmallSeaweedBindingMaxBytes = 8 << 10

// Request contains only the original persisted bootstrap operation and bound.
// The adapter obtains all backend identities from its exact native reads.
type SmallSeaweedBindingRequest struct {
	InstallationID  string    `json:"installationID"`
	RequestID       string    `json:"requestID"`
	Bucket          string    `json:"bucket"`
	StorageUseUntil time.Time `json:"storageUseUntil"`
}

// Binding is public installation intent, not a credential, effect receipt or
// runtime authority. Initialization.Pending is its sole monotonic state bit.
type SmallSeaweedBinding struct {
	Format          string                      `json:"format"`
	RequestID       string                      `json:"requestID"`
	Initialization  SeaweedBucketInitialization `json:"initialization"`
	IAMSecretUID    string                      `json:"iamSecretUID"`
	StorageUseUntil time.Time                   `json:"storageUseUntil"`
}

type SmallSeaweedBindingReceipt struct {
	Binding         SmallSeaweedBinding
	ConfigMap       WorkerObjectReference
	ResourceVersion string
}

func DecodeSmallSeaweedBinding(r io.Reader) (SmallSeaweedBinding, error) {
	return decodeClosedRPC[SmallSeaweedBinding](r, SmallSeaweedBindingMaxBytes)
}
