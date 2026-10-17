package contracts

// Original completed worker-input provenance in the private role-root input.
// These comparable value fields retain exact equality and legacy zero omission;
// pointers would change meaning after JSON decoding even for identical bytes.
type PublicRuntimeWorkerProviderBinding struct {
	Selection        ConfigurationProviderSelection `json:"selection"`
	InputOperationID string                         `json:"inputOperationID"`
	PublicDigest     string                         `json:"publicDigest"`
	Configuration    WorkerObjectReference          `json:"configuration"`
}
