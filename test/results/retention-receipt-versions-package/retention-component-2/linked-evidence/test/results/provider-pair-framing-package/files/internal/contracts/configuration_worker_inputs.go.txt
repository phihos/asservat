package contracts

import "time"

// ConfigurationWorkerInputProvenance pins the original three-role producer
// and the one public ConfigMap attempt before that ConfigMap exists. Its own
// UID is deliberately absent: it can only appear in the parent's independently
// observed receipt, avoiding an input/UID or input/digest self-reference.
type ConfigurationWorkerInputProvenance struct {
	OperationID          string                `json:"operationID"`
	ConfigurationRoot    WorkerObjectReference `json:"configurationRoot"`
	ConfigurationSetupID string                `json:"configurationSetupID"`
	SQLProjection        WorkerObjectReference `json:"sqlProjection"`
}

// One fixed public ConfigMap child in the original resource journal. These
// values carry no credential, secret-payload digest, new provider authority or
// renewed lifetime. Existing claims permit exact observation only; only the
// positively acknowledged original claim can issue the single CREATE.
type ConfigurationWorkerInputClaim struct {
	OperationID          string                           `json:"operationID"`
	PublicDigest         string                           `json:"publicDigest"`
	ConfigurationRoot    WorkerObjectReference            `json:"configurationRoot"`
	ConfigurationSetupID string                           `json:"configurationSetupID"`
	SQLProjection        WorkerObjectReference            `json:"sqlProjection"`
	AuditCredentials     WorkerObjectReference            `json:"auditCredentials"`
	ClaimedAt            time.Time                        `json:"claimedAt"`
	Until                time.Time                        `json:"until"`
	Receipt              *ConfigurationWorkerInputReceipt `json:"receipt,omitempty"`
}

type ConfigurationWorkerInputReceipt struct {
	Configuration   WorkerObjectReference `json:"configuration"`
	ResourceVersion string                `json:"resourceVersion"`
	ObservedAt      time.Time             `json:"observedAt"`
}
