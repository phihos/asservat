package v1alpha1

// These desired-state shapes mirror the existing storage-pool and budget-policy
// contracts. Neither status nor CapacityAssurance establishes accepted backing.
type CapacityAmount struct {
	Bytes   int64 `json:"bytes"`
	Objects int64 `json:"objects"`
}
type CapacityUpload struct {
	BytesPerSecond int64 `json:"bytesPerSecond"`
	BurstBytes     int64 `json:"burstBytes"`
}
type CapacityProtectedAllocation struct {
	BudgetPolicyRef      string         `json:"budgetPolicyRef"`
	WorkloadSlots        int64          `json:"workloadSlots"`
	ProtectedPerWorkload CapacityAmount `json:"protectedPerWorkload"`
}
type EvidenceStoragePoolSpec struct {
	StorageProfileRef          string                        `json:"storageProfileRef"`
	Capacity                   CapacityAmount                `json:"capacity"`
	SafetyHeadroom             CapacityAmount                `json:"safetyHeadroom"`
	SystemReserve              CapacityAmount                `json:"systemReserve"`
	SharedBurst                CapacityAmount                `json:"sharedBurst"`
	ProtectedAllocations       []CapacityProtectedAllocation `json:"protectedAllocations"`
	Upload                     CapacityUpload                `json:"upload"`
	MaxUploadRequestsPerSecond int64                         `json:"maxUploadRequestsPerSecond"`
	CapacityAssurance          string                        `json:"capacityAssurance"`
}
type CapacityPolicyScope struct {
	ClusterID         string   `json:"clusterID"`
	NamespaceSelector Selector `json:"namespaceSelector"`
}
type CapacityNamespaceEnvelope struct {
	MaxWorkloadAccounts int64 `json:"maxWorkloadAccounts"`
	MaxStoredBytes      int64 `json:"maxStoredBytes"`
	MaxObjects          int64 `json:"maxObjects"`
}
type CapacityDumpLimits struct {
	Burst                       int64  `json:"burst"`
	MinimumIntervalSeconds      int64  `json:"minimumIntervalSeconds"`
	MaxStartsPerRollingHour     int64  `json:"maxStartsPerRollingHour"`
	MaxInputBytesPerRollingHour int64  `json:"maxInputBytesPerRollingHour"`
	MaxProcessesPerEpisode      *int64 `json:"maxProcessesPerEpisode,omitempty"`
}
type CapacityWorkloadLimits struct {
	MaxActiveSources           int64              `json:"maxActiveSources,omitempty"`
	InputBytesPerSecond        int64              `json:"inputBytesPerSecond,omitempty"`
	InputBurstBytes            int64              `json:"inputBurstBytes,omitempty"`
	Protected                  CapacityAmount     `json:"protected"`
	HardLimit                  CapacityAmount     `json:"hardLimit"`
	ContextReserve             CapacityAmount     `json:"contextReserve"`
	Dump                       CapacityDumpLimits `json:"dump"`
	MaxConcurrentExpensive     int64              `json:"maxConcurrentExpensive"`
	MaxQueuedExpensive         int64              `json:"maxQueuedExpensive"`
	MaxQueueAgeSeconds         int64              `json:"maxQueueAgeSeconds"`
	Upload                     CapacityUpload     `json:"upload"`
	MaxUploadRequestsPerSecond int64              `json:"maxUploadRequestsPerSecond"`
	MaxSpoolBytes              int64              `json:"maxSpoolBytes"`
	OnFull                     string             `json:"onFull"`
}
type CapacityNodeLimits struct {
	MaxActiveSources       int64          `json:"maxActiveSources,omitempty"`
	InputBytesPerSecond    int64          `json:"inputBytesPerSecond,omitempty"`
	InputBurstBytes        int64          `json:"inputBurstBytes,omitempty"`
	MaxConcurrentExpensive int64          `json:"maxConcurrentExpensive"`
	MaxQueuedExpensive     int64          `json:"maxQueuedExpensive"`
	Upload                 CapacityUpload `json:"upload"`
	MaxSpoolBytes          int64          `json:"maxSpoolBytes"`
	// ADR-246: optional node ring and frozen-snapshot memory limits; absent
	// means the collector-wide ceiling alone applies (never multiplied).
	MaxRingBytes           int64  `json:"maxRingBytes,omitempty"`
	MaxFrozenBytes         int64  `json:"maxFrozenBytes,omitempty"`
	ImpactProfileRef       string `json:"impactProfileRef"`
	UnhealthySamples       int64  `json:"unhealthySamples"`
	SampleIntervalSeconds  int64  `json:"sampleIntervalSeconds"`
	RecoveryHealthySeconds int64  `json:"recoveryHealthySeconds"`
}
type EvidenceBudgetPolicySpec struct {
	PoolRef           string                    `json:"poolRef"`
	Scope             CapacityPolicyScope       `json:"scope"`
	NamespaceEnvelope CapacityNamespaceEnvelope `json:"namespaceEnvelope"`
	Workload          CapacityWorkloadLimits    `json:"workload"`
	Node              CapacityNodeLimits        `json:"node"`
}
