package integration

import (
	wire "asservat.local/asservat/api/v1alpha1"
)

// The old fixture's exact budget choices, supplied before generated identities
// exist. The product fills the original hub cluster ID and creates the sources.
func installerDeclaredCapacitySpecs() (*wire.EvidenceStoragePoolSpec, *wire.EvidenceBudgetPolicySpec) {
	amount := func(b, o int64) wire.CapacityAmount { return wire.CapacityAmount{Bytes: b, Objects: o} }
	systemObjects, burstObjects := installedCapacityObjectPartitions()
	pool := &wire.EvidenceStoragePoolSpec{StorageProfileRef: "dedicated", Capacity: amount(137438953472, installedPoolCapacityObjects()),
		SafetyHeadroom: amount(17179869184, 10000), SystemReserve: amount(8589934592, systemObjects), SharedBurst: amount(42949672960, burstObjects),
		ProtectedAllocations: []wire.CapacityProtectedAllocation{{BudgetPolicyRef: "applications", WorkloadSlots: 4, ProtectedPerWorkload: amount(17179869184, 10000)}},
		Upload:               wire.CapacityUpload{BytesPerSecond: 134217728, BurstBytes: 16777216}, MaxUploadRequestsPerSecond: 100, CapacityAssurance: "qualifiedReservedBackend"}
	policy := &wire.EvidenceBudgetPolicySpec{PoolRef: "capacity", Scope: wire.CapacityPolicyScope{NamespaceSelector: wire.Selector{MatchLabels: map[string]string{"team": "applications"}}},
		NamespaceEnvelope: wire.CapacityNamespaceEnvelope{MaxWorkloadAccounts: 4, MaxStoredBytes: 111669149696, MaxObjects: 80000},
		Workload: wire.CapacityWorkloadLimits{Protected: amount(17179869184, 10000), HardLimit: amount(34359738368, 20000), ContextReserve: amount(1073741824, 1000),
			Dump:                   wire.CapacityDumpLimits{Burst: 1, MinimumIntervalSeconds: 900, MaxStartsPerRollingHour: 2, MaxInputBytesPerRollingHour: 4294967296},
			MaxConcurrentExpensive: 1, MaxQueuedExpensive: 1, MaxQueueAgeSeconds: 30, Upload: wire.CapacityUpload{BytesPerSecond: 33554432, BurstBytes: 4194304},
			MaxUploadRequestsPerSecond: 20, MaxSpoolBytes: 2147483648, OnFull: "RejectNewExpensive"},
		Node: wire.CapacityNodeLimits{MaxConcurrentExpensive: 2, MaxQueuedExpensive: 10, Upload: wire.CapacityUpload{BytesPerSecond: 67108864, BurstBytes: 8388608},
			MaxSpoolBytes: 4294967296, ImpactProfileRef: "standard-node", UnhealthySamples: 3, SampleIntervalSeconds: 5, RecoveryHealthySeconds: 60}}
	return pool, policy
}
