package kubernetes

import wire "asservat.local/asservat/api/v1alpha1"

// Only synthetic, schema-valid objects for nonpersistent dry-run denial. No
// accepted capacity or backend qualification is manufactured by these values.
func capacityProbeSpec(kind, cluster string) any {
	amount := func(n int64) wire.CapacityAmount { return wire.CapacityAmount{Bytes: n, Objects: n} }
	upload := wire.CapacityUpload{BytesPerSecond: 4096, BurstBytes: 4096}
	if kind == "EvidenceStoragePool" {
		return wire.EvidenceStoragePoolSpec{StorageProfileRef: "synthetic-capacity-probe", Capacity: amount(128), SafetyHeadroom: amount(16), SystemReserve: amount(8), SharedBurst: amount(40), ProtectedAllocations: []wire.CapacityProtectedAllocation{{BudgetPolicyRef: "synthetic-capacity-probe", WorkloadSlots: 4, ProtectedPerWorkload: amount(16)}}, Upload: upload, MaxUploadRequestsPerSecond: 10, CapacityAssurance: "qualifiedReservedBackend"}
	}
	return wire.EvidenceBudgetPolicySpec{PoolRef: "synthetic-capacity-probe", Scope: wire.CapacityPolicyScope{ClusterID: cluster, NamespaceSelector: wire.Selector{MatchLabels: map[string]string{"asservat.io/capacity-probe": "true"}}}, NamespaceEnvelope: wire.CapacityNamespaceEnvelope{MaxWorkloadAccounts: 4, MaxStoredBytes: 64, MaxObjects: 64}, Workload: wire.CapacityWorkloadLimits{Protected: amount(16), HardLimit: amount(32), ContextReserve: amount(1), Dump: wire.CapacityDumpLimits{Burst: 1, MinimumIntervalSeconds: 60, MaxStartsPerRollingHour: 10, MaxInputBytesPerRollingHour: 1 << 20}, MaxConcurrentExpensive: 1, MaxQueuedExpensive: 1, MaxQueueAgeSeconds: 30, Upload: upload, MaxUploadRequestsPerSecond: 10, MaxSpoolBytes: 4096, OnFull: "RejectNewExpensive"}, Node: wire.CapacityNodeLimits{MaxConcurrentExpensive: 1, MaxQueuedExpensive: 2, Upload: upload, MaxSpoolBytes: 4096, ImpactProfileRef: "synthetic-capacity-probe", UnhealthySamples: 3, SampleIntervalSeconds: 5, RecoveryHealthySeconds: 60}}
}
