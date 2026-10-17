package v1alpha1

// LocalStartSpec is the first narrow CapacityReservation profile. It contains
// one immutable prepaid effect and references, never evidence or an argv.
type LocalStartSpec struct {
	ExecutorPodUID     string `json:"executorPodUID,omitempty"`
	ExecutorAccountUID string `json:"executorAccountUID,omitempty"`
	Profile            string `json:"profile"`
	OperationID        string `json:"operationID"`
	CaptureID          string `json:"captureID"`
	ActionID           string `json:"actionID"`
	AttemptID          string `json:"attemptID"`
	ClusterID          string `json:"clusterID"`
	IssuerEpoch        string `json:"issuerEpoch"`
	PodUID             string `json:"podUID"`
	NodeUID            string `json:"nodeUID,omitempty"`
	NodeBootID         string `json:"nodeBootID,omitempty"`
	CollectorEpoch     string `json:"collectorEpoch"`
	ScopeDigest        string `json:"scopeDigest"`
	AuthorityDigest    string `json:"authorityDigest"`
	BudgetDigest       string `json:"budgetDigest"`
	AuditDigest        string `json:"auditDigest"`
	NativeBytes        int64  `json:"nativeBytes"`
	NotBefore          string `json:"notBefore"`
	NotAfter           string `json:"notAfter"`
}

type LocalStartStatus struct {
	Phase       string `json:"phase"`
	CommittedAt string `json:"committedAt,omitempty"`
}
