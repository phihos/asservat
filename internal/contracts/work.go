package contracts

// RunActionWork is the strict internal-work/v1 runAction facet only. Other
// purposes have disjoint payloads and cannot decode through this handler.
type RunActionWork struct {
	SchemaVersion        string           `json:"schemaVersion"`
	Kind                 string           `json:"kind"`
	Purpose              string           `json:"purpose"`
	WorkID               string           `json:"workId"`
	OperationID          string           `json:"operationId"`
	ClusterID            string           `json:"clusterId"`
	IssuerEpoch          string           `json:"issuerEpoch"`
	DeliveryFence        int64            `json:"deliveryFence"`
	Recipient            string           `json:"recipient"`
	IssuedAt             string           `json:"issuedAt"`
	NotAfter             string           `json:"notAfter"`
	ScopeDigest          string           `json:"scopeDigest"`
	ScopeRef             WorkReference    `json:"scopeRef"`
	AuthorityRef         WorkReference    `json:"authorityRef"`
	BudgetRef            WorkReference    `json:"budgetRef"`
	AuditRef             WorkReference    `json:"auditRef"`
	RequiredCapabilities []string         `json:"requiredCapabilities"`
	Target               WorkNodeTarget   `json:"target"`
	Payload              RunActionPayload `json:"payload"`
}
type WorkReference struct {
	ID        string `json:"id"`
	Digest    string `json:"digest"`
	Region    string `json:"region"`
	ExpiresAt string `json:"expiresAt"`
}
type WorkNodeTarget struct {
	PodUID     string `json:"podUID"`
	NodeUID    string `json:"nodeUID"`
	NodeBootID string `json:"nodeBootID"`
}
type RunActionPayload struct {
	CaptureID string `json:"captureId"`
	ActionID  string `json:"actionId"`
	AttemptID string `json:"attemptId"`
}
