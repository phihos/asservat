package v1alpha1

// RetentionPolicySpec mirrors the configuration contract. Observed Kubernetes
// metadata and accepted policy/selector protection remain separate facts.
type RetentionScope struct {
	ClusterIDs        []string  `json:"clusterIDs,omitempty"`
	NamespaceSelector *Selector `json:"namespaceSelector,omitempty"`
	WorkloadSelector  *Selector `json:"workloadSelector,omitempty"`
}
type RetentionDurations struct {
	EvidenceSeconds      int64 `json:"evidenceSeconds"`
	CaseMetadataSeconds  int64 `json:"caseMetadataSeconds"`
	AuditMetadataSeconds int64 `json:"auditMetadataSeconds"`
}
type RetentionRule struct {
	Name           string   `json:"name"`
	PrivacyClasses []string `json:"privacyClasses,omitempty"`
	EvidenceTypes  []string `json:"evidenceTypes,omitempty"`
	MaxAgeSeconds  int64    `json:"maxAgeSeconds"`
}
type RetentionPolicySpec struct {
	Scope                 RetentionScope     `json:"scope"`
	PurposeRef            string             `json:"purposeRef"`
	Defaults              RetentionDurations `json:"defaults"`
	Maxima                RetentionDurations `json:"maxima"`
	Rules                 []RetentionRule    `json:"rules"`
	DeletionBudgetSeconds int64              `json:"deletionBudgetSeconds"`
	LegalExceptions       string             `json:"legalExceptions"`
}
