package contracts

// RetentionTopologySettings is installation configuration, not request input.
// Local must be explicitly null or contain one exact source; absence is invalid.
type RetentionTopologySettings struct {
	SchemaVersion   string                 `json:"schemaVersion"`
	Revision        int64                  `json:"revision"`
	RootID          string                 `json:"authorityRootID"`
	TargetClusterID string                 `json:"targetClusterID"`
	Hub             RetentionPolicySource  `json:"hub"`
	Local           *RetentionPolicySource `json:"local"`
}
type RetentionPolicySource struct {
	ClusterID           string `json:"clusterID"`
	ControlNamespaceUID string `json:"controlNamespaceUID"`
	ProtectionSHA256    string `json:"protectionSHA256"`
}
