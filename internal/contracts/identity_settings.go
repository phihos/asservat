// Package contracts contains versioned wire shapes, never authority decisions.
package contracts

type IdentitySettings struct {
	SchemaVersion          string            `json:"schemaVersion"`
	Revision               int64             `json:"revision"`
	Issuer                 string            `json:"issuer"`
	Clients                []IdentityClient  `json:"clients"`
	EligibleSubjects       []IdentitySubject `json:"eligibleSubjects"`
	EligibleGroups         []string          `json:"eligibleGroups"`
	GroupsAtIssueQualified bool              `json:"groupsAtIssueQualified"`
	GroupMaxAgeSeconds     int               `json:"groupMaxAgeSeconds"`
	// Approvals are the protected installation approval settings (ADR-249).
	// Absent: no step-up is configured, so no approval can be decided.
	Approvals *IdentityApprovals `json:"approvals,omitempty"`
}

// IdentityApprovals configures approval step-up and whether metadata
// packet/syscall recordings also need individual approval (REQ-SYS-002).
type IdentityApprovals struct {
	StepUp                   *IdentityStepUp `json:"stepUp,omitempty"`
	RequireRecordingApproval bool            `json:"requireRecordingApproval,omitempty"`
}

// IdentityStepUp names the IdP acr values accepted as step-up and their
// maximum authentication age.
type IdentityStepUp struct {
	ACRValues     []string `json:"acrValues"`
	MaxAgeSeconds int      `json:"maxAgeSeconds"`
}
type IdentityClient struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	ClassQualified bool   `json:"classQualified"`
}
type IdentitySubject struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}
