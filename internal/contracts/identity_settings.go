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
