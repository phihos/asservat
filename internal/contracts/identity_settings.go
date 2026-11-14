// Package contracts contains versioned wire shapes, never authority decisions.
package contracts

// IdentitySettings is identity.json of the Helm-rendered settings ConfigMap
// (specs/contracts/identity-settings.schema.json).
type IdentitySettings struct {
	SchemaVersion  string                 `json:"schemaVersion"`
	Issuer         string                 `json:"issuer"`
	Clients        []IdentityClient       `json:"clients"`
	GroupsClaim    string                 `json:"groupsClaim,omitempty"`
	UsernameClaim  string                 `json:"usernameClaim,omitempty"`
	RequiredGroups []string               `json:"requiredGroups,omitempty"`
	Administrators IdentityAdministrators `json:"administrators"`
	Approvals      *IdentityApprovals     `json:"approvals,omitempty"`
}

// IdentityAdministrators name installation administrators by group or subject.
type IdentityAdministrators struct {
	Groups   []string `json:"groups,omitempty"`
	Subjects []string `json:"subjects,omitempty"`
}

// IdentityApprovals configures the optional approval step-up and policy
// grant periods.
type IdentityApprovals struct {
	PolicyGrants *PolicyGrantApproval `json:"policyGrants,omitempty"`
	StepUp       *IdentityStepUp      `json:"stepUp,omitempty"`
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

// PolicyGrantApproval configures policy grant periods; omitted values use
// the defaults (90 days, 365 days, 14 days).
type PolicyGrantApproval struct {
	DefaultAgeSeconds    int64 `json:"defaultAgeSeconds,omitempty"`
	MaxAgeSeconds        int64 `json:"maxAgeSeconds,omitempty"`
	RenewalNoticeSeconds int64 `json:"renewalNoticeSeconds,omitempty"`
}
