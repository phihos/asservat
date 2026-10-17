// Package v1alpha1 contains permission spec wire shapes. Kubernetes object
// metadata is read separately and status is never an acceptance credential.
// Structural CRDs/admission installation are not supplied by these DTOs.
package v1alpha1

type Subject struct {
	Kind   string `json:"kind"`
	Issuer string `json:"issuer"`
	ID     string `json:"id"`
}
type NamespaceRef struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}
type WorkloadRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	UID  string `json:"uid"`
}
type Scope struct {
	ClusterID    string        `json:"clusterID"`
	NamespaceRef NamespaceRef  `json:"namespaceRef"`
	Workloads    []WorkloadRef `json:"workloads,omitempty"`
}
type AccessBindingSpec struct {
	Effect     string              `json:"effect"`
	Subjects   []Subject           `json:"subjects"`
	Roles      []string            `json:"roles"`
	Scope      Scope               `json:"scope"`
	NotAfter   string              `json:"notAfter,omitempty"`
	Reason     string              `json:"reason"`
	Automation *AutomationEnvelope `json:"automation,omitempty"`
}
type AutomationEnvelope struct {
	AllowedActions     []string `json:"allowedActions"`
	MaxLifetimeSeconds int64    `json:"maxLifetimeSeconds"`
	MaxExecutions      int64    `json:"maxExecutions"`
	MaxBytes           int64    `json:"maxBytes"`
	MaxObservedBytes   int64    `json:"maxObservedBytes"`
}
type Selector struct {
	MatchLabels map[string]string `json:"matchLabels"`
}
type Protection struct {
	Mode      string `json:"mode"`
	ReviewRef string `json:"reviewRef"`
	GuardRef  string `json:"guardRef,omitempty"`
}
type MetadataMapping struct {
	Field  string              `json:"field"`
	Key    string              `json:"key"`
	Mode   string              `json:"mode"`
	Issuer string              `json:"issuer"`
	Values map[string][]string `json:"values,omitempty"`
}
type AdmissionParity struct {
	Mode       string `json:"mode"`
	ReviewRef  string `json:"reviewRef"`
	AdapterRef string `json:"adapterRef,omitempty"`
}
type AccessReview struct {
	Check string `json:"check"`
}
type PermissionSourceSpec struct {
	Enabled               bool             `json:"enabled"`
	ClusterID             string           `json:"clusterID"`
	Type                  string           `json:"type"`
	NamespaceSelector     Selector         `json:"namespaceSelector"`
	ExcludedNamespaces    []string         `json:"excludedNamespaces"`
	Role                  string           `json:"role"`
	MaxDecisionAgeSeconds int              `json:"maxDecisionAgeSeconds"`
	MaxNamespaces         int              `json:"maxNamespaces"`
	Protection            *Protection      `json:"protection,omitempty"`
	MetadataMapping       *MetadataMapping `json:"metadataMapping,omitempty"`
	WorkloadSelector      *Selector        `json:"workloadSelector,omitempty"`
	IdentityMappingRef    string           `json:"identityMappingRef,omitempty"`
	AdmissionParity       *AdmissionParity `json:"admissionParity,omitempty"`
	AccessReview          *AccessReview    `json:"accessReview,omitempty"`
}
