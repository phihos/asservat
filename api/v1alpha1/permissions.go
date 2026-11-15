// Package v1alpha1 contains permission spec wire shapes. Kubernetes object
// metadata is read separately and status is never an acceptance credential.
// Structural CRDs/admission installation are not supplied by these DTOs.
package v1alpha1

type Subject struct {
	Kind   string `json:"kind"`
	Issuer string `json:"issuer,omitempty"`
	ID     string `json:"id"`
}
type WorkloadRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	UID  string `json:"uid,omitempty"`
}

// AccessBindingSpec grants within the binding's own namespace (ADR-329):
// the observing cluster and the namespace UID complete its scope.
type AccessBindingSpec struct {
	Effect     string              `json:"effect"`
	Subjects   []Subject           `json:"subjects"`
	Roles      []string            `json:"roles"`
	Workloads  []WorkloadRef       `json:"workloads,omitempty"`
	NotAfter   string              `json:"notAfter,omitempty"`
	Reason     string              `json:"reason,omitempty"`
	Automation *AutomationEnvelope `json:"automation,omitempty"`
}

// ClusterAccessBindingSpec grants roles in every namespace of its cluster
// matching NamespaceSelector; in the hub cluster Clusters names joined
// clusters or "*" (ADR-335 D14).
type ClusterAccessBindingSpec struct {
	Effect            string    `json:"effect"`
	Subjects          []Subject `json:"subjects"`
	Roles             []string  `json:"roles"`
	NamespaceSelector *Selector `json:"namespaceSelector,omitempty"`
	Clusters          []string  `json:"clusters,omitempty"`
	NotAfter          string    `json:"notAfter,omitempty"`
	Reason            string    `json:"reason,omitempty"`
}
type AutomationEnvelope struct {
	AllowedActions     []string `json:"allowedActions"`
	MaxLifetimeSeconds int64    `json:"maxLifetimeSeconds"`
	MaxExecutions      int64    `json:"maxExecutions"`
	MaxBytes           int64    `json:"maxBytes"`
	MaxObservedBytes   int64    `json:"maxObservedBytes"`
	MaxObservedEvents  int64    `json:"maxObservedEvents,omitempty"`
}
type Selector struct {
	MatchLabels map[string]string `json:"matchLabels"`
}
type Protection struct {
	Mode      string `json:"mode"`
	ReviewRef string `json:"reviewRef,omitempty"`
	GuardRef  string `json:"guardRef,omitempty"`
}
type MetadataMapping struct {
	Field  string              `json:"field"`
	Key    string              `json:"key"`
	Mode   string              `json:"mode"`
	Issuer string              `json:"issuer,omitempty"`
	Values map[string][]string `json:"values,omitempty"`
	Prefix string              `json:"prefix,omitempty"`
}
type AdmissionParity struct {
	Mode       string `json:"mode"`
	ReviewRef  string `json:"reviewRef,omitempty"`
	AdapterRef string `json:"adapterRef,omitempty"`
}
type AccessReview struct {
	Check string `json:"check"`
}
type PermissionSourceSpec struct {
	Enabled            bool             `json:"enabled"`
	Cluster            string           `json:"cluster"`
	Type               string           `json:"type"`
	NamespaceSelector  *Selector        `json:"namespaceSelector,omitempty"`
	ExcludedNamespaces []string         `json:"excludedNamespaces,omitempty"`
	Role               string           `json:"role"`
	Protection         *Protection      `json:"protection,omitempty"`
	MetadataMapping    *MetadataMapping `json:"metadataMapping,omitempty"`
	WorkloadSelector   *Selector        `json:"workloadSelector,omitempty"`
	IdentityMappingRef string           `json:"identityMappingRef,omitempty"`
	AdmissionParity    *AdmissionParity `json:"admissionParity,omitempty"`
	AccessReview       *AccessReview    `json:"accessReview,omitempty"`
}
