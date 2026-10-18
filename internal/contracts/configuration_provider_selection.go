package contracts

// ConfigurationProviderSelection is the original public provider choice for
// the fresh installed worker profile. It is bound before resource CREATE; the
// actual worker ServiceAccount UID and exact two-purpose recipe derive later
// from its original receipt. This value grants no provider/runtime authority.
// AuditCredentials names the dedicated one-key configuration audit Secret.
//
// WorkerConfigurationAudit (ADR-204 decision 7) is optional: the download
// worker configuration observer's own audit Transit key, which the two audit
// purposes may then also encrypt and decrypt with. It must equal the
// permission projection's WorkerConfiguration.AuditTransit. The zero value
// leaves the recipe, its digest and the setup artifact unchanged.
//
// ContextDeletionSigning (ADR-205 decision 6) is optional too: the Ed25519
// Transit key ContextDeletionSigningKeyName on the configuration audit mount,
// which the audit-wrap purpose may then also sign with. The provider setup
// creates it and its readback records the public keys to pin. The zero value
// leaves the recipe, its digest and the setup artifact unchanged.
type ConfigurationProviderSelection struct {
	AuthMount                string                `json:"authMount"`
	AuthMountAccessor        string                `json:"authMountAccessor"`
	AuditCredentials         WorkerObjectReference `json:"auditCredentials"`
	WorkerConfigurationAudit OwnerPublicTransit    `json:"workerConfigurationAudit,omitzero"`
	ContextDeletionSigning   OwnerPublicTransit    `json:"contextDeletionSigning,omitzero"`
}
