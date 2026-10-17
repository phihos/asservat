package contracts

// ConfigurationProviderSelection is the original public provider choice for
// the fresh installed worker profile. It is bound before resource CREATE; the
// actual worker ServiceAccount UID and exact two-purpose recipe derive later
// from its original receipt. This value grants no provider/runtime authority.
// AuditCredentials names the dedicated one-key configuration audit Secret.
type ConfigurationProviderSelection struct {
	AuthMount         string                `json:"authMount"`
	AuthMountAccessor string                `json:"authMountAccessor"`
	AuditCredentials  WorkerObjectReference `json:"auditCredentials"`
}
