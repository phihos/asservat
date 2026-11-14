package configuration

// InitialRuntimeBridgeAdministration is derived from the acknowledged initial
// plan and actual inert runtime object receipts. It grants no effect itself.
// The two fixed policy candidates are consumed only by the protected installer.
type InitialRuntimeBridgeAdministration struct {
	Initial      InitialWorkloadAdministration
	Owner        OwnerWorkloadAdministration
	Credentials  string
	OwnerProbe   InitialRuntimeProbe
	SourceProbes []InitialRuntimeSourceProbe
	// RuntimeProbeAccounts are promoted runtime accounts besides the owner's
	// whose configuration probes target sources created after the bridge;
	// each proves its source's own denial at read time (ADR-203: the
	// publisher's cluster catalog read). The bridge proves none of them.
	RuntimeProbeAccounts []string
}

type InitialRuntimeProbe struct {
	ServiceAccount, ServiceAccountUID string
}

type InitialRuntimeSourceProbe struct {
	ConfigMap, ServiceAccount, ServiceAccountUID string
}
