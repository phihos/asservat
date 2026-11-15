package fleet

// Actual role resolution and grants are separately supplied by protected SQL
// installation. These bounded names never become ambient or caller-selected
// credentials. A name/OID/incarnation mismatch must deny after restoration.
type ConnectorIdentityRoles struct{ Source, Journal, Acknowledgement, Cleanup, Verifier, Finalizer string }

type ConnectorIdentitySource struct {
	Observation ConnectorCredentialObservation
	Roles       ConnectorIdentityRoles
}
