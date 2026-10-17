package postgres

import cfg "asservat.local/asservat/internal/domain/configuration"

// Fixed internal classifications only. No SQL/provider error, identity,
// credential or source payload enters this error, and callers retain the same
// unavailable sentinel for every failed prerequisite.
type ownerIdentityPrerequisiteError string

func (e ownerIdentityPrerequisiteError) Error() string {
	return "owner identity SQL prerequisite unavailable: " + string(e)
}
func (e ownerIdentityPrerequisiteError) Unwrap() error { return cfg.ErrUnavailable }

type ownerIdentitySQLPrerequisites struct {
	administrator, schema, activation, recovery, sourceCurrent, sourceInterval bool
}

func (p ownerIdentitySQLPrerequisites) failure() error {
	switch {
	case !p.administrator:
		return ownerIdentityPrerequisiteError("administrator")
	case !p.schema:
		return ownerIdentityPrerequisiteError("schema")
	case !p.activation:
		return ownerIdentityPrerequisiteError("activation")
	case !p.recovery:
		return ownerIdentityPrerequisiteError("recovery")
	case !p.sourceCurrent:
		return ownerIdentityPrerequisiteError("source-current")
	case !p.sourceInterval:
		return ownerIdentityPrerequisiteError("source-interval")
	default:
		return nil
	}
}
