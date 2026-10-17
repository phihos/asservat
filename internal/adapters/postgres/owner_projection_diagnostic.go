package postgres

import (
	"context"
	"time"
)

// OwnerProjectionSQLCheck is a closed diagnostic for the actual deciding
// statement or existing compound predicate. It is never authority or SQL data.
type OwnerProjectionSQLCheck uint8

const (
	ownerProjectionSQLUnknown OwnerProjectionSQLCheck = iota

	ownerProjectionSQLEntry
	ownerProjectionSQLLifetime
	ownerProjectionSQLAdmitted
	ownerProjectionSQLBegin
	ownerProjectionSQLFleetLock
	ownerProjectionSQLInstallationLock
	ownerProjectionSQLCurrentBeforeNative
	ownerProjectionSQLCurrentNative
	ownerProjectionSQLCurrentDeadline
	ownerProjectionSQLRoleMaterial
	ownerProjectionSQLRoleProvenance
	ownerProjectionSQLRoleVerification
	ownerProjectionSQLCurrentBeforeEffect
	ownerProjectionSQLApply
	ownerProjectionSQLFinalNative
	ownerProjectionSQLCurrentAfterFinal
	ownerProjectionSQLCommit
	ownerProjectionSQLResult
	// advanceOwnerIdentityRoleOperation steps.
	ownerIdentityRoleSQLAdmitted
	ownerIdentityRoleSQLBegin
	ownerIdentityRoleSQLLocks
	ownerIdentityRoleSQLCurrentBefore
	ownerIdentityRoleSQLAfterLock
	ownerIdentityRoleSQLAttempt
	ownerIdentityRoleSQLClaim
	ownerIdentityRoleSQLCreate
	ownerIdentityRoleSQLExisting
	ownerIdentityRoleSQLVerify
	ownerIdentityRoleSQLAuthenticate
	ownerIdentityRoleSQLAcknowledge
	ownerIdentityRoleSQLFinalRead
	ownerIdentityRoleSQLCurrentAfter
	ownerIdentityRoleSQLCommit
	// FinalizeOwnerProjectionOperation steps.
	ownerProjectionSQLFinalizeAdmit
	ownerProjectionSQLFinalizeBegin
	ownerProjectionSQLFinalizeVersionLock
	ownerProjectionSQLFinalizeInstallationLock
	ownerProjectionSQLFinalizeCurrentBefore
	ownerProjectionSQLFinalizeFirstRead
	ownerProjectionSQLFinalizeRoleClaims
	ownerProjectionSQLFinalizeRoleVerify
	ownerProjectionSQLFinalizeFinalRead
	ownerProjectionSQLFinalizeCurrentAfter
	ownerProjectionSQLFinalizeCommit
	ownerProjectionSQLFinalizeResult
)

func (c OwnerProjectionSQLCheck) String() string {
	switch c {

	case ownerProjectionSQLEntry:
		return "entry"
	case ownerProjectionSQLLifetime:
		return "lifetime"
	case ownerProjectionSQLAdmitted:
		return "admitted"
	case ownerProjectionSQLBegin:
		return "begin"
	case ownerProjectionSQLFleetLock:
		return "fleet-lock"
	case ownerProjectionSQLInstallationLock:
		return "installation-lock"
	case ownerProjectionSQLCurrentBeforeNative:
		return "current-before-native"
	case ownerProjectionSQLCurrentNative:
		return "current-native"
	case ownerProjectionSQLCurrentDeadline:
		return "current-deadline"
	case ownerProjectionSQLRoleMaterial:
		return "role-material"
	case ownerProjectionSQLRoleProvenance:
		return "role-provenance"
	case ownerProjectionSQLRoleVerification:
		return "role-verification"
	case ownerProjectionSQLCurrentBeforeEffect:
		return "current-before-effect"
	case ownerProjectionSQLApply:
		return "apply"
	case ownerProjectionSQLFinalNative:
		return "final-native"
	case ownerProjectionSQLCurrentAfterFinal:
		return "current-after-final"
	case ownerProjectionSQLCommit:
		return "commit"
	case ownerProjectionSQLResult:
		return "result"
	case ownerIdentityRoleSQLAdmitted:
		return "role-admitted"
	case ownerIdentityRoleSQLBegin:
		return "role-begin"
	case ownerIdentityRoleSQLLocks:
		return "role-locks"
	case ownerIdentityRoleSQLCurrentBefore:
		return "role-current-before"
	case ownerIdentityRoleSQLAfterLock:
		return "role-after-lock"
	case ownerIdentityRoleSQLAttempt:
		return "role-attempt"
	case ownerIdentityRoleSQLClaim:
		return "role-claim"
	case ownerIdentityRoleSQLCreate:
		return "role-create"
	case ownerIdentityRoleSQLExisting:
		return "role-existing"
	case ownerIdentityRoleSQLVerify:
		return "role-verify"
	case ownerIdentityRoleSQLAuthenticate:
		return "role-authenticate"
	case ownerIdentityRoleSQLAcknowledge:
		return "role-acknowledge"
	case ownerIdentityRoleSQLFinalRead:
		return "role-final-read"
	case ownerIdentityRoleSQLCurrentAfter:
		return "role-current-after"
	case ownerIdentityRoleSQLCommit:
		return "role-commit"
	case ownerProjectionSQLFinalizeAdmit:
		return "finalize-admit"
	case ownerProjectionSQLFinalizeBegin:
		return "finalize-begin"
	case ownerProjectionSQLFinalizeVersionLock:
		return "finalize-version-lock"
	case ownerProjectionSQLFinalizeInstallationLock:
		return "finalize-installation-lock"
	case ownerProjectionSQLFinalizeCurrentBefore:
		return "finalize-current-before"
	case ownerProjectionSQLFinalizeFirstRead:
		return "finalize-first-read"
	case ownerProjectionSQLFinalizeRoleClaims:
		return "finalize-role-claims"
	case ownerProjectionSQLFinalizeRoleVerify:
		return "finalize-role-verify"
	case ownerProjectionSQLFinalizeFinalRead:
		return "finalize-final-read"
	case ownerProjectionSQLFinalizeCurrentAfter:
		return "finalize-current-after"
	case ownerProjectionSQLFinalizeCommit:
		return "finalize-commit"
	case ownerProjectionSQLFinalizeResult:
		return "finalize-result"
	default:
		return "unknown"
	}
}

type OwnerProjectionSQLFailure struct {
	check  OwnerProjectionSQLCheck
	reason OwnerProjectionSQLReason
	cause  error
}

func (e *OwnerProjectionSQLFailure) Check() OwnerProjectionSQLCheck   { return e.check }
func (e *OwnerProjectionSQLFailure) Reason() OwnerProjectionSQLReason { return e.reason }
func (e *OwnerProjectionSQLFailure) Error() string {
	if e.reason != ownerProjectionSQLReasonUnspecified {
		return "owner projection SQL: " + e.check.String() + ": " + e.reason.String()
	}
	return "owner projection SQL: " + e.check.String()
}
func (e *OwnerProjectionSQLFailure) Unwrap() error { return e.cause }

// FixedStep exposes the closed check and reason to the installer's stop text.
func (e *OwnerProjectionSQLFailure) FixedStep() string { return e.Error() }

// OwnerProjectionSQLReason contains only fixed classifications from the exact
// current-after-final predicate. It never retains a driver error or SQL value.
type OwnerProjectionSQLReason uint8

const (
	ownerProjectionSQLReasonUnspecified OwnerProjectionSQLReason = iota
	ownerProjectionSQLReasonCurrentAdministrator
	ownerProjectionSQLReasonCurrentSchema
	ownerProjectionSQLReasonCurrentActivation
	ownerProjectionSQLReasonCurrentRecovery
	ownerProjectionSQLReasonCurrentSource
	ownerProjectionSQLReasonCurrentInterval
	ownerProjectionSQLReasonCurrentCancelled
	ownerProjectionSQLReasonCurrentQuery
	ownerProjectionSQLReasonCurrentAdministratorIdentity
	ownerProjectionSQLReasonCurrentQueryResult
	ownerProjectionSQLReasonCurrentUnknown
	ownerProjectionSQLReasonContextCancelled
	ownerProjectionSQLReasonContextDeadline
	ownerProjectionSQLReasonContextUnknown
	ownerProjectionSQLReasonDeadline
)

func (r OwnerProjectionSQLReason) String() string {
	names := [...]string{
		"unspecified", "current-administrator", "current-schema", "current-activation",
		"current-recovery", "current-source-current", "current-source-interval",
		"current-cancelled", "current-query", "current-administrator-identity",
		"current-query-result", "current-unknown", "context-cancelled",
		"context-deadline", "context-unknown", "deadline",
	}
	if int(r) >= len(names) {
		return "unknown"
	}
	return names[r]
}

// Preserve the old err != nil || ctx.Err() != nil || !time.Now().Before(until)
// short circuit. Production passes time.Now; no new clock or context read runs.
// Only the concrete existing prerequisite type is accepted, with a closed
// whitelist. Unknown/wrapped errors are not unwrapped, rendered or retained.
func ownerProjectionFinalCurrentReason(ctx context.Context, current error, until time.Time, now func() time.Time) OwnerProjectionSQLReason {
	if current != nil {
		if prerequisite, ok := current.(ownerIdentityPrerequisiteError); ok {
			switch prerequisite {
			case "administrator":
				return ownerProjectionSQLReasonCurrentAdministrator
			case "schema":
				return ownerProjectionSQLReasonCurrentSchema
			case "activation":
				return ownerProjectionSQLReasonCurrentActivation
			case "recovery":
				return ownerProjectionSQLReasonCurrentRecovery
			case "source-current":
				return ownerProjectionSQLReasonCurrentSource
			case "source-interval":
				return ownerProjectionSQLReasonCurrentInterval
			case "cancelled":
				return ownerProjectionSQLReasonCurrentCancelled
			case "query":
				return ownerProjectionSQLReasonCurrentQuery
			case "administrator-identity":
				return ownerProjectionSQLReasonCurrentAdministratorIdentity
			case "query-result":
				return ownerProjectionSQLReasonCurrentQueryResult
			}
		}
		return ownerProjectionSQLReasonCurrentUnknown
	}
	if err := ctx.Err(); err != nil {
		switch err {
		case context.Canceled:
			return ownerProjectionSQLReasonContextCancelled
		case context.DeadlineExceeded:
			return ownerProjectionSQLReasonContextDeadline
		default:
			return ownerProjectionSQLReasonContextUnknown
		}
	}
	if !now().Before(until) {
		return ownerProjectionSQLReasonDeadline
	}
	return ownerProjectionSQLReasonUnspecified
}
