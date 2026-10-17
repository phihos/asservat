package fleet

import (
	"context"

	value "asservat.local/asservat/internal/domain/fleet"
)

// AcceptedOwnerAuditEpochReader is a new, unselected purpose-fixed port. An
// implementation must read the actual selected current epoch/full receipt,
// reserve, recovery and unchanged source, preserving the earliest original
// bounds after all blocking reads. Raw OwnerConfigurationReader cannot fill it.
type AcceptedOwnerAuditEpochReader interface {
	ReadAcceptedOwnerAuditEpoch(context.Context) (value.AcceptedOwnerAuditEpochObservation, error)
}

// AdmittedOwnerAuditEpochReader checks exact retained original admission, its
// current non-revocation/receipt and original dependency end plus current
// source/recovery/reserve. It must compare the full actual stored dependency;
// accepting the supplied value alone is forbidden. Head rollover neither fails
// a valid old dependency nor substitutes a newer receipt or end. No production
// implementation/consumer exists yet; this is not an authority callback hook.
type AdmittedOwnerAuditEpochReader interface {
	ReadAdmittedOwnerAuditEpoch(context.Context, value.OwnerAuditEpochDependency) (value.AdmittedOwnerAuditEpochObservation, error)
}
