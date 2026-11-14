package kubernetes

import (
	"time"
)

// ownerBracket is one open installation bracket of the owner installation
// driver (ADR-316). Its opening proof is one complete native read of the
// protected root: handover proof with the phase-two guard, source guards and
// independent probes, administrator, owner account and Service, accepted
// configuration and both journals. Operations inside the bracket keep their
// own SQL locks, claims, CAS writes, journal re-reads, owner Deployment and
// accepted-configuration reads and deadlines; they no longer repeat the
// complete proof. The closing proof repeats it once after the last operation.
// The bracket never outlives the opening proof's original deadline.
type ownerBracket struct {
	root    *OwnerIdentityRoleRoot
	opening ownerIdentityOperationNative
	until   time.Time
}
