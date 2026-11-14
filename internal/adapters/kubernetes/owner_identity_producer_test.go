package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
)

func ownerIdentityFixtureTimeClaimEqual(a, b contracts.PublicRuntimeRoleClaim) bool {
	return a.OperationID == b.OperationID && a.DatabaseOID == b.DatabaseOID && a.PostmasterAt.Equal(b.PostmasterAt) && a.ClaimedAt.Equal(b.ClaimedAt) && a.Until.Equal(b.Until)
}
