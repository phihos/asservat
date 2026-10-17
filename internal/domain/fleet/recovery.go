package fleet

import "asservat.local/asservat/internal/domain/artifact"

// RecoveryState reports an independently activated installation. Reading current
// configuration never creates it or clears RecoveryBlocked after restoration.
type RecoveryState = artifact.RecoveryProof
