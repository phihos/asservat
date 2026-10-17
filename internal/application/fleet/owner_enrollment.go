package fleet

import (
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
)

// The private ingress supplies a fresh owned buffer for this request's token.
// The attester clears it; adapters must not return a shared backing array.
type OwnerPodToken interface {
	ReadOwnerPodToken(context.Context) ([]byte, error)
}

// Enrollment requires the accepted configuration reader, qualified workload
// protection and actual Pod token/CSR proof before durable reservation/signing.
type OwnerEnrollmentProofReader interface {
	ReadOwnerEnrollmentProof(context.Context, value.OwnerEnrollmentRequest) (value.OwnerEnrollmentProof, error)
}
