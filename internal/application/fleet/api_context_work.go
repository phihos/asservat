package fleet

import (
	value "asservat.local/asservat/internal/domain/fleet"
	"context"
)

// APIContextWorkTrustReader is fixed to an installed root/cluster/key purpose.
// Incoming work cannot choose a source, endpoint, key URL or trust policy.
type APIContextWorkTrustReader interface {
	APIContextWorkTrust(context.Context) (value.APIContextWorkTrust, error)
}
type APIContextWorkSigner interface {
	SignAPIContextWork(context.Context, value.APIContextWork) ([]byte, error)
}
type APIContextWorkVerifier interface {
	VerifyAPIContextWork(context.Context, []byte, value.APIContextReceiver) (value.AuthenticatedAPIContextWork, error)
}

// APIContextReceiverCheck retains the exact actual peer and process selected by
// one connection. Fresh checks never restore a lost human request owner.
type APIContextReceiverCheck func(context.Context) (value.APIContextReceiver, error)

// Enumeration returns candidates only. Consumers must use exact current route,
// peer TLS and activated registry checks before every connection/attachment.
type APIContextOwnerCandidatesReader interface {
	ReadContextStartOwners(context.Context) (value.APIContextOwnerCandidates, error)
}
