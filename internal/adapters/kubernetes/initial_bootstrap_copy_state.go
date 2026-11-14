package kubernetes

import (
	"time"

	"asservat.local/asservat/internal/contracts"
)

// InitialBootstrapCopyState is an internal observation of fixed public seed
// metadata. No field is a transferable permit or a caller-selected effect.
type InitialBootstrapCopyState struct {
	Claim                             contracts.InitialBootstrapCopyClaim
	PolicyStartedAt, BindingStartedAt *time.Time
	Policy, Binding                   *contracts.InitialBootstrapCopyReceipt
	SQLMarked, ProviderMarked         *contracts.InitialBootstrapCopyReceipt
	SQLRemoved, ProviderRemoved       *contracts.InitialBootstrapCopyReceipt
	CompletedAt                       *time.Time
	ValidUntil                        time.Time
}
