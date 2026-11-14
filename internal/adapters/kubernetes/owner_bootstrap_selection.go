package kubernetes

import (
	"context"
	"sync"

	"asservat.local/asservat/internal/contracts"
)

// This fixed installer owns only original public allocation and its immutable
// child. It cannot create SQL permissions, enroll a peer or read credentials.
// The caller retains the root; Close cancels and joins this producer's calls.
type OwnerBootstrapSelectionProducer struct {
	self                                              *OwnerBootstrapSelectionProducer
	root                                              *OwnerIdentityRoleRoot
	plan                                              contracts.OwnerBootstrapPlan
	ctx                                               context.Context
	cancel                                            context.CancelFunc
	mu                                                sync.Mutex
	closed, busy                                      bool
	joined                                            sync.WaitGroup
	parentAttempted, childAttempted, receiptAttempted bool
	pendingParent                                     *contracts.OwnerBootstrapSelectionClaim
	pendingChild                                      *contracts.OwnerBootstrapObjectAttempt
	pendingReceipt                                    *contracts.OwnerBootstrapObjectReceipt
	observedChild                                     *contracts.OwnerBootstrapObjectReceipt
}
