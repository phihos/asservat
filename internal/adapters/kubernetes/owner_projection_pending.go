package kubernetes

import (
	"context"

	"asservat.local/asservat/internal/contracts"
)

type ownerProjectionPending struct {
	controller               *ProviderOwnerProjection
	caller                   context.Context
	original                 ownerIdentityOperationNative
	resources                contracts.InitialRuntimeResourceSnapshot
	roles                    contracts.OwnerIdentityRoleSnapshot
	children                 [2]*contracts.OwnerIdentityObjectReceipt
	step                     ownerProjectionStep
	journalBefore            string
	semanticVersion          int64
	journalUnknown, consumed bool
}
