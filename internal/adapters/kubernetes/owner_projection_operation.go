package kubernetes

import (
	"context"
	"sync"

	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
)

// These results describe this one admitted phase, never a reusable effect grant.
type OwnerProjectionAdvanceStatus string

type OwnerProjectionAdvance struct {
	Status   OwnerProjectionAdvanceStatus
	Snapshot contracts.InitialRuntimeResourceSnapshot
}

// The concrete PostgreSQL composition owns the role locks. This finite port is
// separate from legacy role verification; it accepts no source DTO or callback.
type OwnerProjectionOperationVerification interface {
	AdvanceOwnerProjectionOperation(context.Context, *OwnerProjectionOperation) (OwnerProjectionAdvance, error)
}

type ProviderOwnerProjection struct {
	mu              sync.Mutex
	self            *ProviderOwnerProjection
	split, inFlight bool
	executionCaller context.Context
	pending         *ownerProjectionPending
	lastVerified    *ownerProjectionPending
	knownChildren   [2]*contracts.OwnerIdentityObjectReceipt
	projection      *OwnerIdentityProjection
	verification    OwnerProjectionOperationVerification
	receiptAttempts map[ownerProjectionStep]bool // original root serializes all access
}

type ownerProjectionStep uint8

// OwnerProjectionOperation is minted only during one joined original root
// call. Its private native handle owns phase admission and monotonically
// narrowing deadlines; it cannot be constructed from a public journal.
type OwnerProjectionOperation struct {
	self             *OwnerProjectionOperation
	owner            *OwnerIdentityOperation
	projection       *OwnerIdentityProjection
	controller       *ProviderOwnerProjection
	provider         ownerIdentityProviderObservation
	resources        contracts.InitialRuntimeResourceSnapshot
	object           *core.Secret
	input            contracts.OwnerDeployment
	activation       contracts.OwnerIdentityActivation
	data             map[string][]byte
	digest           string
	step             ownerProjectionStep
	fresh            bool
	claimedEffect    bool
	effectDispatched bool
	result           OwnerProjectionAdvanceStatus
	failure          *ownerProjectionDiagnosticSlot
	executionOnly    bool
	pending          *ownerProjectionPending
}
