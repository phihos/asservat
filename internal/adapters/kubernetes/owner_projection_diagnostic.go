package kubernetes

import (
	"sync/atomic"
)

type ownerProjectionCheck uint8

const (
	projectionCheckUnknown ownerProjectionCheck = iota
	projectionCheckEnter
	projectionCheckProviderBorrow
	projectionCheckProviderObserve
	projectionCheckInitialNative
	projectionCheckOriginalInput
	projectionCheckProviderMaterial
	projectionCheckProjectionMaterial
	projectionCheckOwnerClaim
	projectionCheckPlan
	projectionCheckSqlOperation
	projectionCheckOuterResult
	projectionCheckOuterBridge
	projectionCheckCurrentBegin
	projectionCheckCurrentNative
	projectionCheckCurrentInput
	projectionCheckCurrentMaterial
	projectionCheckCurrentFinish
	projectionCheckApplyBegin
	projectionCheckApplyProviderBound
	projectionCheckApplyEffect
	projectionCheckApplyFinish
	projectionCheckFinalBegin
	projectionCheckFinalChildren
	projectionCheckFinalNative
	projectionCheckFinalOriginals
	projectionCheckFinalRoles
	projectionCheckFinalLaunch
	projectionCheckFinalInput
	projectionCheckFinalMaterial
	projectionCheckFinalFinish
	projectionCheckResultBegin
	projectionCheckResultEncode
	projectionCheckResultFinish
)

// Only closed codes are retained across the SQL normalizer. Neither original
// errors nor protected values enter this invocation-owned diagnostic slot.
type ownerProjectionDiagnosticSlot struct {
	first atomic.Pointer[ownerProjectionDiagnostic]
}

type ownerProjectionDiagnostic struct {
	check  ownerProjectionCheck
	cause  error
	inner  *ownerProjectionDiagnostic
	native *ownerOperationDiagnostic
	// detail is a closed class and the elapsed time of a wrapped failure.
	detail string
}
