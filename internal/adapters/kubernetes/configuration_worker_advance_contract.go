package kubernetes

import (
	"context"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/providerconfig"
	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
)

// ConfigurationWorkerInputProgress describes configuration progress, never
// runtime authority. Pending is a positively read original object awaiting an
// independent receipt phase. Spent means the original opportunity was retained
// without a positive recoverable result; it does not assert that no effect ran.
type ConfigurationWorkerInputProgress uint8

type ConfigurationWorkerInputAdvance struct {
	Progress         ConfigurationWorkerInputProgress
	Snapshot         contracts.InitialRuntimeResourceSnapshot
	receiptUncertain bool
	needsInspection  bool
}

// ConfigurationWorkerOperation is made only by one live private Advance.
// Its zero value grants nothing. The concrete SQL verifier pins the original
// root and calls the named post-lock/effect/final methods, never a caller's
// authority callback. Fields and constructor remain private to this adapter.
// It cannot implement the legacy root/source reader from retained values.
type ConfigurationWorkerOperation struct {
	mu               sync.Mutex
	owner            *ConfigurationWorkerInputs
	ctx              context.Context
	cancel           context.CancelFunc
	until            time.Time
	phase            configurationWorkerPhase
	busy             bool
	changed          chan struct{}
	seed             configurationWorkerSeed
	input            contracts.HubWorkerDeployment
	digest           string
	raw              []byte
	setup            providerconfig.ConfigurationSetupCheck
	native           configurationWorkerNative
	retained         initialRuntimeRetainedResources
	roles            contracts.ConfigurationRuntimeRoleSnapshot
	ownerAccount     core.ServiceAccount
	audit            core.Secret
	mode             configurationWorkerEffect
	observedInput    contracts.ConfigurationWorkerInputReceipt
	result           ConfigurationWorkerInputAdvance
	receiptAttempted bool
	intentUncertain  bool
	effectAttempted  bool
}

type configurationWorkerEffect uint8

type configurationWorkerPhase uint8
