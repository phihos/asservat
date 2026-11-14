package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
	core "k8s.io/api/core/v1"
)

// ConfigurationWorkerLaunchOperation belongs to exactly one fresh worker2
// launch or historical acknowledgement. Its only constructor is private to
// the original input producer. The concrete SQL adapter cannot replace its
// source/native phases with an interface or caller-created observation.
type ConfigurationWorkerLaunchOperation struct {
	self                                               *ConfigurationWorkerLaunchOperation
	worker                                             *ConfigurationWorkerOperation
	roleObject                                         *core.Secret
	plan                                               configurationWorkerLaunchPlan
	mode                                               configurationWorkerLaunchMode
	observed                                           contracts.ConfigurationRuntimeLaunchReceipt
	result                                             ConfigurationWorkerLaunchAdvance
	intentUncertain, effectAttempted, receiptAttempted bool
}

type ConfigurationWorkerLaunchProgress uint8

type ConfigurationWorkerLaunchAdvance struct {
	Progress                          ConfigurationWorkerLaunchProgress
	Snapshot                          contracts.ConfigurationRuntimeRoleSnapshot
	receiptUncertain, needsInspection bool
}

type configurationWorkerLaunchMode uint8
