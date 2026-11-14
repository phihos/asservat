package kubernetes

import (
	"time"

	"asservat.local/asservat/internal/contracts"
	admission "k8s.io/api/admissionregistration/v1"
	core "k8s.io/api/core/v1"
)

// Fixed bootstrap/resource observations for one caller-owned native bracket.
// This value does not include runtime source, SQL, provider or effect authority.
// Callers must already own/join both the bridge and resource lifetimes, preserve
// their original deadline and perform those independent current checks.
type initialRuntimeRetainedResources struct {
	bridge    contracts.InitialRuntimeBridgeSnapshot
	resources contracts.InitialRuntimeResourceSnapshot
	object    *core.Secret
	until     time.Time
	// policy is the closing phase-two policy read of the bracket (ADR-191).
	policy *admission.ValidatingAdmissionPolicy
}
