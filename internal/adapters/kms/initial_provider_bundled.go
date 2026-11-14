package kms

import (
	"time"

	"asservat.local/asservat/internal/contracts"
)

// A fixed margin makes the initial issuer and all its children expire before
// their original setup parent. It never extends a provider or installer bound.
const BundledInitialProviderSafetyMargin = contracts.BundledInitialProviderSafetyMargin

func (s *InitialProviderIssuer) expectedEntity() string {
	if s.bundled != nil {
		return s.bundled.EntityID
	}
	return ""
}
func (s *InitialProviderIssuer) withinSetupBound(expiry time.Time) bool {
	return s.bundled == nil || (!expiry.After(s.bundled.SetupParent.ExpiresAt.Add(-BundledInitialProviderSafetyMargin)) && s.now().Before(s.bundled.SetupParent.ExpiresAt))
}
