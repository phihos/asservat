package kms

import (
	"asservat.local/asservat/internal/contracts"
)

// A fixed margin makes the initial issuer and all its children expire before
// their original setup parent. It never extends a provider or installer bound.
const BundledInitialProviderSafetyMargin = contracts.BundledInitialProviderSafetyMargin
