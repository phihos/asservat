package kubernetes

import (
	"asservat.local/asservat/internal/domain/audit"
)

// The protected API/root facts and SQL receipt in this fixture are synthetic.
// It exercises the actual constructors and original handover read graph, not
// native admission or independent database activation.
type rootPinEffectFixture struct {
	record  audit.InitialInstallation
	receipt audit.Receipt
	effects int
}
