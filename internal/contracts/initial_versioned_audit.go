package contracts

// New installations select required immutable audit versions intrinsically.
// Existing persisted profiles keep their original receipt and replay contract.
const InitialBootstrapVersionedAuditFormat = "asservat-initial-bootstrap/v4"
const InitialPreparationVersionedAuditServicesFormat = "asservat-initial-preparation-services/v2"
const InitialInstallerVersionedAuditFormat = "asservat-initial-installer/v2"

func InitialBootstrapHasCopyClosure(format string) bool {
	return format == InitialBootstrapCopyClosureFormat || format == InitialBootstrapVersionedAuditFormat
}

// InitialInstallerFormatForServices is a closed wire mapping. Unknown input
// never chooses a version-optional fallback. It supplies no runtime authority.
func InitialInstallerFormatForServices(format string) string {
	switch format {
	case InitialPreparationServicesFormat:
		return InitialInstallerFormat
	case InitialPreparationVersionedAuditServicesFormat:
		return InitialInstallerVersionedAuditFormat
	default:
		return ""
	}
}
func InitialInstallerFormatSupported(format string) bool {
	return format == InitialInstallerFormat || format == InitialInstallerVersionedAuditFormat
}
