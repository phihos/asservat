package contracts

const HubWorkerProviderInstalledLayout = "asservat-hub-worker-installed/v2"
const OwnerProviderInstalledLayout = "asservat-owner-installed/v2"

// InitialRuntimeLayoutsSupported enumerates complete original installation
// profiles. Recognizing either individual marker never permits a mixed pair,
// upgrades existing receipts, or supplies current runtime authority.
func InitialRuntimeLayoutsSupported(worker, owner string) bool {
	switch worker {
	case "":
		return owner == ""
	case HubWorkerInstalledLayout:
		return owner == "" || owner == OwnerInstalledLayout
	case HubWorkerProviderInstalledLayout:
		return owner == OwnerProviderInstalledLayout
	default:
		return false
	}
}
