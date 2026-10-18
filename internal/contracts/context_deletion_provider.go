package contracts

// ContextDeletionSigningKeyName is the hub-worker's Ed25519 Transit key for
// context deletion records (ADR-205 decision 6), on the configuration audit
// mount. It signs only asservat-context-deletion+jws records.
func ContextDeletionSigningKeyName(installationID string) string {
	return downloadWorkerName(installationID, "-context-deletion")
}
