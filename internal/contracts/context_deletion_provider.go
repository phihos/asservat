package contracts

// ContextDeletionSigningKeyName is the hub-worker's Ed25519 Transit key for
// context deletion records (ADR-205 decision 6), on the configuration audit
// mount. It signs only asservat-context-deletion+jws records.
func ContextDeletionSigningKeyName(installationID string) string {
	return downloadWorkerName(installationID, "-context-deletion")
}

// EvidenceDeleteCredentialName is the immutable Secret holding the operator's
// evidence list-and-delete credential (ADR-205 decision 4), under the key
// EvidenceDeleteCredentialFile; only the hub-worker Pod projects it.
func EvidenceDeleteCredentialName(installationID string) string {
	return downloadWorkerName(installationID, "-evidence-delete")
}

const EvidenceDeleteCredentialFile = "evidence-delete.json"
