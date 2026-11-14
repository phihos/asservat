package kubernetes

import (
	"encoding/json"
	"strings"

	"asservat.local/asservat/internal/contracts"
)

func bundledInboxCandidate(marker string) map[string][]byte {
	b, _ := json.Marshal(contracts.OwnerStorageCredential{AccessKeyID: "ASV" + strings.Repeat(marker, 40), SecretAccessKey: strings.Repeat(marker, 64)})
	return map[string][]byte{contracts.InstallerInboxPhase: []byte("3"), contracts.InstallerInboxAuditCredential: b}
}
