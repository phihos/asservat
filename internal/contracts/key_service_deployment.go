package contracts

import (
	"strings"
)

const KeyServiceDeploymentRoot = "/run/asservat/key-service"

// PublicRuntimeKeyServicePurposes are the key service's logins (ADR-198),
// projected only into its own Secret. ADR-204 adds the acquisition unwrap
// login, which spends download key slots and opens only with Downloads.
func PublicRuntimeKeyServicePurposes() []string {
	return []string{"key-configuration", "key-wrap", "key-verify", "key-acquisition"}
}

// One Recreate replica; a failed process may still close its pools.
const PublicRuntimeRetainedKeyServiceProcesses = 2
const PublicRuntimeKeyServiceRoleConnections = PublicRuntimeRetainedKeyServiceProcesses + 1

func keyServiceName(installationID, suffix string) string {
	return "asservat-" + strings.ReplaceAll(installationID, "-", "") + "-key-service" + suffix
}

// KeyServiceName is the key service's Deployment, Service, account and
// inputs prefix; the other names hold its key material and credentials.
func KeyServiceName(installationID string) string { return keyServiceName(installationID, "") }
