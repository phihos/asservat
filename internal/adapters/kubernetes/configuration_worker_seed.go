package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
)

// configurationWorkerSeed is untrusted input for a read-only provider
// inspection. It deliberately contains no native observation or authority
// interval. Only the later actual SQL/native verification can accept it.
// Its endpoints/CA/token are never read from either journal.
type configurationWorkerSeed struct {
	resources            contracts.InitialRuntimeResourceSnapshot
	roleState            contracts.ConfigurationRuntimeRoleState
	roleUID, roleVersion string
}
