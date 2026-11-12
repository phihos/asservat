package providerconfig

import "fmt"

// InitialIssuerWarningsAllowed recognizes only the provider's informational
// notice about the two intentional explicit caps. OpenBao emits it whenever
// both a token role and the request set a cap, even when the requested shorter
// cap is fully honored. The caller must still independently verify the actual
// nonrenewing token, policy/entity and original expiry before retaining it.
// All other warnings, changed bounds and additional notices remain refusals.
func InitialIssuerWarningsAllowed(warnings []string, requestedSeconds int64) bool {
	if requestedSeconds < 1 || requestedSeconds > 900 {
		return false
	}
	if len(warnings) == 0 {
		return true
	}
	return len(warnings) == 1 && warnings[0] == fmt.Sprintf("Explicit max TTL specified both during creation call and in role; using the lesser value of %d seconds", requestedSeconds)
}
