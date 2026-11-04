package execution

// GoProfileAuthorizationLimit bounds the transient HTTP Authorization value.
// It is never a profile parameter, persisted scope or material digest.
const GoProfileAuthorizationLimit = 4096

func ValidGoProfileAuthorization(value []byte) bool {
	if len(value) == 0 || len(value) > GoProfileAuthorizationLimit {
		return false
	}
	for _, b := range value {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}
