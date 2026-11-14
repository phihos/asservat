package kubernetes

func initialProviderASCII(s string, limit int) bool {
	if len(s) < 1 || len(s) > limit {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
