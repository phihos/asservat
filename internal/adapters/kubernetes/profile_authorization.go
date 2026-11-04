package kubernetes

import (
	"asservat.local/asservat/internal/contracts"
	"bytes"
)

// ProfileAuthorizationValid binds the whole private map to configured public
// named policies. Changing private bytes never changes an approval digest.
func ProfileAuthorizationValid(endpoints []contracts.RegionalProfileEndpoint, raw []byte) bool {
	names := map[string]bool{}
	for _, e := range endpoints {
		if e.Credential != nil {
			names[e.Name] = true
		}
	}
	if len(names) == 0 {
		return len(raw) == 0
	}
	if len(raw) == 0 || len(raw) > contracts.RegionalProfileAuthorizationMaxBytes {
		return false
	}
	a, err := contracts.DecodeRegionalProfileAuthorization(bytes.NewReader(raw))
	defer a.Clear()
	if err != nil || len(a.Entries) != len(names) {
		return false
	}
	for _, e := range a.Entries {
		if !names[e.Name] {
			return false
		}
	}
	return true
}
