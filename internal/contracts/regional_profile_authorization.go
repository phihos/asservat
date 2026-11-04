package contracts

import "io"

const RegionalProfileAuthorizationFile = "profile-authorization.json"
const RegionalProfileAuthorizationFormat = "asservat-profile-authorization/v1"
const RegionalProfileAuthorizationMaxBytes = 384 << 10

// Private installation material. Names select only protected named endpoints;
// no public request chooses a file/key. It is never an approval/public digest.
type RegionalProfileAuthorization struct {
	Format  string                              `json:"format"`
	Entries []RegionalProfileAuthorizationEntry `json:"entries"`
}
type RegionalProfileAuthorizationEntry struct {
	Name          string `json:"name"`
	Authorization []byte `json:"authorization"`
}

func DecodeRegionalProfileAuthorization(r io.Reader) (RegionalProfileAuthorization, error) {
	out, err := decodeClosedRPC[RegionalProfileAuthorization](r, RegionalProfileAuthorizationMaxBytes)
	if err != nil || out.Format != RegionalProfileAuthorizationFormat || len(out.Entries) > 64 {
		return RegionalProfileAuthorization{}, ErrKeyRPC
	}
	seen := map[string]bool{}
	for _, e := range out.Entries {
		if !validProfileAuthorizationWire(e.Authorization) || e.Name == "" || len(e.Name) > 63 || seen[e.Name] {
			out.Clear()
			return RegionalProfileAuthorization{}, ErrKeyRPC
		}
		seen[e.Name] = true
	}
	return out, nil
}
func (a RegionalProfileAuthorization) Clear() {
	for _, e := range a.Entries {
		clear(e.Authorization)
	}
}
func (RegionalProfileAuthorization) String() string {
	return "protected profile authorization projection"
}
func (RegionalProfileAuthorization) GoString() string {
	return "protected profile authorization projection"
}
func (RegionalProfileAuthorizationEntry) String() string {
	return "protected profile authorization entry"
}
func (RegionalProfileAuthorizationEntry) GoString() string {
	return "protected profile authorization entry"
}

// Wire syntax is independent of execution policy. The domain separately
// validates the same finite header grammar before material use.
func validProfileAuthorizationWire(value []byte) bool {
	if len(value) < 1 || len(value) > 4096 {
		return false
	}
	for _, b := range value {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}
