package execution

import (
	"crypto/sha256"
	"net/netip"
	"strings"

	"asservat.local/asservat/internal/domain/artifact"
)

const GoProfileTLSRootsLimit = 8 << 10

// GoProfileTLSMaterial is public trust material for one already resolved
// endpoint. Strings and a value digest preserve shallow-copy queue ownership.
// Zero means ordinary HTTP; Valid checks only nonzero TLS material. The adapter
// must additionally parse canonical certificates and verify the actual peer.
type GoProfileTLSMaterial struct {
	RootsPEM    string
	RootsDigest artifact.Digest
	ServerName  string
}

func (m GoProfileTLSMaterial) IsZero() bool { return m == (GoProfileTLSMaterial{}) }
func (m GoProfileTLSMaterial) Valid() bool {
	return len(m.RootsPEM) > 0 && len(m.RootsPEM) <= GoProfileTLSRootsLimit && ValidGoProfileServerName(m.ServerName) && m.RootsDigest == artifact.Digest(sha256.Sum256([]byte(m.RootsPEM)))
}

// ValidGoProfileServerName retains the named endpoint planner's existing DNS/IP
// grammar. It performs no lookup and accepts no address/host override syntax.
func ValidGoProfileServerName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip.Zone() == "" && !ip.Is4In6() && !ip.IsUnspecified() && !ip.IsMulticast()
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
				continue
			}
			if c != '-' || i == 0 || i == len(label)-1 {
				return false
			}
		}
	}
	return true
}
