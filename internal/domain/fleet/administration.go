package fleet

import (
	"crypto/sha256"
	"time"

	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// Administration is one observation of the installation's fleet trust row:
// its generated installation ID and issuer epoch. It assigns no rights.
type Administration struct {
	InstallationID, IssuerEpoch string
	Revision                    identity.Revision
	Suspended                   bool
	ObservedAt, FreshUntil      time.Time
}

func (a Administration) Valid(now time.Time) bool {
	return authorization.UUID(a.InstallationID) && authorization.UUID(a.IssuerEpoch) && a.Revision.Valid() && identity.Fresh(a.ObservedAt, a.FreshUntil, now, 5*time.Second)
}

// InstallationTrust is the fleet trust observation that setup seeds and the
// hub-worker refreshes. Its source is the generated IDs alone, so its
// revision never changes for one installation.
func InstallationTrust(installation, issuerEpoch string, now time.Time) Administration {
	digest := sha256.Sum256([]byte("asservat-installation-trust/v1\x00" + installation + "\x00" + issuerEpoch))
	return Administration{InstallationID: installation, IssuerEpoch: issuerEpoch, Revision: identity.Revision{UID: installation, Generation: 1, Digest: digest}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
}
