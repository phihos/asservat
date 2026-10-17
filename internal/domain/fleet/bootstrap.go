package fleet

import (
	"time"
	"unicode/utf8"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// BootstrapSlot is a durably reserved, current internal issuance instruction.
// Storing its inactive credential does not claim, activate or enroll a peer.
type BootstrapSlot struct {
	ID                    string
	Binding               PeerBinding
	RequestDigest         artifact.Digest
	DeliveryProfile       string
	NotBefore, NotAfter   time.Time
	CheckedAt, ValidUntil time.Time
}

func (s BootstrapSlot) Valid(now time.Time) bool {
	return authorization.UUID(s.ID) && s.Binding.Valid() && s.Binding.Role == ConnectorPeer && s.RequestDigest != (artifact.Digest{}) && identity.Text(s.DeliveryProfile, 64) && s.NotBefore.Year() >= 2020 && s.NotAfter.Year() <= 9999 && !s.NotBefore.After(now) && now.Before(s.NotAfter) && s.NotAfter.After(s.NotBefore) && !s.NotAfter.After(s.NotBefore.Add(5*time.Minute)) && identity.Fresh(s.CheckedAt, s.ValidUntil, now, 5*time.Second) && !s.CheckedAt.Before(s.NotBefore) && !s.ValidUntil.After(s.NotAfter)
}

type BootstrapCredential struct {
	SlotID, DeliveryProfile string
	SecretDigest            artifact.Digest
	Version                 int
}

func (c BootstrapCredential) Matches(s BootstrapSlot) bool {
	return c.SlotID == s.ID && c.DeliveryProfile == s.DeliveryProfile && c.SecretDigest != (artifact.Digest{}) && c.Version == 1
}

type BootstrapRequest struct {
	KeyDigest           artifact.Digest
	DisplayName, Region string
	Authority           EnrollmentAuthority
}

func (r BootstrapRequest) Valid(now time.Time) bool {
	return r.Authority.Valid(now) && r.KeyDigest != (artifact.Digest{}) && identity.Text(r.DisplayName, 512) && utf8.RuneCountInString(r.DisplayName) <= 128 && identity.Text(r.Region, 256) && utf8.RuneCountInString(r.Region) <= 64
}

// BootstrapIntent is internal issuance progress, not a claimable credential.
// Slot refresh only changes CheckedAt/ValidUntil after current authorization;
// all original identity, request, actor, display and expiry facts are immutable.
type BootstrapIntent struct {
	Slot                                     BootstrapSlot
	Actor                                    identity.Principal
	IdentityRevision, AdministrationRevision identity.Revision
	DisplayName, Region                      string
	Credential                               *BootstrapCredential
	Issued                                   bool
}
