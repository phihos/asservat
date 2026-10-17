package audit

import (
	"time"
	"unicode/utf8"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// BootstrapIssue is a frozen issuance intent with a verified credential digest.
// It does not assert that the final SQL activation or delivery has completed.
type BootstrapIssue struct {
	ID                                       string
	Binding                                  fleet.PeerBinding
	RequestDigest                            artifact.Digest
	Actor                                    identity.Principal
	IdentityRevision, AdministrationRevision identity.Revision
	DisplayName, Region, DeliveryProfile     string
	NotBefore, NotAfter                      time.Time
	Credential                               fleet.BootstrapCredential
}

func (r BootstrapIssue) Valid() bool {
	s := fleet.BootstrapSlot{ID: r.ID, Binding: r.Binding, RequestDigest: r.RequestDigest, DeliveryProfile: r.DeliveryProfile, NotBefore: r.NotBefore, NotAfter: r.NotAfter, CheckedAt: r.NotBefore, ValidUntil: identity.Earlier(r.NotAfter, r.NotBefore.Add(5*time.Second))}
	return s.Valid(r.NotBefore) && r.Actor.Valid() && r.IdentityRevision.Valid() && r.AdministrationRevision.Valid() && identity.Text(r.DisplayName, 512) && utf8.RuneCountInString(r.DisplayName) <= 128 && identity.Text(r.Region, 256) && utf8.RuneCountInString(r.Region) <= 64 && r.Credential.Matches(s)
}
func BootstrapIssueKey(installation, bootstrap string) string {
	return "bootstrap-issue/v1/" + installation + "/" + bootstrap + "/record"
}
func (r Receipt) ValidBootstrapIssue(installation, bootstrap string) bool {
	return authorization.UUID(installation) && authorization.UUID(bootstrap) && r.Key == BootstrapIssueKey(installation, bootstrap) && (r.Version != "null" && identity.Text(r.Version, 1024)) && identity.Text(r.ETag, 256) && r.Bytes > 0 && r.Bytes <= 128<<10 && r.SHA256 != (artifact.Digest{})
}
