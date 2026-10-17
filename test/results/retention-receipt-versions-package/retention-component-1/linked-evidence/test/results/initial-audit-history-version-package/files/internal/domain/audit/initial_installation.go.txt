package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// InitialInstallation records an attempt, never a claim that activation completed.
// The immutable attempt is retained outside SQL before the first activation.
type InitialInstallation struct {
	Scope fleet.InstallationWitnessScope
	Claim fleet.InitialActivationClaim
}

func (r InitialInstallation) Valid() bool { return r.Scope.Valid() && r.Claim.Valid() }
func InitialInstallationKey(installation, claim string) string {
	return "initial-installation/v1/" + installation + "/" + claim + "/record"
}
func (r Receipt) ValidInitialInstallation(installation, claim string) bool {
	return authorization.UUID(installation) && authorization.UUID(claim) && r.Key == InitialInstallationKey(installation, claim) && (identity.Text(r.Version, 1024) && r.Version != "null") && identity.Text(r.ETag, 256) && r.Bytes > 0 && r.Bytes <= 128<<10 && r.SHA256 != (artifact.Digest{})
}
