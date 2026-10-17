package audit

import (
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

// ClusterBootstrap is the encrypted generation-1 audit record (ADR-193): the
// fleet operator's bootstrap, its acknowledged claim audit, the activated key
// and the staged source it was bound to. It precedes activation and grants
// nothing by itself.
type ClusterBootstrap struct {
	InstallationID, BootstrapID, RootID string
	ClusterID, PeerID, IssuerEpoch      string
	LineageID                           string
	KeyDigest, ClaimAuditDigest         artifact.Digest
	SourceUID                           string
	SourceGeneration                    int64
	ProtectionDigest                    artifact.Digest
	ReservedAt                          time.Time
}

func (r ClusterBootstrap) Valid() bool {
	for _, id := range []string{r.InstallationID, r.BootstrapID, r.RootID, r.ClusterID, r.PeerID, r.IssuerEpoch, r.LineageID, r.SourceUID} {
		if !authorization.UUID(id) {
			return false
		}
	}
	return r.KeyDigest != (artifact.Digest{}) && r.ClaimAuditDigest != (artifact.Digest{}) && r.ProtectionDigest != (artifact.Digest{}) &&
		r.SourceGeneration >= 1 && r.SourceGeneration <= 2147483647 && r.ReservedAt.Year() >= 2020
}

func ClusterBootstrapAuditKey(r ClusterBootstrap) string {
	return "cluster-bootstrap/v1/" + r.InstallationID + "/" + r.BootstrapID + "/record"
}

func (rc Receipt) ValidClusterBootstrap(r ClusterBootstrap) bool {
	return r.Valid() && rc.Key == ClusterBootstrapAuditKey(r) && rc.Version != "null" && identity.Text(rc.Version, 1024) && identity.Text(rc.ETag, 256) && rc.Bytes > 0 && rc.Bytes <= 64<<10 && rc.SHA256 != (artifact.Digest{})
}
