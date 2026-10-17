package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"bytes"
)

// Validate the complete original acknowledgement before creating or replaying a
// claimable bootstrap. The caller already holds this row and checks its audit
// record digest and original authority; this adds no lookup or authority interval.
func currentBootstrapIntentAudit(row custodydb.FleetBootstrapIntent) bool {
	if !row.AuditAcknowledgedAt.Valid || !row.AuditObjectKey.Valid || !row.AuditObjectVersion.Valid || !row.AuditObjectEtag.Valid || !row.AuditObjectBytes.Valid || len(row.AuditObjectSha256) != 32 {
		return false
	}
	receipt := audit.Receipt{Key: row.AuditObjectKey.String, Version: row.AuditObjectVersion.String, ETag: row.AuditObjectEtag.String, Bytes: row.AuditObjectBytes.Int64}
	copy(receipt.SHA256[:], row.AuditObjectSha256)
	return receipt.ValidBootstrapIssue(uid(row.InstallationID), uid(row.ID))
}

// The issued row retains a minimized immutable projection of the audit checked
// at activation. Current claim/signing paths must reject old unversioned or
// mismatched origins too. Historical record decoding remains separate.
func currentIssuedBootstrapAudit(row custodydb.FleetBootstrap) bool {
	return authorization.UUID(uid(row.InstallationID)) && authorization.UUID(uid(row.IssueAuditID)) &&
		row.IssueAuditKey == audit.BootstrapIssueKey(uid(row.InstallationID), uid(row.IssueAuditID)) &&
		identity.Text(row.IssueAuditVersion, 1024) && row.IssueAuditVersion != "null" &&
		len(row.IssueAuthorityDigest) == 32 && !bytes.Equal(row.IssueAuthorityDigest, make([]byte, 32)) &&
		len(row.IssueAuditSha256) == 32 && !bytes.Equal(row.IssueAuditSha256, make([]byte, 32))
}
