package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"github.com/jackc/pgx/v5/pgtype"
)

// Current eligibility and effects consume the exact acknowledged object
// receipt. Historical record decoding deliberately remains separate.
func currentAuthorityAudit(row custodydb.AuthorityAudit, root, event pgtype.UUID) bool {
	return root.Valid && event.Valid && row.StreamID == root && row.ID == event &&
		currentAuthorityAuditReceipt(uid(root), uid(event), row.AcknowledgedAt.Valid,
			row.ObjectKey, row.ObjectVersion, row.ObjectEtag, row.ObjectBytes, row.ObjectSha256)
}

// The existing bounded assignment query supplies only these receipt fields;
// duplicating the potentially large audit record per assignment is unnecessary.
func currentAuthorityAuditReceipt(root, event string, acknowledged bool, key, version, etag pgtype.Text, size pgtype.Int8, digest []byte) bool {
	if !acknowledged || !key.Valid || !version.Valid || !etag.Valid || !size.Valid || len(digest) != 32 {
		return false
	}
	var hash artifact.Digest
	copy(hash[:], digest)
	return (audit.Receipt{Key: key.String, Version: version.String, ETag: etag.String,
		Bytes: size.Int64, SHA256: hash}).Valid(root, event)
}
