package postgres

import (
	"encoding/json"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5/pgtype"
)

// Read only under the already locked original session. These projections use
// ordinary SELECT privileges and the same digest/closed-shape decoder as
// decodeDownload. SQL's private trigger validators retain their existing ACLs.
// A decoded historical snapshot is not current disclosure or effect authority.
func originalSessionBacking(account pgtype.UUID, raw, digest []byte, deadline pgtype.Timestamptz, session artifact.DownloadSession) (*value.CapacitySessionBacking, error) {
	if !session.Valid() || !deadline.Valid || !deadline.Time.Equal(session.Deadline) {
		return nil, artifact.ErrIntegrity
	}
	b, err := decodeCapacitySessionBacking(raw, digest, account.Valid, session)
	if err != nil || b != nil && b.AccountID != uid(account) {
		return nil, artifact.ErrIntegrity
	}
	return b, nil
}

func effectiveSessionNativeBacking(row custodydb.ReadSessionNativeBackingRow, session artifact.DownloadSession) (custodydb.DownloadNativeBacking, error) {
	b := row.DownloadNativeBacking
	if b.AllocationID != id(session.AllocationID) || b.RootID != id(session.Scope.RootID) {
		return custodydb.DownloadNativeBacking{}, artifact.ErrIntegrity
	}
	original, err := originalSessionBacking(row.CapacityAccountID, row.CapacityBacking, row.CapacityBackingDigest, row.SessionDeadline, session)
	if err != nil {
		return custodydb.DownloadNativeBacking{}, err
	}
	if original != nil {
		p := original.Native
		b.PolicyJson, err = json.Marshal(p)
		if err != nil {
			return custodydb.DownloadNativeBacking{}, artifact.ErrIntegrity
		}
		b.RowsLimit, b.KeysLimit, b.TransitionsPerRow = p.Rows, p.Keys, p.TransitionsPerRow
		b.BackupHorizonSeconds, b.CleanupSeconds = p.BackupHorizonSeconds, p.CleanupSeconds
		b.ValidUntil, b.RetireBy = ts(p.ValidUntil), ts(p.RetireBy)
	}
	// Current charged rows/keys, residual time and overdue state stay untouched.
	return b, nil
}

func effectiveSessionControlBacking(row custodydb.ReadDownloadSessionControlRow, session artifact.DownloadSession) (custodydb.DownloadControlAllocation, error) {
	c := row.DownloadControlAllocation
	if c.ID != id(session.AllocationID) || c.RootID != id(session.Scope.RootID) {
		return custodydb.DownloadControlAllocation{}, artifact.ErrIntegrity
	}
	original, err := originalSessionBacking(row.CapacityAccountID, row.CapacityBacking, row.CapacityBackingDigest, row.SessionDeadline, session)
	if err != nil {
		return custodydb.DownloadControlAllocation{}, err
	}
	if original != nil {
		if c.AuditStoreID != id(original.AuditStoreID) {
			return custodydb.DownloadControlAllocation{}, artifact.ErrIntegrity
		}
		c.ValidUntil, c.AuditWriteUntil = ts(original.ControlUntil), ts(original.AuditWriteUntil)
	}
	return c, nil
}
