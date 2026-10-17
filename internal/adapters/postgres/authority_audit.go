package postgres

import (
	"bytes"
	"context"
	"encoding/json"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/audit"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgtype"
)

func decodeAuthority(row custodydb.AuthorityAudit) (audit.AuthorityRecord, error) {
	var r audit.AuthorityRecord
	if len(row.Record) > 8<<20 {
		return r, cfg.ErrLimit
	}
	decoder := json.NewDecoder(bytes.NewReader(row.Record))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil || !r.Valid() || r.ID != uid(row.ID) || r.RootID != uid(row.StreamID) || r.Epoch != uid(row.Epoch) || r.Sequence != row.Sequence || r.Kind != row.EventKind || !bytes.Equal(digest(r), row.EventDigest) {
		return audit.AuthorityRecord{}, cfg.ErrUnavailable
	}
	return r, nil
}
func (p *Permissions) PendingAuthorityAudits(ctx context.Context) ([]audit.AuthorityRecord, error) {
	var out []audit.AuthorityRecord
	err := p.transaction(ctx, func(q *custodydb.Queries) error {
		rows, err := q.ListAuthorityAudit(ctx, id(p.root))
		if err != nil {
			return err
		}
		out = nil
		for _, row := range rows {
			r, err := decodeAuthority(row)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (p *Permissions) AcknowledgeAuthorityAudit(ctx context.Context, r audit.AuthorityRecord, receipt audit.Receipt) error {
	if !r.Valid() || r.RootID != p.root || !receipt.Valid(r.RootID, r.ID) {
		return cfg.ErrInvalid
	}
	return p.transaction(ctx, func(q *custodydb.Queries) error {
		// Same root-first order as acceptance; no object-store I/O under these locks.
		if _, err := q.LockPermissionStream(ctx, id(p.root)); err != nil {
			return err
		}
		row, err := q.LockAuthorityAudit(ctx, id(r.ID))
		if err != nil {
			return err
		}
		frozen, err := decodeAuthority(row)
		if err != nil {
			return err
		}
		if !bytes.Equal(digest(frozen), digest(r)) {
			return cfg.ErrChanged
		}
		if row.AcknowledgedAt.Valid {
			if row.ObjectKey.String != receipt.Key || row.ObjectVersion.String != receipt.Version || row.ObjectEtag.String != receipt.ETag || row.ObjectBytes.Int64 != receipt.Bytes || !bytes.Equal(row.ObjectSha256, receipt.SHA256[:]) {
				return cfg.ErrChanged
			}
			return nil
		}
		changed, err := q.AcknowledgeAuthorityAudit(ctx, custodydb.AcknowledgeAuthorityAuditParams{ID: row.ID, ObjectKey: pgtype.Text{String: receipt.Key, Valid: true}, ObjectVersion: pgtype.Text{String: receipt.Version, Valid: true}, ObjectEtag: pgtype.Text{String: receipt.ETag, Valid: true}, ObjectBytes: pgtype.Int8{Int64: receipt.Bytes, Valid: true}, ObjectSha256: receipt.SHA256[:]})
		if err != nil {
			return err
		}
		if changed != 1 {
			return cfg.ErrChanged
		}
		return nil
	})
}
