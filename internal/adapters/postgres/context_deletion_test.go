package postgres

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/privacy"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestContextDeletionRecordRejectsRelationalOrCanonicalSubstitution(t *testing.T) {
	key := "10000000-0000-4000-8000-000000000001"
	now := time.Now().UTC().Truncate(time.Microsecond)
	expected := value.ContextDeletionCheckpoint{RootID: key, CaptureID: key, StoreID: key, InstallationID: key, IssuerEpoch: key, Location: artifact.Location{ClusterID: key, ArtifactID: key, AttemptID: key}, RegistrationDigest: artifact.Digest{1}, WriterDigest: artifact.Digest{2}, PostmasterAt: now.Add(-time.Hour), DatabaseOID: 123, PurgeFence: 1, PurgedAt: now}
	body, _ := json.Marshal(expected)
	sum := app.ContextDeletionDigest(expected)
	row := custodydb.ContextDeletionCheckpoint{RootID: id(key), CaptureID: id(key), AttemptID: id(key), StoreID: id(key), InstallationID: id(key), IssuerEpoch: id(key), RegistrationDigest: expected.RegistrationDigest[:], WriterDigest: expected.WriterDigest[:], RecordDigest: sum[:], RecordJson: body, PostmasterAt: ts(expected.PostmasterAt), DatabaseOid: pgtype.Uint32{Uint32: expected.DatabaseOID, Valid: true}, PurgeFence: 1, PurgedAt: ts(now)}
	if got, err := deletionRecord(row); err != nil || got != expected {
		t.Fatal("exact checkpoint did not decode", err)
	}
	for name, change := range map[string]func(*custodydb.ContextDeletionCheckpoint){
		"database":      func(r *custodydb.ContextDeletionCheckpoint) { r.DatabaseOid.Uint32++ },
		"postmaster":    func(r *custodydb.ContextDeletionCheckpoint) { r.PostmasterAt = ts(now) },
		"fence":         func(r *custodydb.ContextDeletionCheckpoint) { r.PurgeFence++ },
		"record-digest": func(r *custodydb.ContextDeletionCheckpoint) { r.RecordDigest = []byte{1} },
		"writer":        func(r *custodydb.ContextDeletionCheckpoint) { r.WriterDigest = []byte{1} },
		"trailing-json": func(r *custodydb.ContextDeletionCheckpoint) {
			r.RecordJson = append(bytes.Clone(body), []byte(" {}")...)
		},
		"unknown-field": func(r *custodydb.ContextDeletionCheckpoint) {
			r.RecordJson = append([]byte(`{"Unknown":true,`), body[1:]...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := row
			change(&bad)
			if _, err := deletionRecord(bad); err == nil {
				t.Fatal("substituted checkpoint accepted")
			}
		})
	}
	// Finalization bookkeeping cannot silently change what the audit describes.
	row.FinalizationXid = pgtype.Uint64{Uint64: 987654, Valid: true}
	if got, err := deletionRecord(row); err != nil || got != expected {
		t.Fatal("transaction bookkeeping changed immutable audit", err)
	}
}
