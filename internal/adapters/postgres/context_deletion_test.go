package postgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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

// ADR-205: only a bounded, ordered page may advance a scheduling cursor.
func TestContextDeletionPageAcceptsOnlyBoundedOrderedLocations(t *testing.T) {
	through := time.Now().UTC().Truncate(time.Microsecond)
	cursor := ContextDeletionCursor{Through: through}
	row := func(n int) custodydb.ListDueContextDeletionPageRow {
		key := func(prefix int) pgtype.UUID {
			return id(fmt.Sprintf("%08x-0000-4000-8000-%012x", prefix, n))
		}
		return custodydb.ListDueContextDeletionPageRow{ClusterID: key(1), ArtifactID: key(2), ID: key(3), EffectiveExpiresAt: ts(through.Add(-time.Minute))}
	}
	var rows []custodydb.ListDueContextDeletionPageRow
	for n := range 16 {
		rows = append(rows, row(n))
	}
	got, err := contextDeletionPage(rows, cursor)
	if err != nil || len(got.Locations) != 16 || got.Locations[3] != (artifact.Location{ClusterID: "00000001-0000-4000-8000-000000000003", ArtifactID: "00000002-0000-4000-8000-000000000003", AttemptID: "00000003-0000-4000-8000-000000000003"}) ||
		got.Next.Through != through || got.Next.AfterAttemptID != uid(row(15).ID) || !got.Next.AfterExpiresAt.Equal(row(15).EffectiveExpiresAt.Time) || !got.Next.valid() {
		t.Fatal("bounded due page changed", got, err)
	}
	if next, e := contextDeletionPage([]custodydb.ListDueContextDeletionPageRow{row(16)}, got.Next); e != nil || len(next.Locations) != 1 || next.Next != (ContextDeletionCursor{}) {
		t.Fatal("short final page did not wrap for retries", next, e)
	}
	if _, e := contextDeletionPage(rows, got.Next); !errors.Is(e, app.ErrUnavailable) {
		t.Fatal("old failing prefix accepted after the cursor", e)
	}
	if got, err = contextDeletionPage(nil, got.Next); err != nil || got.Locations == nil || len(got.Locations) != 0 || got.Next != (ContextDeletionCursor{}) {
		t.Fatal("empty due page", got, err)
	}
	invalid := row(0)
	invalid.ArtifactID = pgtype.UUID{}
	future, missing, infinity := row(0), row(0), row(0)
	future.EffectiveExpiresAt = ts(through.Add(time.Microsecond))
	missing.EffectiveExpiresAt.Valid = false
	infinity.EffectiveExpiresAt.InfinityModifier = pgtype.Infinity
	for name, bad := range map[string][]custodydb.ListDueContextDeletionPageRow{
		"oversized":                      append(slices.Clone(rows), row(16)),
		"duplicate":                      {row(1), row(1)},
		"invalid":                        {invalid},
		"unordered":                      {row(1), row(0)},
		"new arrival beyond pass cutoff": {future},
		"missing cutoff":                 {missing},
		"infinite cutoff":                {infinity},
	} {
		if _, err = contextDeletionPage(bad, cursor); !errors.Is(err, app.ErrUnavailable) {
			t.Fatal("unbounded or invalid due page accepted", name, err)
		}
	}
}

func TestContextDeletionCursorRejectsPartialOrUnboundedPosition(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "10000000-0000-4000-8000-000000000001"
	for _, c := range []ContextDeletionCursor{{}, {Through: now, AfterExpiresAt: now, AfterAttemptID: id}} {
		if !c.valid() {
			t.Fatal("valid scheduling cursor rejected", c)
		}
	}
	for _, c := range []ContextDeletionCursor{
		{Through: now},
		{AfterExpiresAt: now, AfterAttemptID: id},
		{Through: now, AfterAttemptID: id},
		{Through: now, AfterExpiresAt: now},
		{Through: now, AfterExpiresAt: now, AfterAttemptID: "invalid"},
		{Through: now, AfterExpiresAt: now.Add(time.Microsecond), AfterAttemptID: id},
		{Through: now.Add(time.Nanosecond), AfterExpiresAt: now, AfterAttemptID: id},
		{Through: now, AfterExpiresAt: now.Add(-time.Nanosecond), AfterAttemptID: id},
	} {
		if c.valid() {
			t.Fatal("invalid scheduling cursor accepted", c)
		}
	}
}
