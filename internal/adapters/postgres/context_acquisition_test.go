package postgres

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestCatalogProfileAcquisitionRetainsUnknownAndBounds(t *testing.T) {
	c := compiledProfileReplayRow(t)
	var e artifact.ContextExpectation
	if err := json.Unmarshal(c.ExpectationJson, &e); err != nil {
		t.Fatal(err)
	}
	var legacy custodydb.ContextCatalog
	if got, err := catalogAcquisition(e, legacy.AcquisitionStartedAt, legacy.AcquisitionCompletedAt); err != nil || got != nil {
		t.Fatal("legacy unknown timing invented", got, err)
	}
	start := e.Registration.AnchorAt.UTC().Truncate(time.Microsecond).Add(time.Second)
	row := custodydb.ContextCatalog{AcquisitionStartedAt: ts(start), AcquisitionCompletedAt: ts(start.Add(time.Second))}
	got, err := catalogAcquisition(e, row.AcquisitionStartedAt, row.AcquisitionCompletedAt)
	if err != nil || got == nil || !got.StartedAt.Equal(start) || !got.CompletedAt.Equal(start.Add(time.Second)) {
		t.Fatal("actual acquisition window lost", got, err)
	}
	for name, change := range map[string]func(*custodydb.ContextCatalog){
		"missing start": func(v *custodydb.ContextCatalog) { v.AcquisitionStartedAt.Valid = false },
		"missing end":   func(v *custodydb.ContextCatalog) { v.AcquisitionCompletedAt.Valid = false },
		"reversed":      func(v *custodydb.ContextCatalog) { v.AcquisitionCompletedAt.Time = start.Add(-time.Second) },
		"preanchor": func(v *custodydb.ContextCatalog) {
			v.AcquisitionStartedAt.Time = e.Registration.AnchorAt.Add(-time.Second)
		},
		"write cutoff": func(v *custodydb.ContextCatalog) { v.AcquisitionCompletedAt.Time = e.Registration.WriteUntil },
		"infinite":     func(v *custodydb.ContextCatalog) { v.AcquisitionCompletedAt.InfinityModifier = pgtype.Infinity },
		"unnormalized": func(v *custodydb.ContextCatalog) { v.AcquisitionStartedAt.Time = start.Add(time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := row
			change(&bad)
			if _, err := catalogAcquisition(e, bad.AcquisitionStartedAt, bad.AcquisitionCompletedAt); err == nil {
				t.Fatal("invalid persisted window accepted")
			}
		})
	}
	row.NativeBytes = pgtype.Int8{Int64: 42, Valid: true}
	if f, err := catalogFacts(e, row); err != nil || f.NativeBytes != 42 || f.Acquisition == nil || !f.Acquisition.Equal(*got) {
		t.Fatal("catalog read facts lost", f, err)
	}
	for name, change := range map[string]func(*custodydb.ContextCatalog){
		"missing size": func(v *custodydb.ContextCatalog) { v.NativeBytes.Valid = false },
		"missing window": func(v *custodydb.ContextCatalog) {
			v.AcquisitionStartedAt.Valid, v.AcquisitionCompletedAt.Valid = false, false
		},
	} {
		bad := row
		change(&bad)
		if _, err := catalogFacts(e, bad); !errors.Is(err, artifact.ErrIntegrity) {
			t.Fatal(name, "accepted", err)
		}
	}
	e.Profile = nil
	if _, err := catalogAcquisition(e, row.AcquisitionStartedAt, row.AcquisitionCompletedAt); err == nil {
		t.Fatal("non-profile acquired profile timing semantics")
	}
}
