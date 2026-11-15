package postgres

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestPreviewReadable(t *testing.T) {
	created := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	now := created.Add(time.Minute)
	for _, tc := range []struct {
		name  string
		until pgtype.Timestamptz
		want  bool
	}{
		{"finite-future", pgtype.Timestamptz{Time: now.Add(time.Second), Valid: true}, true},
		{"finite-now", pgtype.Timestamptz{Time: now, Valid: true}, false},
		{"finite-past", pgtype.Timestamptz{Time: now.Add(-time.Second), Valid: true}, false},
		{"positive-infinity", pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}, true},
		{"negative-infinity", pgtype.Timestamptz{InfinityModifier: pgtype.NegativeInfinity, Valid: true}, false},
		{"null", pgtype.Timestamptz{}, false},
	} {
		if got := previewReadable(tc.until, now, created); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
	if previewReadable(pgtype.Timestamptz{InfinityModifier: pgtype.Infinity, Valid: true}, created.Add(-time.Second), created) {
		t.Error("a read before creation was accepted")
	}
}
