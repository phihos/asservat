package postgres

import (
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestVerifiedProfileAcquisitionRetainsUnknownAndBounds(t *testing.T) {
	c := compiledProfileReplayRow(t)
	var e artifact.ContextExpectation
	if err := json.Unmarshal(c.ExpectationJson, &e); err != nil {
		t.Fatal(err)
	}
	var legacy custodydb.ContextVerification
	if got, err := verifiedAcquisition(e, legacy); err != nil || got != nil {
		t.Fatal("legacy unknown timing invented", got, err)
	}
	start := e.Registration.AnchorAt.UTC().Truncate(time.Microsecond).Add(time.Second)
	row := custodydb.ContextVerification{AcquisitionStartedAt: ts(start), AcquisitionCompletedAt: ts(start.Add(time.Second))}
	got, err := verifiedAcquisition(e, row)
	if err != nil || got == nil || !got.StartedAt.Equal(start) || !got.CompletedAt.Equal(start.Add(time.Second)) {
		t.Fatal("actual acquisition window lost", got, err)
	}
	for name, change := range map[string]func(*custodydb.ContextVerification){
		"missing start": func(v *custodydb.ContextVerification) { v.AcquisitionStartedAt.Valid = false },
		"missing end":   func(v *custodydb.ContextVerification) { v.AcquisitionCompletedAt.Valid = false },
		"reversed":      func(v *custodydb.ContextVerification) { v.AcquisitionCompletedAt.Time = start.Add(-time.Second) },
		"preanchor": func(v *custodydb.ContextVerification) {
			v.AcquisitionStartedAt.Time = e.Registration.AnchorAt.Add(-time.Second)
		},
		"write cutoff": func(v *custodydb.ContextVerification) { v.AcquisitionCompletedAt.Time = e.Registration.WriteUntil },
		"infinite":     func(v *custodydb.ContextVerification) { v.AcquisitionCompletedAt.InfinityModifier = pgtype.Infinity },
		"unnormalized": func(v *custodydb.ContextVerification) { v.AcquisitionStartedAt.Time = start.Add(time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := row
			change(&bad)
			if _, err := verifiedAcquisition(e, bad); err == nil {
				t.Fatal("invalid persisted window accepted")
			}
		})
	}
	// Clock skew is unknown. There is deliberately no comparison with the
	// database's verified_at instant, or with API dispatch/store timestamps.
	row.VerifiedAt = ts(start.Add(-time.Hour))
	if _, err := verifiedAcquisition(e, row); err != nil {
		t.Fatal("unqualified cross-clock rule added", err)
	}
	e.Profile = nil
	if _, err := verifiedAcquisition(e, row); err == nil {
		t.Fatal("non-profile acquired profile timing semantics")
	}
}
