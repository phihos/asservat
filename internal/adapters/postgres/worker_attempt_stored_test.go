package postgres

import (
	"encoding/json"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
)

// Installed native72: the hub's prepared attempt carries a proof observed with
// time.Now() (monotonic reading, Local location) and SQL instants in Local.
// The row's JSON round trip drops both, so Go == refused the hub's own attempt
// after the issuer had already signed it, spending both certificate attempts.
func TestStoredAttemptMatchesHubClockAttempt(t *testing.T) {
	observed := time.Now()
	sqlInstant := observed.Add(4 * time.Second).Round(time.Microsecond).In(time.Local)
	projection := value.AcquisitionCertificateAttempt{ID: "10000000-0000-4000-8000-000000000001", Ordinal: 1,
		Proof:     value.AcquisitionWorkerProof{ObservedAt: observed, FreshUntil: sqlInstant},
		CheckedAt: observed.UTC().Round(time.Microsecond), SignBefore: sqlInstant, CertificateNotAfter: sqlInstant.Truncate(time.Second)}
	download := value.WorkerCertificateAttempt{ID: projection.ID, Ordinal: 1,
		Proof:     value.WorkerEnrollmentProof{ObservedAt: observed, FreshUntil: sqlInstant},
		CheckedAt: projection.CheckedAt, SignBefore: sqlInstant, CertificateNotAfter: projection.CertificateNotAfter}
	stored := func(v any) []byte {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	if !storedAttempt(stored(projection), projection) || !storedAttempt(stored(download), download) {
		t.Fatal("the hub's own prepared attempt no longer matches its frozen row")
	}
	other := projection
	other.Ordinal = 2
	if storedAttempt(stored(projection), other) {
		t.Fatal("a different attempt matched the frozen row")
	}
	later := projection
	later.SignBefore = later.SignBefore.Add(time.Microsecond)
	if storedAttempt(stored(projection), later) {
		t.Fatal("a changed instant matched the frozen row")
	}
}
