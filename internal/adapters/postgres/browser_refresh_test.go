package postgres

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
)

func TestRefreshOwnerObservationPreservesOriginalInterval(t *testing.T) {
	observed := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	uuid := id("11111111-1111-4111-8111-111111111111")
	row := custodydb.BrowserRefreshOwner{
		RootID: uuid, Epoch: uuid, OwnerID: uuid, InstallationID: uuid,
		ClusterID: uuid, PodUid: uuid, ProcessEpoch: uuid, Generation: 1,
		SessionID:        append([]byte{1}, make([]byte, 31)...),
		SessionExpiresAt: ts(observed.Add(time.Minute)),
		LeaseUntil:       ts(observed.Add(15 * time.Second)),
	}
	for _, test := range []struct {
		name  string
		until time.Time
		want  time.Time
	}{
		{"nested observation starts later", observed.Add(5*time.Second + time.Microsecond), observed.Add(5 * time.Second)},
		{"earlier protected deadline", observed.Add(2 * time.Second), observed.Add(2 * time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := refreshOwnerView(row, observed, test.until, row.SessionExpiresAt.Time)
			if !got.Valid(observed.Add(time.Millisecond)) || !got.ObservedAt.Equal(observed) || !got.ValidUntil.Equal(test.want) {
				t.Fatalf("original observation interval lost: observed=%s validUntil=%s want=%s", got.ObservedAt, got.ValidUntil, test.want)
			}
			if got.Valid(test.want) {
				t.Fatal("original observation deadline was renewed")
			}
		})
	}
}
