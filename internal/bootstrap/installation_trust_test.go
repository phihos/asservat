package bootstrap

import (
	"testing"
	"time"
)

func TestInstallationTrustIsStable(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	id, epoch := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	a, b := installationTrustAt(id, epoch, now), installationTrustAt(id, epoch, now.Add(time.Minute))
	if !a.Valid(now) || a.Revision != b.Revision || a.Valid(now.Add(5*time.Second)) || installationTrustAt(id, id, now).Revision == a.Revision {
		t.Fatal(a, b)
	}
}
