package targets

import (
	"testing"

	"asservat.local/asservat/internal/domain/privacy"
)

// A saved window resolves retention with the labels recorded at arming.
func TestSourceSnapshotRoutingCarriesArmingLabels(t *testing.T) {
	s := SourceSnapshotTarget{Labels: privacy.EncodeLabels(&privacy.TargetLabels{Workload: map[string]string{"tier": "web"}})}
	if l := s.Routing().Labels; l == nil || l.Workload["tier"] != "web" {
		t.Fatal("routing dropped arming labels", l)
	}
	if (SourceSnapshotTarget{}).Routing().Labels != nil {
		t.Fatal("a source armed without labels must stay unobserved")
	}
}
