package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"testing"
)

func TestInitialInstallationReceiptRequiresImmutableVersion(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	original := Receipt{Key: InitialInstallationKey(id, id), Version: "original-version", ETag: "original", Bytes: 32, SHA256: artifact.Digest{1}}
	if !original.ValidInitialInstallation(id, id) {
		t.Fatal("original versioned receipt rejected")
	}
	for _, version := range []string{"", "null"} {
		name := "missing"
		if version == "null" {
			name = "null"
		}
		t.Run(name, func(t *testing.T) {
			changed := original
			changed.Version = version
			if changed.ValidInitialInstallation(id, id) {
				t.Fatal("INITIAL_HISTORY_ACCEPTED_WITHOUT_IMMUTABLE_VERSION", name)
			}
		})
	}
}
