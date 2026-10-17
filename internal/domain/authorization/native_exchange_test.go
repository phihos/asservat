package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"math"
	"testing"
	"time"
)

func TestNativeBackingRequiresExactFiniteHistory(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	end := time.Now().Add(time.Hour)
	b := NativeBacking{AllocationID: id, RootID: id, PolicyID: id, PolicyDigest: artifact.Digest{1}, Rows: 2, Keys: 3, TransitionsPerRow: 16, BackupHorizonSeconds: 60, CleanupSeconds: 30, ValidUntil: end, RetireBy: end.Add(150 * time.Second), History: NativeHistoryQualification{ID: id, Digest: artifact.Digest{2}, RowBytes: 65536, TransitionWALBytes: 65536, BackupCopies: 2, WALCopies: 2}}
	b.BackupBytes = 2 * b.History.RowBytes * b.History.BackupCopies * (b.Rows + b.Keys)
	b.WALBytes = b.History.TransitionWALBytes * b.History.WALCopies * ((b.TransitionsPerRow+4)*b.Rows + 8*b.Keys)
	if !b.Valid() {
		t.Fatal("exact qualified backing denied")
	}
	for _, field := range []string{"backup", "wal", "transitions", "retire", "keys", "qualification"} {
		t.Run(field, func(t *testing.T) {
			c := b
			switch field {
			case "backup":
				c.BackupBytes--
			case "wal":
				c.WALBytes--
			case "transitions":
				c.TransitionsPerRow = math.MaxInt64
			case "retire":
				c.RetireBy = c.RetireBy.Add(time.Second)
			case "keys":
				c.Keys = 0
			case "qualification":
				c.History.Digest = artifact.Digest{}
			}
			if c.Valid() {
				t.Fatal("unbacked native history admitted")
			}
		})
	}
	if _, ok := nativeMultiply(math.MaxInt64, 2); ok {
		t.Fatal("overflow accepted")
	}
}
