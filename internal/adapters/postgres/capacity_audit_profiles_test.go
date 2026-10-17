package postgres

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
)

func capacityAuditReadFixture() value.AcceptedCapacityAuditProfiles {
	id := "40000000-0000-4000-8000-000000000001"
	n := time.Date(2026, 10, 12, 12, 0, 0, 123456000, time.UTC)
	lane := func(name string) value.CapacityAuditProfile {
		q := value.OperationHistoryQualification{ID: id, Digest: artifact.Digest{1}, Layout: value.OperationVerificationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 1, WALCopies: 1}
		b, w := q.SlotBacking(2)
		return value.CapacityAuditProfile{Policy: value.OperationLifecyclePolicy{RootID: id, Lane: name, InstallationID: id, StoreID: id, PolicyID: id, BackupProfileID: id, PolicyDigest: artifact.Digest{2}, BackupProfileDigest: artifact.Digest{3}, BackingRevision: 1, MetadataSlots: 4, BackupReservedBytes: 4 * b, WALReservedBytes: 4 * w, BackupHorizonSeconds: 0, CleanupBudgetSeconds: 1, ProofWindowSeconds: 1, ValidUntil: n.Add(time.Hour), MaxPurgeLeases: 2, History: &q, OverdueTerminal: value.OperationOverdueTerminal}, RetainedSeconds: 60}
	}
	return value.AcceptedCapacityAuditProfiles{Format: value.CapacityAuditProfilesFormat, RootID: id, InstallationID: id, QualificationID: id, AccountVersion: "original", QualificationDigest: artifact.Digest{4}, PlanDigest: artifact.Digest{5}, ConfigurationRevision: 1, SourceRevision: 3, Normal: lane("normal"), Resolution: lane("resolution"), ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
}

func TestCapacityAuditProfilesDecodeClosedAndNoLegacyFallback(t *testing.T) {
	v := capacityAuditReadFixture()
	original, e := json.Marshal(v)
	if e != nil || !v.Valid(v.ObservedAt) {
		t.Fatal("invalid fixture", e)
	}
	for _, mode := range []string{"valid", "sql-zone", "expired-after-read", "null-profile", "missing-zero", "null-zero", "case-alias", "duplicate", "unknown", "trailing", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			raw := bytes.Clone(original)
			now := v.ObservedAt.Add(time.Second)
			switch mode {
			case "sql-zone":
				raw = bytes.ReplaceAll(raw, []byte("Z\""), []byte("+00:00\""))
			case "expired-after-read":
				now = v.FreshUntil
			case "case-alias":
				raw = bytes.Replace(raw, []byte("\"AccountVersion\""), []byte("\"accountversion\""), 1)
			case "duplicate":
				raw = bytes.Replace(raw, []byte("\"SourceRevision\":3"), []byte("\"SourceRevision\":3,\"SourceRevision\":3"), 1)
			case "trailing":
				raw = append(raw, []byte(" {}")...)
			case "oversized":
				raw = append(raw, bytes.Repeat([]byte(" "), 16<<10)...)
			default:
				var x map[string]any
				if json.Unmarshal(raw, &x) != nil {
					t.Fatal("fixture")
				}
				switch mode {
				case "null-profile":
					x["Normal"] = nil
				case "unknown":
					x["PreviouslyReady"] = true
				case "missing-zero":
					delete(x["Normal"].(map[string]any)["Policy"].(map[string]any), "BackupHorizonSeconds")
				case "null-zero":
					x["Normal"].(map[string]any)["Policy"].(map[string]any)["BackupHorizonSeconds"] = nil
				}
				raw, e = json.Marshal(x)
				if e != nil {
					t.Fatal(e)
				}
			}
			_, err := decodeCapacityAuditProfiles(raw, now)
			if (err == nil) != (mode == "valid" || mode == "sql-zone") {
				t.Fatal("malformed or expired accepted profile decoded", err)
			}
		})
	}
}
