package postgres

import (
	"encoding/json"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
)

func capacityEnrollmentDecodeFixture() capacityEnrollmentRead {
	n := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	return capacityEnrollmentRead{Enrollment: &app.Enrollment{Format: app.CapacityEnrollmentFormat, Key: app.WorkloadCapacityKey{RootID: "30000000-0000-4000-8000-000000000001", ClusterID: "30000000-0000-4000-8000-000000000002", NamespaceUID: "namespace", WorkloadUID: "workload"},
		ID: "30000000-0000-4000-8000-000000000003", AttemptID: "30000000-0000-4000-8000-000000000004", AllocationID: "30000000-0000-4000-8000-000000000005", DownloadAllocationID: "30000000-0000-4000-8000-000000000006",
		SourceDigest: artifact.Digest{1}, PlanDigest: artifact.Digest{2}, Revision: 1, InitialObservedAt: n, InitialUntil: n.Add(4 * time.Second), ReservedAt: n, AccountVersion: "original", AccountDigest: artifact.Digest{3}}, FreshUntil: n.Add(4 * time.Second)}
}
func TestCapacityEnrollmentDecoderDistinguishesAbsentPartialAndReady(t *testing.T) {
	for _, mode := range []string{"absent", "reserved", "capture-backed", "ready"} {
		t.Run(mode, func(t *testing.T) {
			v := capacityEnrollmentDecodeFixture()
			if mode == "absent" {
				v.Enrollment = nil
			} else if mode == "capture-backed" || mode == "ready" {
				n := v.Enrollment.ReservedAt.Add(time.Second)
				v.Enrollment.CaptureBackedAt = &n
				if mode == "ready" {
					ready := n.Add(time.Second)
					v.Enrollment.ReadyAt = &ready
				}
			}
			b, e := json.Marshal(v)
			if e != nil {
				t.Fatal(e)
			}
			out, e := decodeCapacityEnrollment(b)
			if e != nil || !out.FreshUntil.Equal(v.FreshUntil) || (out.Enrollment == nil) != (v.Enrollment == nil) {
				t.Fatalf("exact retained shape unavailable: %v", e)
			}
		})
	}
}
func TestCapacityEnrollmentDecoderRejectsOpenOrInconsistentReceipt(t *testing.T) {
	for _, mode := range []string{"missing-row", "missing-bound", "case-key", "extra", "duplicate", "zero-digest", "ready-without-capture", "capture-before-reserve", "extended-initial", "fractional-revision", "future-precision"} {
		t.Run(mode, func(t *testing.T) {
			v := capacityEnrollmentDecodeFixture()
			b, e := json.Marshal(v)
			if e != nil {
				t.Fatal(e)
			}
			var root map[string]any
			if json.Unmarshal(b, &root) != nil {
				t.Fatal("fixture JSON")
			}
			row := root["Enrollment"].(map[string]any)
			switch mode {
			case "missing-row":
				delete(root, "Enrollment")
			case "missing-bound":
				delete(root, "FreshUntil")
			case "case-key":
				root["freshuntil"] = root["FreshUntil"]
				delete(root, "FreshUntil")
			case "extra":
				row["Authority"] = true
			case "duplicate":
				b = append([]byte(`{"Enrollment":null,`), b[1:]...)
			case "zero-digest":
				row["SourceDigest"] = artifact.Digest{}
			case "ready-without-capture":
				row["ReadyAt"] = v.Enrollment.ReservedAt.Add(time.Second)
			case "capture-before-reserve":
				row["CaptureBackedAt"] = v.Enrollment.ReservedAt.Add(-time.Second)
			case "extended-initial":
				row["InitialUntil"] = v.Enrollment.InitialObservedAt.Add(6 * time.Second)
			case "fractional-revision":
				row["Revision"] = 1.5
			case "future-precision":
				root["FreshUntil"] = v.FreshUntil.Add(time.Nanosecond)
			}
			if mode != "duplicate" {
				b, e = json.Marshal(root)
				if e != nil {
					t.Fatal(e)
				}
			}
			if _, e = decodeCapacityEnrollment(b); e == nil {
				t.Fatal("malformed row became committed enrollment")
			}
		})
	}
}
