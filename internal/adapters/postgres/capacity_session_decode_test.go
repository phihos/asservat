package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

func capacitySnapshotFixture() (value.CapacitySessionBacking, artifact.DownloadSession) {
	id := "11111111-1111-4111-8111-111111111111"
	n := time.Date(2026, 10, 12, 12, 0, 0, 123456000, time.UTC)
	rev := identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}
	p := identity.Principal{Issuer: "https://synthetic.invalid", Subject: "reader", ClientID: "console", Kind: identity.Human}
	s := artifact.DownloadSession{ID: id, AllocationID: id, Scope: artifact.DownloadScope{RootID: id, ArtifactID: id, CaptureID: id, ClusterID: id, NamespaceUID: "ns", WorkloadUID: "workload", PodUID: "pod", Version: artifact.Digest{1}, Principal: p}, RequestDigest: artifact.Digest{2}, State: artifact.DownloadPreparing, CreatedAt: n, Deadline: n.Add(time.Hour), OutputLimit: 8192, ReadLimit: 12 << 20, RequestLimit: 3}
	b := value.CapacitySessionBacking{Format: value.CapacitySessionBackingFormat, AccountID: id, AttemptID: id, AllocationID: id, Revision: 1, PoolSource: rev, PolicySource: rev, AllocationUntil: s.Deadline, ControlUntil: s.Deadline, AuditStoreID: id, AuditWriteUntil: s.Deadline.Add(time.Minute), Native: value.NativeBacking{AllocationID: id, RootID: id, PolicyID: id, PolicyDigest: artifact.Digest{3}, Rows: 1, Keys: 2, TransitionsPerRow: 10, BackupBytes: 1 << 20, WALBytes: 4 << 20, BackupHorizonSeconds: 30, CleanupSeconds: 10, ValidUntil: s.Deadline, RetireBy: s.Deadline.Add(70 * time.Second), History: value.NativeHistoryQualification{ID: id, Digest: artifact.Digest{4}, RowBytes: 64 << 10, TransitionWALBytes: 64 << 10, BackupCopies: 1, WALCopies: 1}}}
	return b, s
}
func capacitySnapshotHash(b []byte) []byte {
	h := sha256.New()
	h.Write([]byte(capacitySessionDigestDomain))
	h.Write(b)
	return h.Sum(nil)
}

func TestCapacitySessionSnapshotClosedAndNeverFallsBack(t *testing.T) {
	b, s := capacitySnapshotFixture()
	raw, err := json.Marshal(b)
	if err != nil || !b.Matches(s) {
		t.Fatal("invalid fixture", err)
	}
	if len(raw) > value.CapacitySessionBackingBytes {
		t.Fatal("snapshot exceeds backed bound")
	}
	for _, mode := range []string{"valid", "sql-timezone", "legacy", "missing-managed", "unmanaged-snapshot", "wrong-digest", "unknown-field", "case-alias", "missing-field", "null-counter", "duplicate-field", "wrong-root", "wrong-allocation", "later-session", "wrong-format", "fractional-time", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			body := bytes.Clone(raw)
			managed := true
			session := s
			switch mode {
			case "sql-timezone":
				body = bytes.ReplaceAll(body, []byte("Z\""), []byte("+00:00\""))
			case "legacy":
				managed = false
				body = nil
			case "missing-managed":
				body = nil
			case "unmanaged-snapshot":
				managed = false
			case "oversize":
				body = append(body, bytes.Repeat([]byte(" "), value.CapacitySessionBackingBytes)...)
			case "duplicate-field":
				body = bytes.Replace(body, []byte("\"Revision\":1"), []byte("\"Revision\":1,\"Revision\":1"), 1)
			case "case-alias":
				body = bytes.Replace(body, []byte("\"Revision\""), []byte("\"revision\""), 1)
			case "later-session":
				session.Deadline = session.Deadline.Add(time.Second)
			case "wrong-root":
				session.Scope.RootID = "22222222-2222-4222-8222-222222222222"
			case "wrong-allocation":
				session.AllocationID = "22222222-2222-4222-8222-222222222222"
			default:
				var v map[string]any
				if json.Unmarshal(body, &v) != nil {
					t.Fatal("fixture JSON")
				}
				switch mode {
				case "unknown-field":
					v["Extra"] = true
				case "missing-field":
					delete(v["Native"].(map[string]any), "BackupHorizonSeconds")
				case "null-counter":
					v["Native"].(map[string]any)["BackupHorizonSeconds"] = nil
				case "wrong-format":
					v["Format"] = "protected-capacity/v2"
				case "fractional-time":
					v["AllocationUntil"] = b.AllocationUntil.Add(time.Nanosecond).Format(time.RFC3339Nano)
				}
				body, err = json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
			}
			hash := capacitySnapshotHash(body)
			if mode == "wrong-digest" {
				hash[0] ^= 1
			}
			if mode == "legacy" {
				hash = nil
			}
			out, err := decodeCapacitySessionBacking(body, hash, managed, session)
			if mode == "valid" || mode == "sql-timezone" {
				if err != nil || out == nil || !out.AuditWriteUntil.Equal(b.AuditWriteUntil) || out.Native.TransitionsPerRow != 10 {
					t.Fatal("valid original snapshot", err)
				}
				return
			}
			if mode == "legacy" {
				if err != nil || out != nil {
					t.Fatal("legacy observation promoted")
				}
				return
			}
			if err == nil || out != nil {
				t.Fatal("malformed managed snapshot fell back or became authority")
			}
		})
	}
}
