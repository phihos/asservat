package postgres

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/jackc/pgx/v5/pgtype"
)

func sessionReadRows(t *testing.T) (custodydb.ReadSessionNativeBackingRow, custodydb.ReadDownloadSessionControlRow, artifact.DownloadSession) {
	t.Helper()
	b, s := capacitySnapshotFixture()
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	n := custodydb.ReadSessionNativeBackingRow{
		DownloadNativeBacking: custodydb.DownloadNativeBacking{AllocationID: id(s.AllocationID), RootID: id(s.Scope.RootID), PolicyJson: []byte("renewed current policy"), RowsLimit: 7, KeysLimit: 14, TransitionsPerRow: 30, ChargedRows: 3, ChargedKeys: 5, BackupHorizonSeconds: 90, CleanupSeconds: 60, ValidUntil: ts(s.Deadline.Add(time.Hour)), RetireBy: ts(s.Deadline.Add(2 * time.Hour)), ResidualUntil: ts(s.Deadline.Add(3 * time.Hour)), Overdue: true},
		CapacityAccountID:     id(b.AccountID), CapacityBacking: raw, CapacityBackingDigest: capacitySnapshotHash(raw), SessionDeadline: ts(s.Deadline),
	}
	c := custodydb.ReadDownloadSessionControlRow{
		DownloadControlAllocation: custodydb.DownloadControlAllocation{ID: id(s.AllocationID), RootID: id(s.Scope.RootID), AuditStoreID: id(b.AuditStoreID), ResponseLimit: 9, WindowLimit: 15, AuditByteLimit: 1 << 20, ReservedResponses: 3, ReservedWindows: 5, ReservedAuditBytes: 4096, ValidUntil: ts(s.Deadline.Add(time.Hour)), AuditWriteUntil: ts(s.Deadline.Add(2 * time.Hour))},
		CapacityAccountID:         id(b.AccountID), CapacityBacking: bytes.Clone(raw), CapacityBackingDigest: capacitySnapshotHash(raw), SessionDeadline: ts(s.Deadline),
	}
	return n, c, s
}

func TestSessionCapacityReadsRetainOriginalLimitsAndCurrentSpend(t *testing.T) {
	n, c, s := sessionReadRows(t)
	old, _ := capacitySnapshotFixture()
	got, err := effectiveSessionNativeBacking(n, s)
	if err != nil {
		t.Fatal(err)
	}
	want := n.DownloadNativeBacking
	want.PolicyJson, _ = json.Marshal(old.Native)
	want.RowsLimit, want.KeysLimit, want.TransitionsPerRow = old.Native.Rows, old.Native.Keys, old.Native.TransitionsPerRow
	want.BackupHorizonSeconds, want.CleanupSeconds = old.Native.BackupHorizonSeconds, old.Native.CleanupSeconds
	want.ValidUntil, want.RetireBy = ts(old.Native.ValidUntil), ts(old.Native.RetireBy)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("renewed native policy replaced original bounds or changed current spend/overdue state")
	}
	control, err := effectiveSessionControlBacking(c, s)
	if err != nil {
		t.Fatal(err)
	}
	expected := c.DownloadControlAllocation
	expected.ValidUntil, expected.AuditWriteUntil = ts(old.ControlUntil), ts(old.AuditWriteUntil)
	if !reflect.DeepEqual(control, expected) {
		t.Fatal("renewed control policy replaced original bounds or changed current reservations")
	}
	if !n.DownloadNativeBacking.Overdue || n.DownloadNativeBacking.ValidUntil.Time.Equal(old.Native.ValidUntil) || c.DownloadControlAllocation.ValidUntil.Time.Equal(old.ControlUntil) {
		t.Fatal("projection changed caller-owned raw rows")
	}
}

func TestSessionCapacityReadsRejectUnboundOrDamagedSnapshots(t *testing.T) {
	for _, mode := range []string{"account", "allocation", "root", "deadline", "missing-deadline", "digest", "missing", "unmanaged-body", "unmanaged-digest", "case-alias", "session-deadline", "invalid-session"} {
		t.Run(mode, func(t *testing.T) {
			n, c, s := sessionReadRows(t)
			other := id("22222222-2222-4222-8222-222222222222")
			switch mode {
			case "account":
				n.CapacityAccountID, c.CapacityAccountID = other, other
			case "allocation":
				n.DownloadNativeBacking.AllocationID, c.DownloadControlAllocation.ID = other, other
			case "root":
				n.DownloadNativeBacking.RootID, c.DownloadControlAllocation.RootID = other, other
			case "deadline":
				n.SessionDeadline, c.SessionDeadline = ts(s.Deadline.Add(time.Second)), ts(s.Deadline.Add(time.Second))
			case "missing-deadline":
				n.SessionDeadline, c.SessionDeadline = pgtype.Timestamptz{}, pgtype.Timestamptz{}
			case "digest":
				n.CapacityBackingDigest[0] ^= 1
				c.CapacityBackingDigest[0] ^= 1
			case "missing":
				n.CapacityBacking, c.CapacityBacking = nil, nil
			case "unmanaged-body":
				n.CapacityAccountID, c.CapacityAccountID = pgtype.UUID{}, pgtype.UUID{}
			case "unmanaged-digest":
				n.CapacityAccountID, c.CapacityAccountID = pgtype.UUID{}, pgtype.UUID{}
				n.CapacityBacking, c.CapacityBacking = nil, nil
			case "case-alias":
				n.CapacityBacking = bytes.Replace(n.CapacityBacking, []byte("\"Revision\""), []byte("\"revision\""), 1)
				c.CapacityBacking = bytes.Clone(n.CapacityBacking)
				n.CapacityBackingDigest, c.CapacityBackingDigest = capacitySnapshotHash(n.CapacityBacking), capacitySnapshotHash(c.CapacityBacking)
			case "session-deadline":
				s.Deadline = s.Deadline.Add(time.Second)
				n.SessionDeadline, c.SessionDeadline = ts(s.Deadline), ts(s.Deadline)
			case "invalid-session":
				s.ID = ""
			}
			if _, err := effectiveSessionNativeBacking(n, s); err == nil {
				t.Fatal("invalid native snapshot accepted")
			}
			if _, err := effectiveSessionControlBacking(c, s); err == nil {
				t.Fatal("invalid control snapshot accepted")
			}
		})
	}
	t.Run("changed-audit-store", func(t *testing.T) {
		_, c, s := sessionReadRows(t)
		c.DownloadControlAllocation.AuditStoreID = id("22222222-2222-4222-8222-222222222222")
		if _, err := effectiveSessionControlBacking(c, s); err == nil {
			t.Fatal("changed audit store selected")
		}
	})
}

func TestSessionCapacityReadsKeepUnmanagedRowsUnchanged(t *testing.T) {
	n, c, s := sessionReadRows(t)
	n.CapacityAccountID, c.CapacityAccountID = pgtype.UUID{}, pgtype.UUID{}
	n.CapacityBacking, c.CapacityBacking = nil, nil
	n.CapacityBackingDigest, c.CapacityBackingDigest = nil, nil
	b, err := effectiveSessionNativeBacking(n, s)
	if err != nil || !reflect.DeepEqual(b, n.DownloadNativeBacking) {
		t.Fatal("unmanaged native row changed", err)
	}
	a, err := effectiveSessionControlBacking(c, s)
	if err != nil || !reflect.DeepEqual(a, c.DownloadControlAllocation) {
		t.Fatal("unmanaged control row changed", err)
	}
}
