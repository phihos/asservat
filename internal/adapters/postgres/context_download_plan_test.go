package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"encoding/json"
	"testing"
	"time"
)

func TestContextPlanRequiresExactFiniteNativeControlAndStopBacking(t *testing.T) {
	const root = "10000000-0000-4000-8000-000000000001"
	const allocation = "10000000-0000-4000-8000-000000000002"
	const installation = "10000000-0000-4000-8000-000000000003"
	const store = "10000000-0000-4000-8000-000000000004"
	now := time.Now().UTC().Truncate(time.Microsecond)
	until := now.Add(time.Hour)
	a := artifact.DownloadAllocation{ID: allocation, RootID: root, ClusterID: installation, NamespaceUID: "ns", WorkloadUID: "workload", OutputLimit: 16384, ReadLimit: 32 << 20, SessionLimit: 2, ValidUntil: until}
	c := custodydb.DownloadControlAllocation{ID: id(allocation), RootID: id(root), AuditStoreID: id(store), ResponseLimit: 2, WindowLimit: 2, AuditByteLimit: 4 * artifact.DownloadWindowAuditBytes, ValidUntil: ts(until), AuditWriteUntil: ts(until.Add(time.Minute))}
	native := authorization.NativeBacking{AllocationID: allocation, RootID: root, PolicyID: store, PolicyDigest: artifact.Digest{1}, Rows: 2, Keys: 2, TransitionsPerRow: 8, BackupBytes: 32 << 20, WALBytes: 32 << 20, CleanupSeconds: 30, ValidUntil: until, RetireBy: until.Add(30 * time.Second), History: authorization.NativeHistoryQualification{ID: installation, Digest: artifact.Digest{2}, RowBytes: 64 << 10, TransitionWALBytes: 64 << 10, BackupCopies: 1, WALCopies: 1}}
	wire, _ := json.Marshal(native)
	n := custodydb.DownloadNativeBacking{AllocationID: id(allocation), RootID: id(root), PolicyJson: wire, RowsLimit: 2, KeysLimit: 2, TransitionsPerRow: 8, CleanupSeconds: 30, ValidUntil: ts(until), RetireBy: ts(native.RetireBy)}
	stop := audit.DownloadStopLifecyclePolicy{RootID: root, InstallationID: installation, StoreID: store, PolicyID: allocation, BackupProfileID: store, QualificationID: installation, PolicyDigest: artifact.Digest{3}, BackupProfileDigest: artifact.Digest{4}, QualificationDigest: artifact.Digest{5}, Layout: audit.DownloadStopHistoryLayout, CleanupBudgetSeconds: 10, ProofWindowSeconds: 3, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 1, WALCopies: 1, MaxPurgeLeases: 8}
	wire, _ = json.Marshal(stop)
	cipher, keys, backup, wal := stop.SlotBacking()
	p := custodydb.DownloadStopPool{RootID: id(root), InstallationID: id(installation), StoreID: id(store), PolicyID: id(allocation), BackupProfileID: id(store), PolicyDigest: stop.PolicyDigest[:], BackupProfileDigest: stop.BackupProfileDigest[:], Slots: 2, Allocated: 2, CipherBytes: 2 * cipher, KeyAttempts: 2 * keys, BackupBytes: 2 * backup, WalBytes: 2 * wal, RetainedSeconds: 64, ValidUntil: ts(until), LifecyclePolicy: wire}
	b := custodydb.DownloadStopBacking{AllocationID: id(allocation), RootID: id(root), Slots: 2}
	limits := ContextDownloadPlanLimits{OutputLimit: 8192, ReadLimit: 8 << 20, RequestLimit: 4, Duration: 8 * time.Hour}
	if !contextPlanBacking(limits, a, c, n, b, p, installation, now) {
		t.Fatal("exact supported backing rejected")
	}
	// Long requested duration is clamped by absolute backing, not by a new
	// lookup-relative Stop timer. SQL47 anchors retention to the session end.
	for _, change := range []func(*custodydb.DownloadControlAllocation, *custodydb.DownloadNativeBacking, *custodydb.DownloadStopBacking, *custodydb.DownloadStopPool){
		func(c *custodydb.DownloadControlAllocation, _ *custodydb.DownloadNativeBacking, _ *custodydb.DownloadStopBacking, _ *custodydb.DownloadStopPool) {
			c.ReservedResponses = c.ResponseLimit
		},
		func(c *custodydb.DownloadControlAllocation, _ *custodydb.DownloadNativeBacking, _ *custodydb.DownloadStopBacking, _ *custodydb.DownloadStopPool) {
			c.ReservedWindows = c.WindowLimit
		},
		func(c *custodydb.DownloadControlAllocation, _ *custodydb.DownloadNativeBacking, _ *custodydb.DownloadStopBacking, _ *custodydb.DownloadStopPool) {
			c.ReservedAuditBytes = c.AuditByteLimit
		},
		func(_ *custodydb.DownloadControlAllocation, n *custodydb.DownloadNativeBacking, _ *custodydb.DownloadStopBacking, _ *custodydb.DownloadStopPool) {
			n.Overdue = true
		},
		func(_ *custodydb.DownloadControlAllocation, n *custodydb.DownloadNativeBacking, _ *custodydb.DownloadStopBacking, _ *custodydb.DownloadStopPool) {
			n.ChargedKeys = n.KeysLimit
		},
		func(_ *custodydb.DownloadControlAllocation, n *custodydb.DownloadNativeBacking, _ *custodydb.DownloadStopBacking, _ *custodydb.DownloadStopPool) {
			n.TransitionsPerRow = 7
		},
		func(_ *custodydb.DownloadControlAllocation, _ *custodydb.DownloadNativeBacking, b *custodydb.DownloadStopBacking, _ *custodydb.DownloadStopPool) {
			b.Charged = b.Slots
		},
		func(_ *custodydb.DownloadControlAllocation, _ *custodydb.DownloadNativeBacking, _ *custodydb.DownloadStopBacking, p *custodydb.DownloadStopPool) {
			p.InstallationID = id(store)
		},
		func(_ *custodydb.DownloadControlAllocation, _ *custodydb.DownloadNativeBacking, _ *custodydb.DownloadStopBacking, p *custodydb.DownloadStopPool) {
			p.BackupBytes--
		},
		func(_ *custodydb.DownloadControlAllocation, _ *custodydb.DownloadNativeBacking, _ *custodydb.DownloadStopBacking, p *custodydb.DownloadStopPool) {
			p.RetainedSeconds = 63
		},
	} {
		cc, nn, bb, pp := c, n, b, p
		change(&cc, &nn, &bb, &pp)
		if contextPlanBacking(limits, a, cc, nn, bb, pp, installation, now) {
			t.Fatal("unsupported or exhausted backing accepted")
		}
	}
	if contextPlanBacking(limits, a, c, n, b, p, installation, until) {
		t.Fatal("expired original backing accepted")
	}
}
