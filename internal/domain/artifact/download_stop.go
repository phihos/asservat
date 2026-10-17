package artifact

import (
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

const DownloadStopProtocol = "prepaid-download-stop/v1"
const DownloadStopCipherLimit int64 = 64 << 10

// One allocation reserves every eventual stop before native acquisition. This
// is installation-owned backing, never a user-provided capacity declaration.
// Retained/uncertain reservations cannot be refunded by deadline or row expiry.
type DownloadStopBacking struct {
	AllocationID, RootID, InstallationID, StoreID, PolicyID, BackupProfileID string
	PolicyDigest, BackupProfileDigest                                        Digest
	Slots, AllocationSlots, CipherBytes, KeyAttempts, BackupBytes, WALBytes  int64
	ExpectedRevision                                                         int64
	RetainedSeconds, BackupHorizonSeconds                                    int64
	ObservedAt, ValidUntil                                                   time.Time
}

func (b DownloadStopBacking) Valid() bool {
	return uuid(b.AllocationID) && uuid(b.RootID) && uuid(b.InstallationID) && uuid(b.StoreID) && uuid(b.PolicyID) && uuid(b.BackupProfileID) && b.PolicyDigest != (Digest{}) && b.BackupProfileDigest != (Digest{}) && b.Slots > 0 && b.Slots <= 100000 && b.AllocationSlots > 0 && b.AllocationSlots <= b.Slots && b.ExpectedRevision >= 0 && b.ExpectedRevision < 1<<60 && b.CipherBytes/b.Slots >= DownloadStopCipherLimit && b.KeyAttempts >= 6*b.Slots && b.BackupBytes/b.Slots >= 128<<10 && b.WALBytes/b.Slots >= 1<<20 && b.RetainedSeconds >= 60 && b.RetainedSeconds <= 316224000 && b.BackupHorizonSeconds >= 0 && b.BackupHorizonSeconds < b.RetainedSeconds && !b.ObservedAt.IsZero() && b.ValidUntil.After(b.ObservedAt)
}

// Stop receipts deliberately reveal no artifact, native metadata, finer prior
// terminal state or evidence-retention dates. Current original actor/client
// authentication suffices; evidence-read scope is not needed to reduce access.
type DownloadStopReceipt struct {
	DownloadID, RequestID, State, AuditState string
	ObservedAt, ValidUntil                   time.Time
}

func (r DownloadStopReceipt) Valid(now time.Time) bool {
	return uuid(r.DownloadID) && uuid(r.RequestID) && (r.State == "Cancelled" || r.State == "AlreadyTerminal") && (r.AuditState == "pending" || r.AuditState == "recorded" || r.AuditState == "overdue") && identity.Fresh(r.ObservedAt, r.ValidUntil, now, DownloadLease)
}

// One immutable restrictive decision, separately encrypted and independently
// acknowledged. It is neither a new two-phase invocation nor permission to read.
type DownloadStopDecision struct {
	Protocol, RootID, DownloadID, RequestID, StoreID string
	Actor                                            identity.Principal
	KeyDigest                                        Digest
	State                                            string
	RequestedAt, WriteUntil, RetainUntil             time.Time
}

func (d DownloadStopDecision) Valid() bool {
	return d.Protocol == DownloadStopProtocol && uuid(d.RootID) && uuid(d.DownloadID) && uuid(d.RequestID) && uuid(d.StoreID) && d.Actor.Valid() && d.KeyDigest != (Digest{}) && (d.State == "Cancelled" || d.State == "AlreadyTerminal") && !d.RequestedAt.IsZero() && d.WriteUntil.After(d.RequestedAt) && !d.WriteUntil.After(d.RequestedAt.Add(30*time.Second)) && d.RetainUntil.After(d.WriteUntil) && !d.RetainUntil.After(d.RequestedAt.Add(3660*24*time.Hour))
}
func DownloadStopKey(root, download string) string {
	return "download-stop/v1/" + root + "/" + download
}
