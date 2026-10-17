package capacity

import (
	"crypto/sha256"
	"encoding/json"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

const (
	RootBackingFormat  = "protected-capacity-root/v1"
	RootMetadataLayout = "capacity-root-history/v1"
	RootBackingBytes   = 64 << 10
	// This is a conservative implementation ceiling. Native qualification must
	// establish worst-case lock and transaction timing before enablement; the
	// unrelated 512-session arithmetic boundary is not a measured capacity.
	MaxManagedCapacityAccounts = int64(16)
)

// RootMetadataQualification covers the complete fixed source/parent graph,
// one full workload graph, and ordinary context/control/publication records
// not covered by the purpose-specific capture/native/Stop qualifications.
// A transition bound covers the entire transaction, including lock/rollback
// WAL, not just the row containing its counter. ConfigurationTransitions is a
// finite prepaid allowance; refreshing observation dates cannot refill it.
// New accepted qualification periods require their own residual-history check.
type RootMetadataQualification struct {
	ID, Layout                                                                                            string
	Digest                                                                                                artifact.Digest
	FixedRowBytes, AccountRowBytes, RecordRowBytes, RecordWALBytes, RecordKeyAttempts, TransitionWALBytes int64
	BackupCopies, WALCopies, ConfigurationTransitions                                                     int64
}

func (q RootMetadataQualification) Valid() bool {
	return authorization.UUID(q.ID) && q.Digest != (artifact.Digest{}) && q.Layout == RootMetadataLayout &&
		q.FixedRowBytes >= 1<<20 && q.FixedRowBytes <= 64<<20 &&
		q.AccountRowBytes >= 256<<10 && q.AccountRowBytes <= 16<<20 &&
		q.RecordRowBytes >= 128<<10 && q.RecordRowBytes <= 16<<20 &&
		q.RecordWALBytes >= 1<<20 && q.RecordWALBytes <= 256<<20 && q.RecordKeyAttempts >= 16 && q.RecordKeyAttempts <= 256 &&
		q.TransitionWALBytes >= 1<<20 && q.TransitionWALBytes <= 256<<20 &&
		q.BackupCopies >= 1 && q.BackupCopies <= 64 && q.WALCopies >= 1 && q.WALCopies <= 64 &&
		q.ConfigurationTransitions >= 3 && q.ConfigurationTransitions <= 1000000
}

// RootAuditBacking describes one fixed root lane. The complete lifecycle is
// shared by all consumers of that lane, including processing initialization
// and public prepare/status/content. It is not cloned per component/account.
type RootAuditBacking struct {
	Accounts, RecordsPerAccount, RetainedSeconds int64
	Policy                                       audit.OperationLifecyclePolicy
}

func (p RootAuditBacking) valid(root, installation, lane, layout string) bool {
	if p.Accounts < 1 || p.Accounts > 1000000 || p.RecordsPerAccount < 1 || p.RecordsPerAccount > 1000000 || p.RetainedSeconds < 60 || p.RetainedSeconds > 316224000 || !p.Policy.CertificateVerificationBacked() || p.Policy.RootID != root || p.Policy.InstallationID != installation || p.Policy.Lane != lane || p.Policy.History.Layout != layout || p.Policy.BackingRevision != 1 || p.Policy.OverdueTerminal != audit.OperationOverdueTerminal {
		return false
	}
	slots, ok := capacityProduct(p.Accounts, p.RecordsPerAccount)
	// Exact values keep unused prepaid slots explicit and prevent unrelated
	// component profiles from silently claiming the same logical reserve.
	return ok && slots == p.Policy.MetadataSlots && p.RetainedSeconds > 2*p.Policy.BackupHorizonSeconds+3*p.Policy.CleanupBudgetSeconds+p.Policy.ProofWindowSeconds+30
}

// RootBackingInput is an independently protected installer input. None of its
// qualification IDs, store envelopes or role-owned lifecycle identities come
// from EvidenceStoragePool status or an individual capture request.
type RootBackingInput struct {
	Format, RootID, InstallationID, QualificationID string
	QualificationDigest                             artifact.Digest
	SystemPoolUID, AccountVersion                   string
	Accounts, RecordsPerAccount                     int64
	// Derived by the protected installer profile. It bounds a new configuration
	// revision; it never extends an original SQL phase or admitted session.
	AdmissionSeconds                        int64
	Capture, Normal, Resolution, Processing RootAuditBacking
	ProcessingState                         privacy.ProcessingBacking
	ProcessingEpoch, ProcessingSourceUID    string
	ProcessingProtectionDigest              artifact.Digest
	ContextHistory                          ContextBackingHistory
	StopRetainedSeconds                     int64
	Metadata                                RootMetadataQualification
	Envelope                                RootBackingEnvelope
}

// Object capacity is checked against the designated public system slice as
// well as this accepted physical/logical envelope. SQL and backup/WAL costs
// are distinct dimensions and cannot be paid using unused evidence bytes.
type RootBackingEnvelope struct {
	SystemObjects                                BudgetAmount
	SQLBytes, BackupBytes, WALBytes, KeyAttempts int64
}

type RootBackingTotals struct {
	Accounts, RecordsPerAccount, Records         int64
	SystemObjects                                BudgetAmount
	SQLBytes, BackupBytes, WALBytes, KeyAttempts int64
	ConfigurationTransitions                     int64
}

// RootBackingPlan contains canonical immutable values; accessors return new
// copies. SQL independently recompiles the protected input and compares both
// exact bytes/digest and the complete semantic object.
type RootBackingPlan struct {
	canonical string
	digest    artifact.Digest
	totals    RootBackingTotals
}

func (p RootBackingPlan) Canonical() ([]byte, artifact.Digest) { return []byte(p.canonical), p.digest }
func (p RootBackingPlan) Totals() RootBackingTotals            { return p.totals }

// ValidateRootBackingInput checks the complete static cost vector against its
// own finite installed envelope before an irreversible setup claim. This does
// not observe a source pool or accept that envelope; CompileQualifiedRootBacking
// must still match the independently accepted actual pool before funding it.
func ValidateRootBackingInput(in RootBackingInput) bool {
	_, err := CompileRootBacking(in, ProtectedPoolPlan{Format: ProtectedPoolPlanFormat, UID: in.SystemPoolUID, System: in.Envelope.SystemObjects})
	return err == nil
}

func CompileRootBacking(in RootBackingInput, systemPool ProtectedPoolPlan) (RootBackingPlan, error) {
	var zero RootBackingPlan
	if in.Format != RootBackingFormat || !authorization.UUID(in.RootID) || !authorization.UUID(in.InstallationID) || !authorization.UUID(in.QualificationID) || in.QualificationDigest == (artifact.Digest{}) || !identity.Text(in.SystemPoolUID, 64) || !identity.Text(in.AccountVersion, 64) || in.Accounts < 1 || in.Accounts > MaxManagedCapacityAccounts || in.RecordsPerAccount < 1 || in.RecordsPerAccount > artifact.MaxDownloadResponses/contextDownloadResponses || in.AdmissionSeconds < 60 || in.AdmissionSeconds > 86400 || !authorization.UUID(in.ProcessingEpoch) || !authorization.UUID(in.ProcessingSourceUID) || in.ProcessingProtectionDigest == (artifact.Digest{}) || !in.Metadata.Valid() || systemPool.Format != ProtectedPoolPlanFormat || systemPool.UID != in.SystemPoolUID || !systemPool.System.positive() {
		return zero, ErrBudgetInvalid
	}
	for _, x := range []struct {
		p            RootAuditBacking
		lane, layout string
	}{
		{in.Capture, "capture", audit.CaptureOperationHistoryLayout},
		{in.Normal, "normal", audit.OperationVerificationHistoryLayout},
		{in.Resolution, "resolution", audit.OperationVerificationHistoryLayout},
		{in.Processing, "processing", audit.ProcessingReleaseHistoryLayout},
	} {
		if !x.p.valid(in.RootID, in.InstallationID, x.lane, x.layout) || x.p.Policy.StoreID != in.Capture.Policy.StoreID || !x.p.Policy.ValidUntil.Equal(in.Capture.Policy.ValidUntil) {
			return zero, ErrBudgetInvalid
		}
	}
	if in.Capture.Accounts != in.Accounts || in.Capture.RecordsPerAccount != in.RecordsPerAccount || in.Capture.Policy.History == nil || *in.Capture.Policy.History != in.ContextHistory.Capture || in.Capture.Policy.MaxPurgeLeases != in.ContextHistory.CapturePurgeLeases || in.ContextHistory.Stop.RootID != in.RootID || in.ContextHistory.Stop.InstallationID != in.InstallationID || in.ContextHistory.Stop.StoreID != in.Capture.Policy.StoreID || in.StopRetainedSeconds < 60 || in.StopRetainedSeconds > 316224000 || in.StopRetainedSeconds <= 2*in.ContextHistory.Stop.BackupHorizonSeconds+3*in.ContextHistory.Stop.CleanupBudgetSeconds+in.ContextHistory.Stop.ProofWindowSeconds+30 {
		return zero, ErrBudgetInvalid
	}
	// A single workload's complete worst case is funded for every root slot,
	// even when current source matching enrolls a smaller workload account.
	unit := artifact.Registration{NativeLimit: artifact.MaxContextBytes}.ReservedBytes()
	bytes, ok := capacityProduct(unit, in.RecordsPerAccount)
	if !ok {
		return zero, ErrBudgetInvalid
	}
	objects, ok := capacityProduct(4, in.RecordsPerAccount)
	if !ok {
		return zero, ErrBudgetInvalid
	}
	work, e := CompileContextProtocolBacking(BudgetAmount{bytes, objects}, in.ContextHistory)
	if e != nil || work.Records != in.RecordsPerAccount {
		return zero, ErrBudgetInvalid
	}
	t := RootBackingTotals{Accounts: in.Accounts, RecordsPerAccount: in.RecordsPerAccount, ConfigurationTransitions: in.Metadata.ConfigurationTransitions}
	if t.Records, ok = capacityProduct(in.Accounts, in.RecordsPerAccount); !ok {
		return zero, ErrBudgetInvalid
	}
	ps := in.ProcessingState
	if !ps.Valid() || ps.RootID != in.RootID || ps.InstallationID != in.InstallationID || ps.MaxCaptures < t.Records || in.Processing.Policy.MetadataSlots < ps.MaxRules*privacy.MaxProcessingChanges || !ps.ValidUntil.Equal(in.Capture.Policy.ValidUntil) {
		return zero, ErrBudgetInvalid
	}
	cb, ok := capacityProduct(in.Accounts, work.CaptureBackupBytes)
	if !ok || cb != in.Capture.Policy.BackupReservedBytes {
		return zero, ErrBudgetInvalid
	}
	cw, ok := capacityProduct(in.Accounts, work.CaptureWALBytes)
	if !ok || cw != in.Capture.Policy.WALReservedBytes {
		return zero, ErrBudgetInvalid
	}
	if t.SystemObjects, ok = work.ProtocolSystemObjects.multiply(in.Accounts); !ok {
		return zero, ErrBudgetInvalid
	}
	// Capture, Stop and native costs already occur in work. Root normal,
	// resolution and processing are added exactly once here.
	add := func(dst *int64, values ...int64) bool {
		v, ok := capacityProduct(values...)
		if !ok {
			return false
		}
		return capacityAddTo(dst, v)
	}
	processingRows := 1 + ps.MaxRootTransitions + ps.MaxCaptures + (1+privacy.MaxProcessingChanges)*ps.MaxRules
	if !add(&t.SQLBytes, processingRows, ps.History.RowBytes) || !add(&t.BackupBytes, ps.BackupBytes) || !add(&t.WALBytes, ps.WALBytes) {
		return zero, ErrBudgetInvalid
	}
	for _, lane := range []RootAuditBacking{in.Normal, in.Resolution, in.Processing} {
		n := lane.Policy.MetadataSlots
		objects, ok := (BudgetAmount{2 * audit.OperationCipherLimit, 2}).multiply(n)
		if !ok {
			return zero, ErrBudgetInvalid
		}
		if t.SystemObjects, ok = t.SystemObjects.add(objects); !ok {
			return zero, ErrBudgetInvalid
		}
		if !add(&t.SQLBytes, n, lane.Policy.History.MaximumRowFootprintBytes) || !add(&t.BackupBytes, lane.Policy.BackupReservedBytes) || !add(&t.WALBytes, lane.Policy.WALReservedBytes) || !add(&t.KeyAttempts, 13, n) {
			return zero, ErrBudgetInvalid
		}
	}
	for _, cost := range []int64{work.CaptureBackupBytes, work.NativeBackupBytes, work.StopBackupBytes} {
		if !add(&t.BackupBytes, in.Accounts, cost) {
			return zero, ErrBudgetInvalid
		}
	}
	for _, cost := range []int64{work.CaptureWALBytes, work.NativeWALBytes, work.StopWALBytes} {
		if !add(&t.WALBytes, in.Accounts, cost) {
			return zero, ErrBudgetInvalid
		}
	}
	// Verification/deletion/preparation/window protocol key bounds are part
	// of the accepted ordinary-record qualification, not unlimited IO credit.
	// Their eight maximum audit objects need at least seal+independent open;
	// artifact wraps and native/preparation unwraps are counted separately.
	for _, cost := range []int64{work.CaptureKeyAttempts, work.StopKeyAttempts, work.ArtifactWraps, work.PreparationUnwraps, work.ContentUnwraps} {
		if !add(&t.KeyAttempts, in.Accounts, cost) {
			return zero, ErrBudgetInvalid
		}
	}
	q := in.Metadata
	if q.ConfigurationTransitions < 3+3*in.Accounts {
		return zero, ErrBudgetInvalid
	}
	var ordinarySQL int64
	if !add(&ordinarySQL, q.FixedRowBytes) || !add(&ordinarySQL, in.Accounts, q.AccountRowBytes) || !add(&ordinarySQL, t.Records, q.RecordRowBytes) || !add(&t.SQLBytes, ordinarySQL) || !add(&t.KeyAttempts, t.Records, q.RecordKeyAttempts) {
		return zero, ErrBudgetInvalid
	}
	if !add(&t.BackupBytes, 2, q.BackupCopies, ordinarySQL) || !add(&t.WALBytes, q.ConfigurationTransitions, q.TransitionWALBytes, q.WALCopies) || !add(&t.WALBytes, t.Records, q.RecordWALBytes, q.WALCopies) {
		return zero, ErrBudgetInvalid
	}
	if !add(&t.SQLBytes, t.Records, in.ContextHistory.Capture.MaximumRowFootprintBytes) || !add(&t.SQLBytes, t.Records, in.ContextHistory.Stop.MaximumRowFootprintBytes) || !add(&t.SQLBytes, in.Accounts, work.NativeRows+work.NativeKeys, in.ContextHistory.Native.RowBytes) {
		return zero, ErrBudgetInvalid
	}
	if !systemPool.System.contains(t.SystemObjects) || !in.Envelope.SystemObjects.contains(t.SystemObjects) || in.Envelope.SQLBytes < t.SQLBytes || in.Envelope.BackupBytes < t.BackupBytes || in.Envelope.WALBytes < t.WALBytes || in.Envelope.KeyAttempts < t.KeyAttempts {
		return zero, ErrBudgetFull
	}
	wire := struct {
		Input  RootBackingInput
		Totals RootBackingTotals
	}{in, t}
	b, e := json.Marshal(wire)
	if e != nil || len(b) > RootBackingBytes {
		return zero, ErrBudgetInvalid
	}
	h := sha256.New()
	_, _ = h.Write([]byte("asservat-capacity-root/json-v1\x00"))
	_, _ = h.Write(b)
	var digest artifact.Digest
	copy(digest[:], h.Sum(nil))
	return RootBackingPlan{string(b), digest, t}, nil
}

func capacityAddTo(dst *int64, v int64) bool {
	if v < 0 || *dst < 0 || v > int64(^uint64(0)>>1)-*dst {
		return false
	}
	*dst += v
	return true
}
