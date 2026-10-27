package capacity

import (
	"math"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
)

const ContextBackingFormat = "protected-context-backing/v1"

// These are the existing first-profile protocol limits, not administrator or
// capture-caller knobs. Two finite responses permit the initial content request
// and one continuation; they are not a promise to refill an exhausted session.
const (
	contextDownloadResponses = int64(2)
	// ADR-248: one 8 MiB recording response with its window read work and
	// one resume (migration 00098; pod status needed 12 MiB).
	contextDownloadReadBytes  = int64(24 << 20)
	contextDownloadRequests   = int64(3)
	contextNativeTransitions  = int64(10)
	contextCaptureKeyAttempts = int64(13)
)

// ContextBackingHistory contains independently accepted layout measurements.
// Valid numbers alone cannot establish their provenance. The protected source
// binds these complete values and their qualification IDs/digests before SQL
// may use the resulting arithmetic; no CRD status supplies them.
type ContextBackingHistory struct {
	Capture            audit.OperationHistoryQualification
	CapturePurgeLeases int64
	Native             authorization.NativeHistoryQualification
	Stop               audit.DownloadStopLifecyclePolicy
}

// ContextProtocolBacking is the closed, already-bounded part of one workload's
// prepaid graph. It is not a complete backend qualification or a SQL permit.
// The enclosing qualification additionally covers fixed enrollment/parent
// metadata, ordinary context/control/publication records and bounded recurring
// configuration WAL. Public normal/resolution/processing pools are root-level
// system commitments and are intentionally not multiplied here per workload.
type ContextProtocolBacking struct {
	Format                                                                                                         string
	Records, ReplayRecords                                                                                         int64
	Evidence, CaptureObjects, VerificationObjects, DeletionObjects, PreparationObjects, WindowObjects, StopObjects BudgetAmount
	ProtocolSystemObjects                                                                                          BudgetAmount
	Sessions, OutputBytes, ReadBytes, RequestsPerSession, Responses, Windows                                       int64
	NativeRows, NativeKeys, NativeTransitionsPerRow                                                                int64
	CaptureKeyAttempts, StopKeyAttempts, ArtifactWraps, PreparationUnwraps, ContentUnwraps                         int64
	CaptureBackupBytes, CaptureWALBytes, NativeBackupBytes, NativeWALBytes, StopBackupBytes, StopWALBytes          int64
}

// CompileContextProtocolBacking derives the retained count from the selected
// context slice. The existing response allocation caps two-response sessions
// at 512. Space beyond this closed profile remains reserved to its workload;
// neither another workload nor the shared burst can borrow it implicitly.
// This function never rounds a too-small slice up to one record.
func CompileContextProtocolBacking(contextSlice BudgetAmount, h ContextBackingHistory) (ContextProtocolBacking, error) {
	var zero ContextProtocolBacking
	if !contextSlice.positive() || !h.Capture.Valid() || h.Capture.Layout != audit.CaptureOperationHistoryLayout || h.CapturePurgeLeases < 2 || h.CapturePurgeLeases > 32 || !h.Native.Valid() || !h.Stop.Valid() {
		return zero, ErrBudgetInvalid
	}
	unit := artifact.Registration{NativeLimit: artifact.MaxContextBytes}.ReservedBytes()
	if unit <= 0 {
		return zero, ErrBudgetInvalid
	}
	n := min(contextSlice.Bytes/unit, contextSlice.Objects/4, artifact.MaxDownloadResponses/contextDownloadResponses)
	if n < 1 {
		return zero, ErrBudgetFull
	}
	out := ContextProtocolBacking{Format: ContextBackingFormat, Records: n, ReplayRecords: n,
		Sessions: n, RequestsPerSession: contextDownloadRequests, NativeTransitionsPerRow: contextNativeTransitions}
	amount := func(bytes, objects int64) (BudgetAmount, error) {
		v, ok := (BudgetAmount{Bytes: bytes, Objects: objects}).multiply(n)
		if !ok {
			return BudgetAmount{}, ErrBudgetInvalid
		}
		return v, nil
	}
	var e error
	if out.Evidence, e = amount(unit, 4); e != nil {
		return zero, e
	}
	// Record, object and protocol work remain bounded by the small-context
	// profile. Preserve authored evidence funding for the supported packet
	// output cap instead of discarding it when objects bind the record count.
	recordingUnit := (artifact.Registration{NativeLimit: artifact.RecordingNativeLimit}).ReservedBytes()
	recordingBytes, ok := capacityProduct(n, recordingUnit)
	if !ok {
		return zero, ErrBudgetInvalid
	}
	out.Evidence.Bytes = min(contextSlice.Bytes, recordingBytes)
	// Two maximum originals coexist. The deletion certificate can be written
	// only after original absence; it does not add a third simultaneous object.
	if out.CaptureObjects, e = amount(2*audit.OperationCipherLimit, 2); e != nil {
		return zero, e
	}
	if out.VerificationObjects, e = amount(128<<10, 1); e != nil {
		return zero, e
	}
	if out.DeletionObjects, e = amount(128<<10, 1); e != nil {
		return zero, e
	}
	// Preparation has its existing distinct intent/outcome objects; content
	// response/window backing does not pay for them a second time or replace it.
	if out.PreparationObjects, e = amount(2*(128<<10), 2); e != nil {
		return zero, e
	}
	if out.WindowObjects, e = amount(2*contextDownloadResponses*artifact.DownloadWindowAuditBytes, 2*contextDownloadResponses); e != nil {
		return zero, e
	}
	stopCipher, stopKeys, stopBackup, stopWAL := h.Stop.SlotBacking()
	if out.StopObjects, e = amount(stopCipher, 1); e != nil {
		return zero, e
	}
	for _, part := range []BudgetAmount{out.CaptureObjects, out.VerificationObjects, out.DeletionObjects, out.PreparationObjects, out.WindowObjects, out.StopObjects} {
		var ok bool
		out.ProtocolSystemObjects, ok = out.ProtocolSystemObjects.add(part)
		if !ok {
			return zero, ErrBudgetInvalid
		}
	}
	captureBackup, captureWAL := h.Capture.SlotBacking(h.CapturePurgeLeases)
	// The native protocol independently backs one owner and two content-key
	// rows. Its existing formula has two residual row generations, but does
	// not multiply the finite transition WAL by an additional factor of two.
	nativeBackup, ok := capacityProduct(2, h.Native.RowBytes, h.Native.BackupCopies, 1+contextDownloadResponses)
	if !ok {
		return zero, ErrBudgetInvalid
	}
	nativeWAL, ok := capacityProduct(h.Native.TransitionWALBytes, h.Native.WALCopies, contextNativeTransitions+4+8*contextDownloadResponses)
	if !ok {
		return zero, ErrBudgetInvalid
	}
	for _, field := range []struct {
		dst       *int64
		perRecord int64
	}{
		{&out.OutputBytes, 2 * artifact.RecordingNativeLimit}, {&out.ReadBytes, contextDownloadReadBytes},
		{&out.Responses, contextDownloadResponses}, {&out.Windows, contextDownloadResponses}, {&out.NativeRows, 1}, {&out.NativeKeys, contextDownloadResponses},
		// Per original phase: one seal, one self-open, two reconciliations.
		// Certificate: sign/seal/self-open and two independent verifier opens.
		{&out.CaptureKeyAttempts, contextCaptureKeyAttempts}, {&out.StopKeyAttempts, stopKeys},
		{&out.ArtifactWraps, 3}, {&out.PreparationUnwraps, 3}, {&out.ContentUnwraps, 3 * contextDownloadResponses},
		{&out.CaptureBackupBytes, captureBackup}, {&out.CaptureWALBytes, captureWAL},
		{&out.NativeBackupBytes, nativeBackup}, {&out.NativeWALBytes, nativeWAL},
		{&out.StopBackupBytes, stopBackup}, {&out.StopWALBytes, stopWAL},
	} {
		v, ok := capacityProduct(n, field.perRecord)
		if !ok {
			return zero, ErrBudgetInvalid
		}
		*field.dst = v
	}
	if !contextSlice.contains(out.Evidence) || out.OutputBytes > artifact.MaxDownloadOutput || out.ReadBytes > artifact.MaxDownloadReadWork || out.Responses > artifact.MaxDownloadResponses || out.Windows > artifact.MaxDownloadWindows || out.WindowObjects.Bytes > artifact.MaxDownloadWindowAuditBytes {
		return zero, ErrBudgetInvalid
	}
	return out, nil
}

func capacityProduct(values ...int64) (int64, bool) {
	out := int64(1)
	for _, v := range values {
		if v < 0 || v != 0 && out > math.MaxInt64/v {
			return 0, false
		}
		out *= v
	}
	return out, true
}
