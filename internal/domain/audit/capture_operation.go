package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

const CaptureOperationName = "persist_capture_intent"
const CaptureOperationInputFormat = "capture-intent/v2"
const CaptureOperationHistoryLayout = "capture-intent-history/v1"
const CaptureOperationReconcileAttempts = 2

// This private payload is the already accepted minimized intent, never a public
// input or collection authority. Legacy absent-field encodings are unchanged.
func (r OperationIntent) capturePayloadValid() bool {
	if r.Name != CaptureOperationName {
		return r.Capture == nil
	}
	c := r.Capture
	if c == nil || !c.Valid() || c.Actor.Kind != identity.Human || r.Actor != c.Actor || r.Peer != nil || r.Process != nil || r.ID != c.CaptureID || r.RootID != c.RootID || r.TraceID != c.OccurrenceID || r.InputFormat != CaptureOperationInputFormat || !r.CreatedAt.Equal(c.CreatedAt) || r.WriteUntil.After(c.Deadline) {
		return false
	}
	// BindOperationLifecycle first validates the payload without a binding.
	// Actual capture admission additionally requires CaptureOperationPolicy.
	return r.Lifecycle == nil || CaptureOperationPolicy(r.Lifecycle.Policy)
}
func (r OperationOutcome) captureOutcomeValid() bool {
	if r.Intent.Name != CaptureOperationName {
		return true
	}
	// Persistence of already accepted intent says nothing about acquisition.
	return r.Status == "success" && r.Reason == "prepared" && r.Effect == "accepted" && len(r.CaseIDs) == 0 && len(r.ArtifactIDs) == 0 && len(r.CaptureIDs) == 1 && r.CaptureIDs[0] == r.Intent.ID && r.OutputBytes == 0 && r.Credential == nil
}
func CaptureOperationPolicy(p OperationLifecyclePolicy) bool {
	return p.CertificateVerificationBacked() && p.Lane == "capture" && p.History != nil && p.History.Layout == CaptureOperationHistoryLayout
}

// Private protected account selection. The stable digest identifies only this
// installation/root/allocation; changing human/client cannot consume another
// workload's guaranteed account. It is still privacy-relevant correlation.
type CaptureAuditAccount struct {
	RootID, AllocationID, AccountVersion string
	AccountDigest                        artifact.Digest
	Revision                             int64
	Records, RetainedSeconds             int64
	Policy                               OperationLifecyclePolicy
}

func (a CaptureAuditAccount) Valid() bool {
	return authorization.UUID(a.RootID) && authorization.UUID(a.AllocationID) && identity.Text(a.AccountVersion, 64) && a.AccountDigest != (artifact.Digest{}) && a.Revision > 0 && a.Revision <= 1<<60 && a.Records > 0 && a.Records <= 1000000 && a.RetainedSeconds >= 60 && a.RetainedSeconds <= 316224000 && CaptureOperationPolicy(a.Policy) && a.Policy.RootID == a.RootID
}

// The two exact read intervals are immutable prepaid work claims. They are not
// writer completion, current acquisition authority or a renewable lease.
type CaptureReconciliationClaim struct {
	Attempt int64
	Until   time.Time
}

func (c CaptureReconciliationClaim) Valid() bool {
	return c.Attempt >= 1 && c.Attempt <= CaptureOperationReconcileAttempts && microTime(c.Until)
}

// Fresh is true only for an acknowledged irreversible first claim. Until is
// the original SQL observation bound, carried through the joined object call.
type CaptureWriteClaim struct {
	Fresh bool
	Until time.Time
}

func (c CaptureWriteClaim) Valid() bool { return microTime(c.Until) }
