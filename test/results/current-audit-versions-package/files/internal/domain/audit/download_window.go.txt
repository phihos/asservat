package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// Window audit is a new purpose/version. Historical per-chunk v1 records keep
// their original bytes and keys; current authority requires an immutable version.
// One intent/outcome pair backs a window.
type DownloadWindowIntent struct {
	Response artifact.DownloadResponse
	Window   artifact.DownloadWindow
}

func (i DownloadWindowIntent) Valid() bool {
	r, w := i.Response, i.Window
	return r.Valid() && w.Valid() && w.ResponseID == r.ID && w.SessionID == r.SessionID && w.OwnerID == r.OwnerID && w.Generation == r.Generation && w.Ordinal == r.WindowCount && w.ID == r.ActiveWindowID && w.Offset == r.Plan.Selection.Offset+r.EmittedBytes && w.Length == min(artifact.DownloadWindowBytes, r.Plan.Selection.Length-r.EmittedBytes) && !w.IntentAcknowledged && w.Outcome == nil && !w.OutcomeAcknowledged && r.CompletedWindows+1 == w.Ordinal && !r.Closed
}

type DownloadWindowAuditOutcome struct {
	Intent  DownloadWindowIntent
	Outcome artifact.DownloadWindowOutcome
}

func (o DownloadWindowAuditOutcome) Valid() bool {
	if !o.Intent.Valid() {
		return false
	}
	w := o.Intent.Window
	w.IntentAcknowledged = true
	w.Outcome = &o.Outcome
	return w.Valid() && (!o.Outcome.VerifiedFinal || w.Ordinal == o.Intent.Response.Plan.Windows())
}
func DownloadWindowAuditKey(root, response, window, phase string) string {
	return "download-window-audit/v1/" + root + "/" + response + "/" + window + "/" + phase
}
func (r Receipt) ValidDownloadWindow(i DownloadWindowIntent, phase string) bool {
	return r.Version != "" && r.Version != "null" && r.ValidHistoricalDownloadWindow(i, phase)
}

// ValidHistoricalDownloadWindow is structural history for recording already
// emitted bytes. It cannot qualify a delivery lease, key binding or completion.
func (r Receipt) ValidHistoricalDownloadWindow(i DownloadWindowIntent, phase string) bool {
	return i.Valid() && (phase == "intent" || phase == "outcome") && r.Key == DownloadWindowAuditKey(i.Window.Authority.Scope.RootID, i.Response.ID, i.Window.ID, phase) && (r.Version == "" || identity.Text(r.Version, 1024)) && identity.Text(r.ETag, 256) && r.Bytes > 0 && r.Bytes <= artifact.DownloadWindowAuditBytes && r.SHA256 != (artifact.Digest{})
}

// Completion is a phase-specific joined physical write fact for future cleanup,
// not disclosure authority or a lifecycle receipt. Only successful first PUT +
// exact independently verified GET can produce it. Find/412/unknown cannot.
type DownloadWindowWriteCompletion struct {
	RootID, ResponseID, WindowID, StoreID, Phase string
	RecordDigest                                 artifact.Digest
	Receipt                                      Receipt
	CompletedAt                                  time.Time
}

func (c DownloadWindowWriteCompletion) Valid(i DownloadWindowIntent, o *DownloadWindowAuditOutcome) bool {
	phase := "intent"
	if o != nil {
		phase = "outcome"
	}
	return i.Valid() && authorization.UUID(c.RootID) && c.RootID == i.Window.Authority.Scope.RootID && c.ResponseID == i.Response.ID && c.WindowID == i.Window.ID && authorization.UUID(c.StoreID) && c.StoreID == i.Window.AuditStoreID && c.Phase == phase && c.RecordDigest != (artifact.Digest{}) && c.Receipt.ValidDownloadWindow(i, phase) && !c.CompletedAt.Before(i.Window.StartedAt) && c.CompletedAt.Before(i.Window.WriteUntil) && (o == nil || !c.CompletedAt.Before(o.Outcome.RecordedAt))
}

type DownloadWindowWriteResult struct {
	Receipt    Receipt
	Completion *DownloadWindowWriteCompletion
}
