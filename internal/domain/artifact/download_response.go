package artifact

import (
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

const (
	DownloadResponseVersion           = 1
	DownloadWindowBytes         int64 = 64 << 20
	DownloadWindowAuditBytes    int64 = 128 << 10
	MaxDownloadResponses        int64 = 1024
	MaxDownloadWindows                = MaxDownloadOutput/DownloadWindowBytes + MaxDownloadResponses
	MaxDownloadWindowAuditBytes       = 2 * MaxDownloadWindows * DownloadWindowAuditBytes
	// MaxDownloadWindowWrite bounds a window's audit write deadline, which SQL
	// pins to its control allocation's AuditWriteUntil. A protected-capacity
	// control lives up to its 24 h admission plus the 5 min audit grace, so the
	// former 8 h + 5 min response bound refused every capacity-backed window.
	MaxDownloadWindowWrite = 24*time.Hour + 5*time.Minute
)

// DownloadControlAllocation is protected configuration, independent of evidence
// output/read quota. Existing download allocations have no implicit control
// credit. Original reservations remain charged until qualified lifecycle cleanup.
type DownloadControlAllocation struct {
	ID, RootID, AuditStoreID                   string
	ResponseLimit, WindowLimit, AuditByteLimit int64
	ValidUntil, AuditWriteUntil                time.Time
}

func (a DownloadControlAllocation) Valid() bool {
	return uuid(a.ID) && uuid(a.RootID) && uuid(a.AuditStoreID) && a.ResponseLimit > 0 && a.ResponseLimit <= MaxDownloadResponses && a.WindowLimit > 0 && a.WindowLimit <= MaxDownloadWindows && a.AuditByteLimit > 0 && a.AuditByteLimit <= MaxDownloadWindowAuditBytes && !a.ValidUntil.IsZero() && a.AuditWriteUntil.After(a.ValidUntil) && !a.AuditWriteUntil.After(a.ValidUntil.Add(5*time.Minute))
}

// Plan uses a verified native selection, not public caller sizes. The read bound
// comes from the protected framed reader. It is not an in-memory buffer size.
// No native hash, filename or payload is persisted with this plan.
type DownloadResponsePlan struct {
	Version         int
	Selection       DownloadSelection
	WholeFile       bool
	WindowReadLimit int64
}

func (p DownloadResponsePlan) Windows() int64 {
	if p.Selection.Length == 0 {
		return 1
	}
	return (p.Selection.Length-1)/DownloadWindowBytes + 1
}
func (p DownloadResponsePlan) AuditBytes() int64 { return p.Windows() * 2 * DownloadWindowAuditBytes }
func (p DownloadResponsePlan) ReadBytes() int64  { return p.Windows() * p.WindowReadLimit }
func (p DownloadResponsePlan) Valid() bool {
	r := p.Selection
	return p.Version == DownloadResponseVersion && r.Offset >= 0 && r.Length >= 0 && r.Offset <= MaxNativeBytes && r.Length <= MaxNativeBytes-r.Offset && (!r.Partial || r.Length > 0) && (!p.WholeFile || r.Offset == 0) && p.WindowReadLimit > 0 && p.WindowReadLimit <= MaxDownloadReadWork/p.Windows()
}

type DownloadResponse struct {
	ID, SessionID, OwnerID                      string
	Generation                                  int64
	Plan                                        DownloadResponsePlan
	StartedAt, Until                            time.Time
	WindowCount, CompletedWindows, EmittedBytes int64
	ActiveWindowID                              string
	LeaseSequence                               int64
	LeaseUntil                                  time.Time
	Closed                                      bool
}

func (r DownloadResponse) Valid() bool {
	return uuid(r.ID) && uuid(r.SessionID) && uuid(r.OwnerID) && r.Generation > 0 && r.Plan.Valid() && !r.StartedAt.IsZero() && r.Until.After(r.StartedAt) && !r.Until.After(r.StartedAt.Add(8*time.Hour)) && r.WindowCount >= 0 && r.WindowCount <= r.Plan.Windows() && r.CompletedWindows >= 0 && r.CompletedWindows <= r.WindowCount && r.EmittedBytes >= 0 && r.EmittedBytes <= r.Plan.Selection.Length && (r.ActiveWindowID == "" || uuid(r.ActiveWindowID)) && r.LeaseSequence >= 0 && (!r.LeaseUntil.After(r.Until))
}
func (s DownloadSession) BeginResponse(a DownloadAuthority, r DownloadResponse, now time.Time) (DownloadSession, DownloadResponse, error) {
	if e := s.current(a, now); e != nil {
		return s, r, e
	}
	if s.State == DownloadPreparing || s.Active != nil && now.Before(s.Active.LeaseUntil) {
		return s, r, ErrDownloadConflict
	}
	if !uuid(r.ID) || r.SessionID != s.ID || !uuid(r.OwnerID) || !r.Plan.Valid() || r.Generation != 0 || r.WindowCount != 0 || r.CompletedWindows != 0 || r.EmittedBytes != 0 || r.ActiveWindowID != "" || r.LeaseSequence != 0 || !r.LeaseUntil.IsZero() || r.Closed || !r.Until.After(now) || r.Until.After(s.Deadline) || r.Until.After(a.AccessUntil) {
		return s, r, ErrInvalid
	}
	if r.Plan.Selection.Length > s.OutputLimit-s.ChargedOutput || r.Plan.ReadBytes() > s.ReadLimit-s.ChargedRead {
		return s, r, ErrDownloadCapacity
	}
	s.Generation++
	s.Active = nil
	s.State = DownloadStreaming
	r.Generation = s.Generation
	r.StartedAt = now
	r.LeaseUntil = identity.Earlier(a.ValidUntil, r.Until)
	if !r.Valid() {
		return s, r, ErrInvalid
	}
	return s, r, nil
}

// A window is prepaid accounting, not a five-second disclosure lease. Its
// separately acknowledged encrypted intent must precede any contained byte.
type DownloadWindow struct {
	ID, ResponseID, SessionID, OwnerID, AuditStoreID string
	Generation, Ordinal, Offset, Length, ReadLimit   int64
	StartedAt, WriteUntil                            time.Time
	Authority                                        DownloadAuthority
	IntentAcknowledged                               bool
	Outcome                                          *DownloadWindowOutcome
	OutcomeAcknowledged                              bool
}
type DownloadWindowOutcome struct {
	EmittedBytes           int64
	Success, VerifiedFinal bool
	RecordedAt             time.Time
}

func (w DownloadWindow) Valid() bool {
	if !uuid(w.ID) || !uuid(w.ResponseID) || !uuid(w.SessionID) || !uuid(w.OwnerID) || !uuid(w.AuditStoreID) || w.Generation < 1 || w.Ordinal < 1 || w.Ordinal > MaxNativeBytes/DownloadWindowBytes || w.Offset < 0 || w.Offset > MaxNativeBytes || w.Length < 0 || w.Length > DownloadWindowBytes || w.Length > MaxNativeBytes-w.Offset || w.ReadLimit < 1 || w.ReadLimit > MaxDownloadReadWork || !w.Authority.Valid(w.StartedAt) || !w.WriteUntil.After(w.StartedAt) || w.WriteUntil.After(w.StartedAt.Add(MaxDownloadWindowWrite)) {
		return false
	}
	if w.Outcome == nil {
		return !w.OutcomeAcknowledged
	}
	o := w.Outcome
	return o.EmittedBytes >= 0 && o.EmittedBytes <= w.Length && !o.RecordedAt.Before(w.StartedAt) && (!o.Success || o.EmittedBytes == w.Length) && (!o.VerifiedFinal || o.Success) && (!o.Success || w.IntentAcknowledged) && (!w.OutcomeAcknowledged || w.IntentAcknowledged)
}
func (r DownloadResponse) current(s DownloadSession, a DownloadAuthority, owner string, now time.Time) error {
	if e := s.current(a, now); e != nil {
		return e
	}
	if !r.Valid() || r.SessionID != s.ID || r.Generation != s.Generation || r.OwnerID != owner || r.Closed || !now.Before(r.Until) {
		return ErrDownloadExpired
	}
	return nil
}
func (r DownloadResponse) BeginWindow(s DownloadSession, a DownloadAuthority, id, storeID string, writeUntil, now time.Time) (DownloadSession, DownloadResponse, DownloadWindow, error) {
	var w DownloadWindow
	if e := r.current(s, a, r.OwnerID, now); e != nil {
		return s, r, w, e
	}
	if r.ActiveWindowID != "" || r.WindowCount != r.CompletedWindows || r.WindowCount >= r.Plan.Windows() || !uuid(id) {
		return s, r, w, ErrDownloadConflict
	}
	length := min(DownloadWindowBytes, r.Plan.Selection.Length-r.EmittedBytes)
	if length > s.OutputLimit-s.ChargedOutput || r.Plan.WindowReadLimit > s.ReadLimit-s.ChargedRead {
		return s, r, w, ErrDownloadCapacity
	}
	w = DownloadWindow{ID: id, AuditStoreID: storeID, ResponseID: r.ID, SessionID: s.ID, OwnerID: r.OwnerID, Generation: r.Generation, Ordinal: r.WindowCount + 1, Offset: r.Plan.Selection.Offset + r.EmittedBytes, Length: length, ReadLimit: r.Plan.WindowReadLimit, StartedAt: now, WriteUntil: writeUntil, Authority: a}
	if !w.Valid() {
		return s, r, DownloadWindow{}, ErrInvalid
	}
	r.WindowCount++
	r.LeaseUntil = identity.Earlier(a.ValidUntil, r.Until)
	r.ActiveWindowID = id
	s.ChargedOutput += w.Length
	s.ChargedRead += w.ReadLimit
	return s, r, w, nil
}

// DeliveryLease carries one existing current authority observation. Its original
// bounds survive all I/O; sequential chunks may reuse it but never renew it.
type DownloadDeliveryLease struct {
	ResponseID, WindowID, OwnerID string
	Generation, Sequence          int64
	Offset, Length                int64
	StartedAt, Until              time.Time
	Authority                     DownloadAuthority
}

func (l DownloadDeliveryLease) Valid(now time.Time) bool {
	return uuid(l.ResponseID) && uuid(l.WindowID) && uuid(l.OwnerID) && l.Generation > 0 && l.Sequence > 0 && l.Offset >= 0 && l.Length >= 0 && l.Length <= DownloadWindowBytes && l.Offset <= MaxNativeBytes-l.Length && identity.Fresh(l.StartedAt, l.Until, now, DownloadLease) && l.Authority.Valid(now) && !l.Until.After(l.Authority.ValidUntil)
}
func (r DownloadResponse) Lease(s DownloadSession, w DownloadWindow, a DownloadAuthority, owner string, now time.Time) (DownloadResponse, DownloadDeliveryLease, error) {
	var l DownloadDeliveryLease
	if e := r.current(s, a, owner, now); e != nil {
		return r, l, e
	}
	if !w.Valid() || !w.IntentAcknowledged || w.Outcome != nil || w.ResponseID != r.ID || w.SessionID != s.ID || w.Generation != r.Generation || w.OwnerID != owner || w.ID != r.ActiveWindowID || w.Authority.Scope != a.Scope {
		return r, l, ErrDownloadConflict
	}
	r.LeaseSequence++
	r.LeaseUntil = identity.Earlier(a.ValidUntil, r.Until)
	l = DownloadDeliveryLease{ResponseID: r.ID, WindowID: w.ID, OwnerID: owner, Generation: r.Generation, Sequence: r.LeaseSequence, Offset: w.Offset, Length: w.Length, StartedAt: now, Until: r.LeaseUntil, Authority: a}
	if !l.Valid(now) {
		return r, DownloadDeliveryLease{}, ErrDownloadExpired
	}
	return r, l, nil
}
func (l DownloadDeliveryLease) Allows(offset, length int64, now time.Time) bool {
	return l.Valid(now) && offset >= l.Offset && offset <= l.Offset+l.Length && length >= 0 && length <= DeliveryBytes && length <= l.Offset+l.Length-offset
}

// RecordWindow closes one original accounting fact after writers have joined.
// It never refunds uncertainty or makes a stored result current authority.
func (r DownloadResponse) RecordWindow(s DownloadSession, w DownloadWindow, o DownloadWindowOutcome, now time.Time) (DownloadSession, DownloadResponse, DownloadWindow, error) {
	if !r.Valid() || !s.Valid() || !w.Valid() || w.ResponseID != r.ID || w.SessionID != s.ID || w.Generation != r.Generation || w.ID != r.ActiveWindowID || w.Ordinal != r.CompletedWindows+1 || w.Offset != r.Plan.Selection.Offset+r.EmittedBytes || w.Outcome != nil {
		return s, r, w, ErrDownloadConflict
	}
	o.RecordedAt = now
	w.Outcome = &o
	if !w.Valid() || o.VerifiedFinal && (w.Ordinal != r.Plan.Windows() || !o.Success) {
		return s, r, w, ErrInvalid
	}
	// Accounting is historical even after replacement/cancellation. Never report
	// completion before the independent encrypted outcome has been acknowledged.
	s.EmittedBytes += o.EmittedBytes
	if !s.Valid() {
		return s, r, w, ErrInvalid
	}
	return s, r, w, nil
}
func (r DownloadResponse) AcknowledgeWindow(s DownloadSession, w DownloadWindow, now time.Time) (DownloadSession, DownloadResponse, DownloadWindow, error) {
	if !r.Valid() || !s.Valid() || !w.Valid() || w.ResponseID != r.ID || w.SessionID != s.ID || w.Generation != r.Generation || w.ID != r.ActiveWindowID || w.Ordinal != r.CompletedWindows+1 || w.Offset != r.Plan.Selection.Offset+r.EmittedBytes || w.Outcome == nil || w.OutcomeAcknowledged {
		return s, r, w, ErrDownloadConflict
	}
	w.OutcomeAcknowledged = true
	o := w.Outcome
	r.EmittedBytes += o.EmittedBytes
	r.CompletedWindows++
	r.ActiveWindowID = ""
	final := r.CompletedWindows == r.Plan.Windows()
	if !o.Success || final {
		r.Closed = true
	}
	if s.Generation == r.Generation && !s.State.Terminal() {
		if !now.Before(s.Deadline) || !now.Before(r.Until) {
			s.State = DownloadExpired
			r.Closed = true
		} else if !o.Success || final {
			s.State = DownloadInterrupted
			if final && o.Success && o.VerifiedFinal && r.Plan.WholeFile && r.EmittedBytes == r.Plan.Selection.Length {
				s.State = DownloadCompleted
			}
		}
	}
	return s, r, w, nil
}
