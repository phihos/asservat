package artifact

import (
	"asservat.local/asservat/internal/domain/identity"
	"errors"
	"time"
)

var (
	ErrDownloadConflict    = errors.New("download operation conflicts")
	ErrDownloadUnavailable = errors.New("download unavailable")
	ErrDownloadCapacity    = errors.New("download capacity exhausted")
	ErrDownloadExpired     = errors.New("download authority or session expired")
)

type DownloadState string

const (
	DownloadPreparing   DownloadState = "Preparing"
	DownloadReady       DownloadState = "Ready"
	DownloadStreaming   DownloadState = "Streaming"
	DownloadInterrupted DownloadState = "Interrupted"
	DownloadCompleted   DownloadState = "Completed"
	DownloadCancelled   DownloadState = "Cancelled"
	DownloadExpired     DownloadState = "Expired"
	DownloadDenied      DownloadState = "Denied"
	DownloadFailed      DownloadState = "Failed"
)

func (s DownloadState) Terminal() bool {
	return s == DownloadCompleted || s == DownloadCancelled || s == DownloadExpired || s == DownloadDenied || s == DownloadFailed
}
func (s DownloadState) Valid() bool {
	return s == DownloadPreparing || s == DownloadReady || s == DownloadStreaming || s == DownloadInterrupted || s.Terminal()
}

// DownloadScope contains identifiers and ciphertext/accepted-scope digests only.
// Native checksums, filenames and evidence never enter the SQL session record.
type DownloadScope struct {
	RootID, ArtifactID, CaptureID, ClusterID, NamespaceUID, WorkloadUID, PodUID string
	Version                                                                     Digest
	Principal                                                                   identity.Principal
}

func (s DownloadScope) Valid() bool {
	return uuid(s.RootID) && uuid(s.ArtifactID) && uuid(s.CaptureID) && uuid(s.ClusterID) && identity.Text(s.NamespaceUID, 64) && identity.Text(s.WorkloadUID, 64) && identity.Text(s.PodUID, 64) && s.Version != (Digest{}) && s.Principal.Valid()
}

// DownloadAuthority is a current internal decision, never decoded public input.
// The short effect lease is distinct from the absolute session/access deadline.
// Eligibility, current retention/locality and raw coverage must precede it.
type DownloadAuthority struct {
	Environment                        DownloadEnvironment `json:",omitzero"`
	Retention                          RetentionProof      `json:",omitzero"`
	Scope                              DownloadScope
	PermissionEpoch                    string
	PermissionSequence                 int64
	ProjectionDigest, DecisionDigest   Digest
	IdentityRevision                   identity.Revision
	CheckedAt, ValidUntil, AccessUntil time.Time
	// Optional only for historical v1 audit decoding. Current disclosure requires it.
	DeleteBy time.Time `json:",omitzero"`
}

func (a DownloadAuthority) Valid(now time.Time) bool {
	return (a.Environment == (DownloadEnvironment{}) || (a.Environment.Valid(now) && a.Environment.RootID == a.Scope.RootID && a.Environment.Location.ClusterID == a.Scope.ClusterID && a.Environment.Location.ArtifactID == a.Scope.ArtifactID && a.Environment.Principal == a.Scope.Principal && !a.ValidUntil.After(a.Environment.ValidUntil))) && (a.Retention == (RetentionProof{}) || (a.Retention.Valid(now) && a.Retention.Matches(a.Scope.RootID, a.Scope.ClusterID, a.Scope.NamespaceUID, a.Scope.WorkloadUID, a.Scope.PodUID) && !a.ValidUntil.After(a.Retention.ValidUntil))) && a.Scope.Valid() && uuid(a.PermissionEpoch) && a.PermissionSequence > 0 && a.ProjectionDigest != (Digest{}) && a.DecisionDigest != (Digest{}) && a.IdentityRevision.Valid() && identity.Fresh(a.CheckedAt, a.ValidUntil, now, 5*time.Second) && !a.ValidUntil.After(a.AccessUntil) && (a.DeleteBy.IsZero() || a.AccessUntil.Before(a.DeleteBy))
}

const (
	MaxDownloadRequests int64 = 1024
	MaxDownloadOutput   int64 = 16 * MaxNativeBytes
	MaxDownloadReadWork int64 = 64 * MaxNativeBytes
	DownloadLease             = 5 * time.Second
)

// Each workload receives a separate finite transfer allocation. It is disjoint
// from incident upload/storage reservations. Configuration alone is not access.
type DownloadAllocation struct {
	ID, RootID, ClusterID, NamespaceUID, WorkloadUID string
	OutputLimit, ReadLimit, SessionLimit             int64
	ValidUntil                                       time.Time
}

func (a DownloadAllocation) Valid() bool {
	return uuid(a.ID) && uuid(a.RootID) && uuid(a.ClusterID) && identity.Text(a.NamespaceUID, 64) && identity.Text(a.WorkloadUID, 64) && a.OutputLimit > 0 && a.OutputLimit <= MaxDownloadOutput && a.ReadLimit > 0 && a.ReadLimit <= MaxDownloadReadWork && a.SessionLimit > 0 && a.SessionLimit <= 100000 && !a.ValidUntil.IsZero()
}
func (a DownloadAllocation) Covers(s DownloadScope) bool {
	return a.RootID == s.RootID && a.ClusterID == s.ClusterID && a.NamespaceUID == s.NamespaceUID && a.WorkloadUID == s.WorkloadUID
}

type DownloadSession struct {
	// Absent only for historical/component sessions; public acquisition requires prepaid stop.
	StopProtocol                                       string `json:",omitzero"`
	ID, AllocationID                                   string
	Scope                                              DownloadScope
	RequestDigest                                      Digest
	State                                              DownloadState
	CreatedAt, Deadline                                time.Time
	OutputLimit, ReadLimit, RequestLimit               int64
	ChargedOutput, ChargedRead, Requests, EmittedBytes int64
	Generation                                         int64
	Active                                             *DownloadBatch
}
type DownloadPurpose string

const (
	DownloadMetadata DownloadPurpose = "prepare"
	DownloadContent  DownloadPurpose = "content"
)

// A batch is prepaid and has a write-once encrypted audit before any disclosure.
// Lost replies keep the charge. A lease timeout permits a fresh generation but
// never retries the previous bytes for free or proves its writer stopped.
type DownloadBatch struct {
	ID                             string
	Generation                     int64
	Purpose                        DownloadPurpose
	Offset, OutputBytes, ReadBytes int64
	StartedAt, LeaseUntil          time.Time
	Authority                      DownloadAuthority
	AuditAcknowledged              bool
}

func (s DownloadSession) Valid() bool {
	return (s.StopProtocol == "" || s.StopProtocol == DownloadStopProtocol) && uuid(s.ID) && uuid(s.AllocationID) && s.Scope.Valid() && s.RequestDigest != (Digest{}) && s.State.Valid() && !s.CreatedAt.IsZero() && s.Deadline.After(s.CreatedAt) && !s.Deadline.After(s.CreatedAt.Add(8*time.Hour)) && s.OutputLimit > 0 && s.OutputLimit <= MaxDownloadOutput && s.ReadLimit > 0 && s.ReadLimit <= MaxDownloadReadWork && s.RequestLimit > 0 && s.RequestLimit <= MaxDownloadRequests && s.ChargedOutput >= 0 && s.ChargedOutput <= s.OutputLimit && s.ChargedRead >= 0 && s.ChargedRead <= s.ReadLimit && s.Requests >= 0 && s.Requests <= s.RequestLimit && s.EmittedBytes >= 0 && s.EmittedBytes <= s.ChargedOutput && s.Generation >= 0
}

func (s DownloadSession) current(a DownloadAuthority, now time.Time) error {
	if !s.Valid() || !a.Valid(now) || s.Scope != a.Scope || !now.Before(s.Deadline) || !now.Before(a.AccessUntil) {
		return ErrDownloadExpired
	}
	if s.State.Terminal() {
		return ErrDownloadConflict
	}
	return nil
}

// Start is a pure transition. The ledger must serialize it with allocation,
// principal and installation concurrency and current permission/restore fences.
func (s DownloadSession) Start(a DownloadAuthority, b DownloadBatch, now time.Time) (DownloadSession, error) {
	if err := s.current(a, now); err != nil {
		return s, err
	}
	if !uuid(b.ID) || b.Generation != 0 || b.AuditAcknowledged || b.Offset < 0 || b.Offset > MaxNativeBytes || b.OutputBytes < 0 || b.OutputBytes > DeliveryBytes || b.OutputBytes > MaxNativeBytes-b.Offset || b.ReadBytes < 1 || b.ReadBytes > MaxDownloadReadWork {
		return s, ErrInvalid
	}
	if b.Purpose != DownloadMetadata && b.Purpose != DownloadContent {
		return s, ErrInvalid
	}
	if b.Purpose == DownloadMetadata && (b.Offset != 0 || b.OutputBytes != 0) || b.Purpose == DownloadContent && s.State == DownloadPreparing {
		return s, ErrDownloadConflict
	}
	if s.Active != nil && now.Before(s.Active.LeaseUntil) {
		return s, ErrDownloadConflict
	}
	if s.Requests == s.RequestLimit || b.OutputBytes > s.OutputLimit-s.ChargedOutput || b.ReadBytes > s.ReadLimit-s.ChargedRead {
		return s, ErrDownloadCapacity
	}
	s.Generation++
	s.Requests++
	s.ChargedOutput += b.OutputBytes
	s.ChargedRead += b.ReadBytes
	b.Generation = s.Generation
	b.Authority = a
	b.StartedAt = now
	b.LeaseUntil = identity.Earlier(a.ValidUntil, s.Deadline)
	s.Active = &b
	if b.Purpose == DownloadContent {
		s.State = DownloadStreaming
	}
	return s, nil
}

// Permit runs after audit and blocking native reads, immediately before output.
// It cannot extend the batch's original deadline or borrow a newer generation.
func (s DownloadSession) Permit(a DownloadAuthority, batchID string, generation int64, now time.Time) error {
	if err := s.current(a, now); err != nil {
		return err
	}
	if s.Active == nil || s.Active.ID != batchID || s.Active.Generation != generation || !s.Active.AuditAcknowledged || !now.Before(s.Active.LeaseUntil) {
		return ErrDownloadExpired
	}
	return nil
}

// Finish is an accounting fact, not renewed authority. It can record historical
// bytes after cancellation/expiry. Only the exact active generation can move a
// nonterminal session; no timeout or failed response refunds charged bytes.
func (s DownloadSession) Finish(batchID string, generation, emitted int64, success, fullFile bool, now time.Time) (DownloadSession, error) {
	b := s.Active
	if !s.Valid() || b == nil || b.ID != batchID || b.Generation != generation || emitted < 0 || emitted > b.OutputBytes || !b.AuditAcknowledged && (emitted != 0 || success) || fullFile && (b.Purpose == DownloadMetadata || b.Offset != 0 || !success) {
		return s, ErrDownloadConflict
	}
	if success && b.Purpose == DownloadContent && emitted != b.OutputBytes {
		return s, ErrInvalid
	}
	s.EmittedBytes += emitted
	s.Active = nil
	if s.State.Terminal() {
		return s, nil
	}
	if !now.Before(s.Deadline) {
		s.State = DownloadExpired
		return s, nil
	}
	if b.Purpose == DownloadMetadata {
		if success {
			s.State = DownloadReady
		} else if s.State != DownloadPreparing {
			s.State = DownloadInterrupted
		}
	} else if success && fullFile {
		s.State = DownloadCompleted
	} else {
		s.State = DownloadInterrupted
	}
	return s, nil
}

func (s DownloadSession) Cancel() (DownloadSession, error) {
	if !s.Valid() {
		return s, ErrInvalid
	}
	if !s.State.Terminal() {
		s.State = DownloadCancelled
	}
	return s, nil
}

// NativeDownloadMetadata is transient authorized output. Full native checksums,
// filenames and coverage stay in protected manifests, never session SQL/logs.
type NativeDownloadMetadata struct {
	Filename, Format, ETag, Coverage string
	Size                             int64
	SHA256                           Digest
	ReadUntil, DeleteBy              time.Time
}
type DownloadSelection struct {
	Offset, Length int64
	Partial        bool
}
