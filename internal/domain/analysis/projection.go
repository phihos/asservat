// Package analysis contains pure bounded-query values. Structural validation is
// not authentication, publication verification, admission or disclosure authority.
package analysis

import (
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const (
	ContextProjectionPurpose = "context-projection/v1"
	ContextDisplayVersion    = "approved-pod-status-display/v1"
	ContextLogicalPath       = "pod-status.txt"
	ContextDefaultQueryTime  = 10 * time.Second
	ContextMaxQueryTime      = 60 * time.Second
	ContextMaxReadBatches    = 2
	ContextBatchReadWork     = 4 << 20
	ContextResultBytes       = 24 << 10
	ContextWireBytes         = 64 << 10
)

var (
	ErrInvalid     = errors.New("invalid context projection")
	ErrUnavailable = errors.New("context projection unavailable")
	ErrExpired     = errors.New("context projection expired")
	// ErrBusy refuses a query whose worker would exceed the live acquisition
	// worker caps; the query stays charged and a later retry may succeed.
	ErrBusy = errors.New("context projection workers busy")
)

// HTTPHeadersDisplayVersion names the get_http_headers page rendering of an
// approved httpHeaders extract (ADR-282).
const HTTPHeadersDisplayVersion = "approved-http-headers-page/v1"

const ProfileSummaryDisplayVersion = "approved-pprof-summary/v1"

// ProjectionSource is one of the closed published sources: pod-status
// metadata, an httpHeaders extract, or raw pprof input for the distinct
// approved summary operation (ADR-291). Every field must match exactly; no other native type,
// class or size bound is a projection source. The HTTP projection is itself
// the native document, so it has no separate manifest projection digest.
type ProjectionSource struct {
	NativeType, Format, DataClass, EvidenceType, DisplayVersion string
	NativeLimit                                                 int64
	ProjectionDigest                                            artifact.Digest
}

// LookupProjectionSource returns the source for a published native type.
func LookupProjectionSource(nativeType string) (ProjectionSource, bool) {
	if nativeType == artifact.SyscallRecordsArtifact || nativeType == artifact.SyscallArgumentsArtifact {
		return LookupProjectionSourceFor(nativeType, SyscallSummaryDisplayVersion)
	}
	switch nativeType {
	case artifact.PodStatusArtifact:
		return ProjectionSource{NativeType: artifact.PodStatusArtifact, Format: artifact.ContextFormat, DataClass: "metadata", EvidenceType: "context",
			DisplayVersion: ContextDisplayVersion, NativeLimit: artifact.MaxContextBytes, ProjectionDigest: ContextSourceProjectionDigest()}, true
	case artifact.PprofArtifact:
		return ProjectionSource{NativeType: artifact.PprofArtifact, Format: artifact.PprofFormat, DataClass: "raw", EvidenceType: "profile", DisplayVersion: ProfileSummaryDisplayVersion, NativeLimit: artifact.MaxPprofBytes}, true
	case artifact.HTTPHeadersArtifact:
		return ProjectionSource{NativeType: artifact.HTTPHeadersArtifact, Format: artifact.HTTPHeadersFormat, DataClass: "extract", EvidenceType: "packetCapture",
			DisplayVersion: HTTPHeadersDisplayVersion, NativeLimit: artifact.RecordingNativeLimit}, true
	}
	return ProjectionSource{}, false
}

// LookupProjectionSourceFor binds a closed display purpose as well as its
// native input. A syscall source supports two distinct approved views.
func LookupProjectionSourceFor(nativeType, displayVersion string) (ProjectionSource, bool) {
	if nativeType == artifact.SyscallRecordsArtifact || nativeType == artifact.SyscallArgumentsArtifact {
		if displayVersion != SyscallSummaryDisplayVersion && displayVersion != SyscallEventsDisplayVersion {
			return ProjectionSource{}, false
		}
		class, format := "metadata", artifact.SyscallRecordsFormat
		if nativeType == artifact.SyscallArgumentsArtifact {
			class, format = "raw", artifact.SyscallArgumentsFormat
		}
		return ProjectionSource{NativeType: nativeType, Format: format, DataClass: class, EvidenceType: "syscallTrace", DisplayVersion: displayVersion, NativeLimit: artifact.RecordingNativeLimit}, true
	}
	known, ok := LookupProjectionSource(nativeType)
	return known, ok && known.DisplayVersion == displayVersion
}

// Matches reports whether published facts are exactly this source.
func (p ProjectionSource) Matches(nativeType, format, dataClass, evidenceType string, nativeLimit int64, digest artifact.Digest) bool {
	return p.NativeType == nativeType && p.Format == format && p.DataClass == dataClass && p.EvidenceType == evidenceType &&
		(p.NativeLimit == nativeLimit || p.NativeType == artifact.PprofArtifact && nativeLimit > 0 && nativeLimit <= p.NativeLimit) && p.ProjectionDigest == digest
}

func ContextSourceProjectionDigest() artifact.Digest {
	// Pinned immutable native definition; the unit regression verifies its SHA256.
	return artifact.Digest{0xdd, 0xb9, 0x74, 0xba, 0xe2, 0x42, 0x8c, 0x14, 0x69, 0xa5, 0xca, 0xb5, 0x04, 0xcf, 0x41, 0x0a, 0x8b, 0x2d, 0x53, 0x31, 0xfd, 0x5b, 0xfe, 0x3b, 0xdf, 0x2b, 0x88, 0x56, 0x57, 0x9a, 0x41, 0x41}
}

type LineSelection struct {
	LineStart, MaxLines int
}

// ContextExcerptSelection is normalized public selection, never a source route.
type ContextExcerptSelection struct {
	CaseID, ArtifactID string
	Selection          LineSelection
}

func (s ContextExcerptSelection) Valid() bool {
	return authorization.UUID(s.CaseID) && authorization.UUID(s.ArtifactID) && s.Selection.Valid()
}

func (s LineSelection) Valid() bool {
	return s.LineStart >= 1 && s.LineStart <= 1_000_000_000 && s.MaxLines >= 1 && s.MaxLines <= 200
}

// NormalizeLineSelection applies the canonical optional-input defaults. Zero
// means omitted only at this boundary; stored scopes always require positive values.
func NormalizeLineSelection(start, maximum int) (LineSelection, error) {
	if start == 0 {
		start = 1
	}
	if maximum == 0 {
		maximum = 200
	}
	s := LineSelection{LineStart: start, MaxLines: maximum}
	if !s.Valid() {
		return LineSelection{}, ErrInvalid
	}
	return s, nil
}

// HTTPHeaderWindow is the record window of an httpHeaders projection read:
// the first record index, the page size and, after the first page, the
// projection-digest binding its cursor carries.
type HTTPHeaderWindow struct {
	Start, Limit int
	Binding      string `json:",omitempty"`
}

func (w HTTPHeaderWindow) Valid() bool {
	if w.Limit < 1 || w.Limit > HTTPHeaderPageRecords || w.Start < 0 || w.Start >= HTTPHeaderMaxRecords {
		return false
	}
	if w.Start == 0 {
		return w.Binding == ""
	}
	return lowerHex(w.Binding, httpHeaderBindingDigits)
}

// Selection is the public selection this window reads for one artifact.
func (w HTTPHeaderWindow) Selection(caseID, artifactID string) HTTPHeaderSelection {
	return HTTPHeaderSelection{CaseID: caseID, ArtifactID: artifactID, Start: w.Start, Limit: w.Limit, Binding: w.Binding}
}

// ContextProjectionCandidate is a content-minimized route, not a protected
// evidence lookup. C-03 checks target rights before reading the published source
// and resolving the exact version-bound scope. No caller may supply that route.
// NativeType selects the source (empty is pod status) and with it the
// selection branch: lines for pod status, a record window for httpHeaders,
// or a sample type/top-N for pprof. All other branches are zero. Added fields
// are omitted when zero, preserving existing candidate/scope serialization.
type ContextProjectionCandidate struct {
	RootID, CaseID, ArtifactID, CaptureID, ClusterID, NamespaceUID, WorkloadUID, PodUID string
	Selection                                                                           LineSelection
	Principal                                                                           identity.Principal
	NativeType                                                                          string                  `json:",omitempty"`
	Headers                                                                             HTTPHeaderWindow        `json:",omitzero"`
	Profile                                                                             ProfileSummarySelection `json:",omitzero"`
	Syscalls                                                                            SyscallWindow           `json:",omitzero"`
}

func (c ContextProjectionCandidate) Valid() bool {
	return c.RouteValid() && c.selectionValid()
}

// RouteValid checks only the routing facts a case locator supplies, without
// any source or selection.
func (c ContextProjectionCandidate) RouteValid() bool {
	return authorization.UUID(c.RootID) && authorization.UUID(c.CaseID) && authorization.UUID(c.ArtifactID) &&
		authorization.UUID(c.CaptureID) && authorization.UUID(c.ClusterID) && identity.Text(c.NamespaceUID, 64) &&
		identity.Text(c.WorkloadUID, 64) && identity.Text(c.PodUID, 64) && c.Principal.Valid()
}

// Source derives the view identity from the closed typed selection.
func (c ContextProjectionCandidate) Source() (ProjectionSource, bool) {
	if c.NativeType == artifact.SyscallRecordsArtifact || c.NativeType == artifact.SyscallArgumentsArtifact {
		return LookupProjectionSourceFor(c.NativeType, c.Syscalls.View.DisplayVersion())
	}
	return LookupProjectionSource(c.NativeType)
}

func (c ContextProjectionCandidate) selectionValid() bool {
	if c.NativeType != artifact.SyscallRecordsArtifact && c.NativeType != artifact.SyscallArgumentsArtifact && c.Syscalls != (SyscallWindow{}) {
		return false
	}
	switch c.NativeType {
	case artifact.PodStatusArtifact:
		return c.Selection.Valid() && c.Headers == HTTPHeaderWindow{} && c.Profile == (ProfileSummarySelection{})
	case artifact.HTTPHeadersArtifact:
		return c.Selection == LineSelection{} && c.Headers.Valid() && c.Profile == (ProfileSummarySelection{})
	case artifact.SyscallRecordsArtifact, artifact.SyscallArgumentsArtifact:
		return c.Selection == (LineSelection{}) && c.Headers == (HTTPHeaderWindow{}) && c.Profile == (ProfileSummarySelection{}) && c.Syscalls.Valid()
	case artifact.PprofArtifact:
		return c.Selection == LineSelection{} && c.Headers == (HTTPHeaderWindow{}) && c.Profile.Valid()
	}
	return false
}

// ContextProjectionScope is built from protected routing/publication facts,
// never decoded from a public request or treated as a permit by itself.
type ContextProjectionScope struct {
	RootID, CaseID, ArtifactID, CaptureID, ClusterID, NamespaceUID, WorkloadUID, PodUID string
	Version, SourceProjectionDigest                                                     artifact.Digest
	SourceFormat, DisplayVersion                                                        string
	Selection                                                                           LineSelection
	Principal                                                                           identity.Principal
	NativeType                                                                          string                  `json:",omitempty"`
	Headers                                                                             HTTPHeaderWindow        `json:",omitzero"`
	Profile                                                                             ProfileSummarySelection `json:",omitzero"`
	Syscalls                                                                            SyscallWindow           `json:",omitzero"`
}

func (s ContextProjectionScope) Valid() bool {
	src, ok := s.Source()
	return ok && s.Candidate().Valid() && s.Version != (artifact.Digest{}) &&
		s.SourceProjectionDigest == src.ProjectionDigest && s.SourceFormat == src.Format && s.DisplayVersion == src.DisplayVersion
}

// Source is the closed projection source this scope reads.
func (s ContextProjectionScope) Source() (ProjectionSource, bool) {
	if (s.NativeType == artifact.SyscallRecordsArtifact || s.NativeType == artifact.SyscallArgumentsArtifact) && s.Syscalls.View.DisplayVersion() != s.DisplayVersion {
		return ProjectionSource{}, false
	}
	return LookupProjectionSourceFor(s.NativeType, s.DisplayVersion)
}

func (s ContextProjectionScope) Candidate() ContextProjectionCandidate {
	return ContextProjectionCandidate{RootID: s.RootID, CaseID: s.CaseID, ArtifactID: s.ArtifactID, CaptureID: s.CaptureID,
		ClusterID: s.ClusterID, NamespaceUID: s.NamespaceUID, WorkloadUID: s.WorkloadUID, PodUID: s.PodUID,
		Selection: s.Selection, Principal: s.Principal, NativeType: s.NativeType, Headers: s.Headers, Profile: s.Profile, Syscalls: s.Syscalls}
}

// ContextProjectionPath is accepted placement for this query purpose. It is not
// a DownloadPath alias. ADR-219 shares the protected processing placement,
// while ReadApproved remains an independently evaluated disclosure authority.
type ContextProjectionPath struct {
	Purpose, ID, TargetClusterID, StoreID   string
	StorageRegion                           string
	AcquisitionClusterID, AcquisitionRegion string
	ConnectorClusterID, ConnectorRegion     string
	HubClusterID, HubRegion                 string
	WorkerConfiguration, HubConfiguration   identity.Revision
}

func (p ContextProjectionPath) Valid() bool {
	return p.Purpose == ContextProjectionPurpose && authorization.UUID(p.ID) && authorization.UUID(p.TargetClusterID) &&
		authorization.UUID(p.StoreID) && authorization.UUID(p.AcquisitionClusterID) && p.ConnectorClusterID == p.AcquisitionClusterID &&
		authorization.UUID(p.HubClusterID) && identity.Text(p.StorageRegion, 63) && identity.Text(p.AcquisitionRegion, 63) &&
		identity.Text(p.ConnectorRegion, 63) && identity.Text(p.HubRegion, 63) && p.WorkerConfiguration.Valid() &&
		p.HubConfiguration.Valid() && authorization.UUID(p.WorkerConfiguration.UID) && authorization.UUID(p.HubConfiguration.UID)
}

// The existing processing proof is neutral complete root/capture/location state
// despite its historical name. No download authority or policy is accepted here.
type ContextProjectionEnvironment struct {
	RootID, InstallationID, Region, StoreID string
	Location                                artifact.Location
	Principal                               identity.Principal
	PolicyRevision                          identity.Revision
	Recovery                                artifact.RecoveryProof
	Processing                              artifact.DownloadProcessingProof
	Path                                    ContextProjectionPath
	ObservedAt, ValidUntil                  time.Time
}

func (e ContextProjectionEnvironment) Valid(now time.Time) bool {
	return authorization.UUID(e.RootID) && authorization.UUID(e.InstallationID) && authorization.UUID(e.StoreID) &&
		e.Location.Validate() == nil && e.Principal.Valid() && e.PolicyRevision.Valid() &&
		identity.Fresh(e.ObservedAt, e.ValidUntil, now, identity.EvidenceReadRequestWindow) &&
		e.Recovery.Valid(now) && e.Recovery.InstallationID == e.InstallationID && !e.ValidUntil.After(e.Recovery.FreshUntil) &&
		e.Processing.Valid(now) && e.Processing.RootID == e.RootID && e.Processing.Location == e.Location &&
		!e.ValidUntil.After(e.Processing.ValidUntil) && e.Path.Valid() && e.Region == e.Path.AcquisitionRegion &&
		e.Path.TargetClusterID == e.Location.ClusterID && e.Path.StoreID == e.StoreID
}

// ContextProjectionAuthority is a current internal read decision. All proofs
// are mandatory; historical zero-value compatibility never permits effects.
type ContextProjectionAuthority struct {
	Scope                                        ContextProjectionScope
	Environment                                  ContextProjectionEnvironment
	Retention                                    artifact.RetentionProof
	PermissionRevision, IdentityRevision         identity.Revision
	DecisionDigest                               artifact.Digest
	CheckedAt, ValidUntil, AccessUntil, DeleteBy time.Time
	// Bound names the component whose interval set ValidUntil, for the
	// operator report only. It is never persisted, digested or authority.
	Bound string `json:"-"`
}

func (a ContextProjectionAuthority) Valid(now time.Time) bool {
	return a.Scope.Valid() && a.Environment.Valid(now) && a.Environment.RootID == a.Scope.RootID &&
		a.Environment.Principal == a.Scope.Principal && a.Environment.Location.ClusterID == a.Scope.ClusterID &&
		a.Environment.Location.ArtifactID == a.Scope.ArtifactID && a.Environment.Processing.CaptureID == a.Scope.CaptureID &&
		a.Retention.Valid(now) && a.Retention.Matches(a.Scope.RootID, a.Scope.ClusterID, a.Scope.NamespaceUID, a.Scope.WorkloadUID, a.Scope.PodUID) &&
		a.PermissionRevision.Valid() && authorization.UUID(a.PermissionRevision.UID) && a.IdentityRevision.Valid() &&
		a.DecisionDigest != (artifact.Digest{}) && identity.Fresh(a.CheckedAt, a.ValidUntil, now, identity.EvidenceReadRequestWindow) &&
		!a.ValidUntil.After(a.Environment.ValidUntil) && !a.ValidUntil.After(a.Retention.ValidUntil) &&
		!a.ValidUntil.After(a.AccessUntil) && a.AccessUntil.Before(a.DeleteBy)
}

// ContextQueryDeadline fixes the total query bound, distinct from a request's
// five-second authority. The application must persist this once; replay cannot
// call it with a new start to renew an admitted query. Current identity/session
// bounds apply independently to each result-read request, not the stored query.
func ContextQueryDeadline(start time.Time, lifetime time.Duration, accessUntil time.Time) (time.Time, error) {
	if start.IsZero() || accessUntil.IsZero() {
		return time.Time{}, ErrInvalid
	}
	if lifetime == 0 {
		lifetime = ContextDefaultQueryTime
	}
	if lifetime < 0 || lifetime > ContextMaxQueryTime {
		return time.Time{}, ErrInvalid
	}
	until := identity.Earlier(start.Add(lifetime), accessUntil)
	if !until.After(start) {
		return time.Time{}, ErrExpired
	}
	return until, nil
}

// AcquisitionPath extracts placement only. The caller retains the closed query
// purpose and independent ReadApproved authority; this is never DownloadAuthority.
func (p ContextProjectionPath) AcquisitionPath() artifact.DownloadPath {
	if !p.Valid() {
		return artifact.DownloadPath{}
	}
	return artifact.DownloadPath{ID: p.ID, TargetClusterID: p.TargetClusterID, StoreID: p.StoreID, StorageRegion: p.StorageRegion, AcquisitionClusterID: p.AcquisitionClusterID, AcquisitionRegion: p.AcquisitionRegion, ConnectorClusterID: p.ConnectorClusterID, ConnectorRegion: p.ConnectorRegion, HubClusterID: p.HubClusterID, HubRegion: p.HubRegion, WorkerConfiguration: p.WorkerConfiguration, HubConfiguration: p.HubConfiguration}
}
