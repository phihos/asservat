package capture

import (
	"errors"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
)

// HistoryLifetime bounds how long an accepted capture appears in history and
// can be repeated (ADR-236): the specification's initial seven-day
// case-metadata default, a constant. It never extends evidence retention.
const HistoryLifetime = 7 * 24 * time.Hour

// MaxHistoryPage is the largest history page; DefaultHistoryPage is used when
// the caller names no limit. HistoryScan bounds the rows one page examines.
const (
	MaxHistoryPage     = 100
	DefaultHistoryPage = 20
	HistoryScan        = 200
)

// ErrTargetReplaced reports that a repeat resolved the original workload name
// to another namespace or workload UID. It is reported only after the caller
// is eligible to collect from the current workload.
var ErrTargetReplaced = errors.New("the repeated workload was recreated")

// HistoryOrigin is manual (a human request) or policy (a policy occurrence).
type HistoryOrigin string

const (
	HistoryManual HistoryOrigin = "manual"
	HistoryPolicy HistoryOrigin = "policy"
)

// HistoryCursor is the keyset position after the last examined row. It only
// positions a page: every page authorizes every row again.
type HistoryCursor struct {
	Target                    authorization.Target
	SnapshotBefore, ExpiresAt time.Time
	AuthorizationRevision     identity.Revision
	AcceptedAt                time.Time
	CaptureID                 string
}

// HistoryQuery names one current workload identity, resolved under current
// authority by the caller, and the origins to list.
type HistoryQuery struct {
	SelectorKey    artifact.Digest
	SnapshotBefore time.Time
	RootID         string
	Target         authorization.Target // workload scope (authorization.WorkloadScope) or an explicit Pod; rows keep their own Pod
	Origins        []HistoryOrigin
	After          *HistoryCursor
	Limit          int
	Identity       identity.Identity
	Recovery       artifact.RecoveryProof
}

func (q HistoryQuery) Valid(now time.Time) bool {
	if !authorization.UUID(q.RootID) || !q.Target.Valid() || len(q.Origins) < 1 || len(q.Origins) > 2 || q.Limit < 1 || q.Limit > MaxHistoryPage || !q.Identity.Valid(now) || !q.Recovery.Valid(now) {
		return false
	}
	for _, o := range q.Origins {
		if o != HistoryManual && o != HistoryPolicy {
			return false
		}
	}
	return q.After == nil || authorization.UUID(q.After.CaptureID) && !q.After.AcceptedAt.IsZero()
}

// HistoryEntry is a content-minimized summary of one accepted capture.
type HistoryEntry struct {
	Requester         identity.Principal
	ActionKinds       []string
	RepeatState       string
	SettingsExpiresAt time.Time
	RepeatedFrom      string
	CaptureID         string
	Origin            HistoryOrigin
	AcceptedAt        time.Time
	ExpiresAt         time.Time // AcceptedAt + HistoryLifetime: summary and settings
	Phase             string    // the get_capture phase
	EvidenceState     string    // pending, available, expired or unavailable
}

type HistoryPage struct {
	Target                 authorization.Target
	SnapshotBefore         time.Time
	AuthorizationRevision  identity.Revision
	Entries                []HistoryEntry
	Next                   *HistoryCursor
	ObservedAt, ValidUntil time.Time
}

// SettingsQuery reads the repeatable settings of one history entry.
type SettingsQuery struct {
	RootID, CaptureID string
	Identity          identity.Identity
	Recovery          artifact.RecoveryProof
}

func (q SettingsQuery) Valid(now time.Time) bool {
	return authorization.UUID(q.RootID) && authorization.UUID(q.CaptureID) && q.Identity.Valid(now) && q.Recovery.Valid(now)
}

// CaptureSettings is the immutable repeatable projection of an accepted
// capture: its authored target, recipe and dependency pins and requested
// retention. It carries no reason, sharing, grant, credential or old pod.
type CaptureSettings struct {
	FrozenFilters            []byte
	ExplicitPodUID           string
	Selection                string
	PolicyOrigins            []HistoryPolicyOrigin
	Composition              *planning.ProfileComposition
	CompositionJSON          []byte
	RecipeJSON               []byte
	SettingsKey              artifact.Digest
	OriginalEffectiveSeconds int64
	CaptureID                string
	Origin                   HistoryOrigin
	ClusterID                string
	NamespaceUID             string
	WorkloadUID              string
	AcceptedAt, ExpiresAt    time.Time
	TargetJSON               []byte // the accepted collection target (target.schema.json)
	DependencyJSON           []byte // the accepted dependency pins
	Namespace                string
	WorkloadKind             string
	WorkloadName             string
	RequestedSeconds         int64
	ExecutionDigest          artifact.Digest
	ObservedAt, ValidUntil   time.Time
}

// HistoryEvidenceState derives the evidence state of a summary from its
// progress phase and the attempt's effective access deadline.
func HistoryEvidenceState(phase string, effectiveExpiresAt, now time.Time) string {
	switch phase {
	case "Succeeded":
		if !effectiveExpiresAt.IsZero() && now.Before(effectiveExpiresAt) {
			return "available"
		}
		return "expired"
	case "Failed", "Indeterminate":
		return "unavailable"
	}
	return "pending"
}
