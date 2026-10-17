package configuration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

type RetentionFence struct {
	RootID, Epoch string
	Source        privacy.PolicySourceRef
	Sequence      int64
	LeaseUntil    time.Time
}

func (f RetentionFence) Valid() bool {
	return authorization.UUID(f.RootID) && authorization.UUID(f.Epoch) && ValidRetentionSource(f.Source) && f.Sequence >= 0 && !f.LeaseUntil.IsZero()
}
func ValidRetentionSource(s privacy.PolicySourceRef) bool {
	return authorization.UUID(s.ClusterID) && identity.Text(s.ControlNamespaceUID, 64) && s.ProtectionDigest != (artifact.Digest{})
}

// Exactly one transition is persisted before its successor. An expired
// checkpoint can be replayed as an obligation; it cannot authorize access.
type RetentionTransition struct {
	ID     string
	Fence  RetentionFence
	List   PolicyList
	Event  *PolicyEvent
	Review *value.RetentionBootstrapReview
}
type RetentionCheckpoint struct {
	Transition RetentionTransition
	Record     audit.RetentionAcceptance
	Audited    bool
}
type RetentionStart struct {
	Fence        RetentionFence
	Checkpoint   *RetentionCheckpoint
	ResumeCursor string
}

type RetentionObservation struct {
	Fence      RetentionFence
	List       PolicyList
	Protection privacy.SourceProtection
}

func RetentionTransitionDigest(t RetentionTransition) artifact.Digest {
	b, err := json.Marshal(t)
	if err != nil || len(b) > 8<<20 {
		return artifact.Digest{}
	}
	return sha256.Sum256(b)
}

// ValidateRetentionTransition replays the single exact event against the last
// durable checkpoint. A newly fetched LIST cannot substitute for that history.
func ValidateRetentionTransition(t RetentionTransition, previous *RetentionCheckpoint, now time.Time) (audit.RetentionAcceptance, error) {
	var out audit.RetentionAcceptance
	f, s := t.Fence, t.List.Snapshot
	if !authorization.UUID(t.ID) || !f.Valid() || f.Sequence >= 2147483647 || !now.Before(f.LeaseUntil) || !validPolicyList(t.List, s.ObservedAt) || s.ObservedAt.After(now) || s.SourceClusterID != f.Source.ClusterID || s.ControlNamespaceUID != f.Source.ControlNamespaceUID || s.Hub != f.Source.Hub || RetentionTransitionDigest(t) == (artifact.Digest{}) {
		return out, value.ErrInvalid
	}
	out = audit.RetentionAcceptance{ID: t.ID, RootID: f.RootID, Epoch: f.Epoch, SourceClusterID: f.Source.ClusterID, ControlNamespaceUID: f.Source.ControlNamespaceUID, Hub: f.Source.Hub, Sequence: f.Sequence + 1, ProtectionDigest: f.Source.ProtectionDigest, CheckpointDigest: RetentionTransitionDigest(t), CreatedAt: now, Policies: make([]artifact.RetentionRule, 0, len(s.Policies))}
	if f.Sequence == 0 {
		if previous != nil || t.Event != nil || len(t.List.Deleting) != 0 {
			return audit.RetentionAcceptance{}, value.ErrInvalid
		}
		if err := CheckInitialRetention(s, f.Source.ProtectionDigest, t.Review, now); err != nil {
			return audit.RetentionAcceptance{}, err
		}
		out.Bootstrap = &audit.RetentionBootstrap{PoliciesDigest: RetentionSnapshotDigest(s), PolicyCount: len(s.Policies)}
		if len(s.Policies) > 0 {
			r := t.Review
			out.Bootstrap.ReviewUID = r.Resource.UID
			out.Bootstrap.ReviewVersion = r.Resource.ResourceVersion
			out.Bootstrap.Reviewer = r.Reviewer
			out.Bootstrap.ReviewDigest = r.Resource.SpecDigest
			out.Bootstrap.ReviewedAt = r.ReviewedAt
			out.Bootstrap.ExpiresAt = r.ExpiresAt
		} else if t.Review != nil {
			return audit.RetentionAcceptance{}, value.ErrInvalid
		}
	} else {
		if previous == nil || !previous.Record.Valid() || previous.Record.Sequence != f.Sequence || previous.Transition.Fence.RootID != f.RootID || previous.Transition.Fence.Source != f.Source || t.Event == nil || t.Event.Type == "BOOKMARK" || t.Review != nil {
			return audit.RetentionAcceptance{}, value.ErrChanged
		}
		out.PreviousDigest = RetentionTransitionDigest(previous.Transition)
		if out.PreviousDigest != previous.Record.CheckpointDigest {
			return audit.RetentionAcceptance{}, value.ErrInvalid
		}
		journal, err := ResumeRetentionJournal(previous.Transition.List)
		if err != nil {
			return audit.RetentionAcceptance{}, err
		}
		if err = journal.Apply(*t.Event); err != nil {
			return audit.RetentionAcceptance{}, err
		}
		expected, err := journal.HistoricalCheckpoint()
		if err != nil || !samePolicyList(t.List, expected) {
			return audit.RetentionAcceptance{}, value.ErrChanged
		}
	}
	for _, p := range s.Policies {
		out.Policies = append(out.Policies, artifact.RetentionRule{UID: p.Policy.Revision.UID, Generation: p.Policy.Revision.Generation, Digest: p.Policy.Revision.Digest})
	}
	slices.SortFunc(out.Policies, func(a, b artifact.RetentionRule) int { return comparePolicyUID(a.UID, b.UID) })
	if !out.Valid() {
		return audit.RetentionAcceptance{}, value.ErrInvalid
	}
	return out, nil
}

// No Ready setter is exposed. The separate reader must prove the entire
// retained-evidence catch-up barrier, current protection and complete LIST.
type RetentionCheckpointStore interface {
	BeginRetention(context.Context, string, privacy.PolicySourceRef, string) (RetentionStart, error)
	AcceptRetention(context.Context, RetentionTransition) (RetentionCheckpoint, error)
	RenewRetention(context.Context, RetentionFence) (RetentionFence, error)
	SuspendRetention(context.Context, RetentionFence) error
	AdvanceRetentionCursor(context.Context, RetentionFence, string) error
	ObserveRetention(context.Context, RetentionObservation) error
}
type RetentionAcceptanceJournal interface {
	PendingRetentionAcceptances(context.Context, int) ([]audit.RetentionAcceptance, error)
	AcknowledgeRetentionAcceptance(context.Context, string, audit.Receipt) error
}
type RetentionAcceptanceWriter interface {
	WriteRetentionAcceptance(context.Context, audit.RetentionAcceptance) (audit.Receipt, error)
}
type RetentionAcceptancePublisher struct {
	Journal RetentionAcceptanceJournal
	Writer  RetentionAcceptanceWriter
}

func (p RetentionAcceptancePublisher) Publish(ctx context.Context, limit int) error {
	if p.Journal == nil || p.Writer == nil || limit < 1 || limit > 64 {
		return value.ErrInvalid
	}
	rows, err := p.Journal.PendingRetentionAcceptances(ctx, limit)
	if err != nil {
		return err
	}
	if len(rows) > limit {
		return value.ErrLimit
	}
	for _, r := range rows {
		if !r.Valid() {
			return value.ErrInvalid
		}
		receipt, err := p.Writer.WriteRetentionAcceptance(ctx, r)
		if err != nil {
			return err
		}
		if !receipt.ValidRetentionAcceptance(r.RootID, r.ID) {
			return value.ErrInvalid
		}
		if err = p.Journal.AcknowledgeRetentionAcceptance(ctx, r.ID, receipt); err != nil {
			return err
		}
	}
	return nil
}
