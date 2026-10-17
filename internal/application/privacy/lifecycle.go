package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"
)

type RetentionLedger interface {
	RetainedArtifact(context.Context, artifact.Location) (value.RetainedArtifact, error)
	TightenRetention(context.Context, value.LifecycleDecision) error
}
type LifecycleJournal interface {
	PendingLifecycleDecisions(context.Context) ([]value.LifecycleDecision, error)
	AcknowledgeLifecycleDecision(context.Context, value.LifecycleDecision, audit.Receipt) error
}
type LifecycleWriter interface {
	WriteLifecycleDecision(context.Context, value.LifecycleDecision) (audit.Receipt, error)
}

// Signing and historical verification use keys dedicated to lifecycle records,
// never acquisition tickets or TLS identity. Bootstrap owns protected key choice.
type LifecycleSigner interface {
	SignLifecycle(context.Context, value.LifecycleDecision) ([]byte, error)
}
type LifecycleVerifier interface {
	VerifyLifecycle(context.Context, value.LifecycleDecision, []byte) error
}

func RegistrationDigest(r artifact.Registration) artifact.Digest {
	r.AnchorAt = r.AnchorAt.UTC()
	r.WriteUntil = r.WriteUntil.UTC()
	r.ExpiresAt = r.ExpiresAt.UTC()
	r.DeleteBy = r.DeleteBy.UTC()
	b, _ := json.Marshal(r)
	return sha256.Sum256(b)
}

type RetentionShortener struct {
	Ledger   RetentionLedger
	Resolver RetentionResolver
	Now      func() time.Time
	NewID    func() string
}

func (s RetentionShortener) Reconcile(ctx context.Context, loc artifact.Location) error {
	if s.Ledger == nil || s.Now == nil || s.NewID == nil {
		return ErrUnavailable
	}
	r, err := s.Ledger.RetainedArtifact(ctx, loc)
	if err != nil {
		return err
	}
	if !r.Valid() || r.Registration.Location != loc {
		return value.ErrInvalid
	}
	resolved, err := s.Resolver.ResolveRetained(ctx, r.Input, r.Effective, r.OriginPolicies)
	if err != nil {
		return err
	}
	if resolved.ExpiresAt.Equal(r.Effective.ExpiresAt) && resolved.DeleteBy.Equal(r.Effective.DeleteBy) {
		return nil
	}
	origins, err := value.MergePolicyOrigins(r.OriginPolicies, resolved.Policies)
	if err != nil {
		return err
	}
	now := s.Now().UTC().Truncate(time.Microsecond)
	d := value.LifecycleDecision{ID: s.NewID(), RootID: r.RootID, Location: loc, Target: r.Input.Target, Sequence: r.Sequence + 1, RegistrationDigest: RegistrationDigest(r.Registration), PolicyRevision: resolved.PolicyRevision, Policies: slices.Clone(resolved.Policies), Origins: origins, Previous: r.Effective, Effective: resolved.Deadlines, ObservedAt: now, ValidUntil: resolved.ValidUntil.UTC().Truncate(time.Microsecond)}
	if !d.Valid() || !now.Before(d.ValidUntil) {
		return value.ErrUnavailable
	}
	// Apply the restrictive fence before remote journal work. An unavailable
	// signature/KMS/object store must never preserve access past a known cutoff.
	return s.Ledger.TightenRetention(ctx, d)
}

type LifecyclePublisher struct {
	Ledger  LifecycleJournal
	Objects LifecycleWriter
}

func (p LifecyclePublisher) Publish(ctx context.Context) error {
	if p.Ledger == nil || p.Objects == nil {
		return ErrUnavailable
	}
	rows, err := p.Ledger.PendingLifecycleDecisions(ctx)
	if err != nil {
		return err
	}
	if len(rows) > 64 {
		return ErrUnavailable
	}
	for _, r := range rows {
		if !r.Valid() || ctx.Err() != nil {
			return ErrUnavailable
		}
		receipt, err := p.Objects.WriteLifecycleDecision(ctx, r)
		if err != nil {
			return err
		}
		if err = p.Ledger.AcknowledgeLifecycleDecision(ctx, r, receipt); err != nil {
			return err
		}
	}
	return nil
}
