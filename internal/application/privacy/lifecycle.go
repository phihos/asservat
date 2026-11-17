package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/privacy"
	"context"
	"crypto/sha256"
	"encoding/json"
)

type LifecycleJournal interface {
	PendingLifecycleDecisions(context.Context) ([]value.LifecycleDecision, error)
	AcknowledgeLifecycleDecision(context.Context, value.LifecycleDecision, audit.Receipt) error
}

type singleLifecycleJournal interface {
	PendingLifecycleDecision(context.Context) (value.LifecycleDecision, bool, error)
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

type LifecyclePublisher struct {
	Ledger  LifecycleJournal
	Objects LifecycleWriter
}

func (p LifecyclePublisher) Publish(ctx context.Context) error {
	if ctx == nil || p.Ledger == nil || p.Objects == nil {
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
		if err := p.publishDecision(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// PublishOne selects and publishes at most one retained decision. attempted
// is true once a row was selected, including when publication cannot finish.
func (p LifecyclePublisher) PublishOne(ctx context.Context) (attempted bool, err error) {
	journal, ok := p.Ledger.(singleLifecycleJournal)
	if ctx == nil || ctx.Err() != nil || !ok || p.Objects == nil {
		return false, ErrUnavailable
	}
	r, found, err := journal.PendingLifecycleDecision(ctx)
	if err != nil || !found {
		return found, err
	}
	return true, p.publishDecision(ctx, r)
}

func (p LifecyclePublisher) publishDecision(ctx context.Context, r value.LifecycleDecision) error {
	if !r.Valid() || ctx.Err() != nil {
		return ErrUnavailable
	}
	receipt, err := p.Objects.WriteLifecycleDecision(ctx, r)
	if err != nil {
		return err
	}
	return p.Ledger.AcknowledgeLifecycleDecision(ctx, r, receipt)
}
