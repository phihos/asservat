package integration

import (
	"context"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// Synthetic protected-root port: this fixture qualifies the actual Goose/SQL
// boundary, not Kubernetes guard authority or the deployed initial-schema CLI.
type syntheticSchemaRoot struct {
	mu                                   sync.Mutex
	record                               *contracts.InitialPreparationSchema
	reads, failRead, claims, completions int
	shortRead                            int
	shortLease                           time.Duration
	loseCompletion                       bool
	expired                              bool
}

func (r *syntheticSchemaRoot) ReadInitialSchema(ctx context.Context) (contracts.InitialPreparationRoot, time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reads++
	if r.reads == r.failRead || ctx.Err() != nil {
		return contracts.InitialPreparationRoot{}, time.Time{}, cfg.ErrUnavailable
	}
	until := time.Now().Add(5 * time.Second)
	if r.reads == r.shortRead {
		// Shortens one bracket's lease below or just above the step reserve.
		until = time.Now().Add(r.shortLease)
	}
	if r.expired {
		until = time.Now().Add(-time.Second)
	}
	w := contracts.InitialPreparationRoot{}
	if r.record != nil {
		v := *r.record
		w.Schema = &v
	}
	return w, until, nil
}
func (r *syntheticSchemaRoot) ClaimInitialSchema(ctx context.Context, v contracts.InitialPreparationSchema) (contracts.InitialPreparationRoot, time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil || r.record != nil {
		return contracts.InitialPreparationRoot{}, time.Time{}, cfg.ErrUnavailable
	}
	v.AttemptID = custodyID()
	v.ClaimedAt = time.Now().UTC().Truncate(time.Microsecond)
	r.record = &v
	r.claims++
	return contracts.InitialPreparationRoot{Schema: &v}, time.Now().Add(5 * time.Second), nil
}
func (r *syntheticSchemaRoot) CompleteInitialSchema(ctx context.Context, v contracts.InitialPreparationSchema) (contracts.InitialPreparationRoot, time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx.Err() != nil || r.record == nil || r.record.AttemptID != v.AttemptID {
		return contracts.InitialPreparationRoot{}, time.Time{}, cfg.ErrUnavailable
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	v.CompletedAt = &now
	r.record = &v
	r.completions++
	if r.loseCompletion {
		r.loseCompletion = false
		return contracts.InitialPreparationRoot{}, time.Time{}, cfg.ErrUnavailable
	}
	return contracts.InitialPreparationRoot{Schema: &v}, time.Now().Add(5 * time.Second), nil
}
