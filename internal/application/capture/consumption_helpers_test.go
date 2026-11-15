package capture

import (
	"context"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

type consumptionStorageFunc func(context.Context, authorization.Target) (ContextStorageObservation, error)

func (f consumptionStorageFunc) ContextStorage(ctx context.Context, target authorization.Target) (ContextStorageObservation, error) {
	return f(ctx, target)
}

type consumptionFacts struct {
	*investigationFixture
	eligible               ContextEligibilityReader
	eligibility, caps, ret int
	bound                  string
	until                  time.Time
}

func (r *consumptionFacts) ContextEligibilityCurrent(ctx context.Context, source identities.CurrentIdentity, target authorization.Target) authorization.CaptureEligibility {
	r.eligibility++
	out := r.eligible.ContextEligibilityCurrent(ctx, source, target)
	if r.bound == "eligibility" {
		out.ValidUntil = r.until
	}
	if r.bound == "eligibility-identity" {
		out.VerifiedIdentity.ValidUntil = r.until
	}
	return out
}

func (r *consumptionFacts) ContextCapability(ctx context.Context, target authorization.Target) (planning.ContextCapability, error) {
	r.caps++
	out, err := r.investigationFixture.ContextCapability(ctx, target)
	if r.bound == "capability" {
		out.FreshUntil = r.until
	}
	return out, err
}

func (r *consumptionFacts) Resolve(ctx context.Context, in privacy.Input) (privacy.Resolution, error) {
	r.ret++
	out, err := r.investigationFixture.Resolve(ctx, in)
	if r.bound == "retention" {
		out.ValidUntil = r.until
	}
	if r.bound == "retention-proof" {
		out.ValidUntil, out.Proof.ValidUntil = r.until, r.until
	}
	return out, err
}

type consumptionAdmission struct {
	*investigationFixture
	got value.Admission
}

type consumptionRecovery struct {
	*investigationFixture
	until time.Time
}

func (r consumptionRecovery) RecoveryState(ctx context.Context) (artifact.RecoveryProof, error) {
	out, err := r.investigationFixture.RecoveryState(ctx)
	out.FreshUntil = r.until
	return out, err
}

type consumptionTarget struct {
	*investigationFixture
	until time.Time
}

func (r consumptionTarget) ResolvePod(ctx context.Context, target targets.Request) (targets.PodResolution, error) {
	out, err := r.investigationFixture.ResolvePod(ctx, target)
	out.FreshUntil = r.until
	return out, err
}

func (a *consumptionAdmission) AdmitReviewedContext(ctx context.Context, id string, in value.Admission) (value.Accepted, error) {
	a.got = in
	return a.investigationFixture.AdmitReviewedContext(ctx, id, in)
}
