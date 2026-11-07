package evidence

import (
	auditport "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"context"
	"reflect"
	"slices"
	"time"
)

// ContextPublicationGate must establish current accepted result, collector and
// privacy authority independently of uploaded bytes and the public request.
// Its production composition is not replaced by the SQL acceptance lookup.
type ContextPublicationGate interface {
	CheckContextPublication(context.Context, artifact.ContextExpectation) (artifact.PublicationAuthority, error)
}
type ContextAcceptanceReader interface {
	AcceptedContextForPublication(context.Context, string) (artifact.ContextExpectation, error)
}
type ContextVerificationRecorder interface {
	// The trusted recorder requires timing for a new profile verdict and matches
	// non-null existing timing. A historical null remains unknown on replay;
	// it is never backfilled or used to rewrite an immutable audit record.
	RecordContextVerification(context.Context, artifact.ContextExpectation, artifact.Copies, artifact.PublicationAuthority, artifact.ContextVerificationResult) (audit.ContextVerification, error)
}
type ContextVerificationAuditor interface {
	AcknowledgeContextVerification(context.Context, audit.ContextVerification, audit.Receipt) error
}
type ContextCatalogPublisher interface {
	PublishContext(context.Context, artifact.ContextExpectation, artifact.Copies, artifact.PublicationAuthority) (artifact.PublishedContext, error)
}
type ContextPublicationLedger interface {
	ContextAcceptanceReader
	ContextVerificationRecorder
	ContextVerificationAuditor
	ContextCatalogPublisher
}

// Compose separately credentialed adapters without granting any SQL role all
// four capabilities. Embedding exposes only each consumer-owned facet.
type ContextPublicationFacets struct {
	ContextAcceptanceReader
	ContextVerificationRecorder
	ContextVerificationAuditor
	ContextCatalogPublisher
}
type ContextPublisher struct {
	Ledger    ContextPublicationLedger
	Authority ContextPublicationGate
	Verifier  ContextVerifier
	Audit     auditport.ContextVerificationWriter
	Now       func() time.Time
}

// Publish never trusts a stored_unpublished status as semantic verification.
// Replays verify the original immutable copies; they never recollect evidence.
func (p ContextPublisher) Publish(ctx context.Context, captureID string, copies artifact.Copies) (artifact.PublishedContext, error) {
	var out artifact.PublishedContext
	if p.Ledger == nil || p.Authority == nil || p.Verifier == nil || p.Audit == nil || p.Now == nil {
		return out, privacy.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	e, err := p.Ledger.AcceptedContextForPublication(ctx, captureID)
	if err != nil {
		return out, PublicationStage("accepted", err)
	}
	if e.Validate() != nil || e.CaptureUID != captureID || !e.ServedClass() || copies.Validate(e.Registration) != nil {
		return out, artifact.ErrInvalid
	}
	e.Audience = slices.Clone(e.Audience)
	e.RetentionRules = slices.Clone(e.RetentionRules)
	immutable := ContextExpectationDigest(e)
	check := func() (artifact.PublicationAuthority, error) {
		a, err := p.Authority.CheckContextPublication(ctx, e)
		if err != nil {
			return a, err
		}
		if ContextExpectationDigest(e) != immutable {
			return a, artifact.ErrIntegrity
		}
		if ctx.Err() != nil || !a.Valid(e, ContextExpectationDigest(e), p.Now()) {
			return a, privacy.ErrExpired
		}
		return a, nil
	}
	before, err := check()
	if err != nil {
		return out, PublicationStage("authority", err)
	}
	verified, err := p.Verifier.VerifyContext(ctx, e, copies)
	if err != nil {
		return out, PublicationStage("verify", err)
	}
	if !verified.Valid(e) {
		return out, artifact.ErrIntegrity
	}
	verified = verified.Clone()
	current, err := check()
	if err != nil {
		return out, PublicationStage("authority-after-verify", err)
	}
	if current.RootID != before.RootID {
		return out, privacy.ErrConflict
	}
	record, err := p.Ledger.RecordContextVerification(ctx, e, copies, current, verified)
	if err != nil {
		return out, PublicationStage("record", err)
	}
	if !record.Valid() || record.NativeBytes != nil && *record.NativeBytes != verified.NativeBytes || record.Acquisition != nil && (verified.Acquisition == nil || !record.Acquisition.Equal(*verified.Acquisition)) || record.RootID != current.RootID || record.CaptureID != captureID || record.ArtifactID != e.Registration.Location.ArtifactID || record.AttemptID != e.Registration.Location.AttemptID || record.ScopeDigest != e.PlanDigest || record.ExpectationDigest != ContextExpectationDigest(e) || record.CopiesDigest != ContextCopiesDigest(copies) || record.VerifiedAt.After(p.Now()) || !record.WriteUntil.Equal(e.Registration.WriteUntil) || !record.ExpiresAt.Equal(e.Registration.ExpiresAt) || !record.DeleteBy.Equal(e.Registration.DeleteBy) {
		return out, artifact.ErrIntegrity
	}
	receipt, err := p.Audit.WriteContextVerification(ctx, record)
	if err != nil {
		return out, PublicationStage("audit", err)
	}
	if !receipt.ValidContextVerification(record.RootID, captureID) {
		return out, artifact.ErrIntegrity
	}
	if err = p.Ledger.AcknowledgeContextVerification(ctx, record, receipt); err != nil {
		return out, PublicationStage("acknowledge", err)
	}
	current, err = check()
	if err != nil {
		return out, PublicationStage("authority-before-publish", err)
	}
	if current.RootID != record.RootID {
		return out, privacy.ErrConflict
	}
	out, err = p.Ledger.PublishContext(ctx, e, copies, current)
	if err != nil {
		return artifact.PublishedContext{}, PublicationStage("publish", err)
	}
	if out.RootID != record.RootID || out.CaptureID != captureID || !reflect.DeepEqual(out.Expectation, e) || out.Copies != copies || !out.VerifiedAt.Equal(record.VerifiedAt) || out.PublishedAt.Before(out.VerifiedAt) || !out.PublishedAt.Before(e.Registration.ExpiresAt) {
		return artifact.PublishedContext{}, artifact.ErrIntegrity
	}
	return out, nil
}

// PublicationStageError names the fixed publication step that refused; it
// carries no dependency text and keeps the original error class.
type PublicationStageError struct {
	Stage string
	Err   error
}

func (e *PublicationStageError) Error() string { return "publication " + e.Stage + ": " + e.Err.Error() }
func (e *PublicationStageError) Unwrap() error { return e.Err }

func PublicationStage(stage string, err error) error {
	return &PublicationStageError{Stage: stage, Err: err}
}
