package integration

import (
	"context"
	"fmt"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
)

// Preserve errors.Is and the actual publication sequence while identifying the
// failed facet. These diagnostics contain no evidence, credentials or proofs.
type publicationDiagnosticLedger struct {
	evidence.ContextPublicationLedger
}

func publicationStepError(step string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("publication %s: %w", step, err)
}

func (d publicationDiagnosticLedger) AcceptedContextForPublication(ctx context.Context, id string) (artifact.ContextExpectation, error) {
	v, err := d.ContextPublicationLedger.AcceptedContextForPublication(ctx, id)
	return v, publicationStepError("accepted context", err)
}

func (d publicationDiagnosticLedger) RecordContextVerification(ctx context.Context, e artifact.ContextExpectation, c artifact.Copies, a artifact.PublicationAuthority) (audit.ContextVerification, error) {
	v, err := d.ContextPublicationLedger.RecordContextVerification(ctx, e, c, a)
	return v, publicationStepError("verification record", err)
}

func (d publicationDiagnosticLedger) AcknowledgeContextVerification(ctx context.Context, v audit.ContextVerification, r audit.Receipt) error {
	return publicationStepError("audit acknowledgement", d.ContextPublicationLedger.AcknowledgeContextVerification(ctx, v, r))
}

func (d publicationDiagnosticLedger) PublishContext(ctx context.Context, e artifact.ContextExpectation, c artifact.Copies, a artifact.PublicationAuthority) (artifact.PublishedContext, error) {
	v, err := d.ContextPublicationLedger.PublishContext(ctx, e, c, a)
	return v, publicationStepError("catalog commit", err)
}
