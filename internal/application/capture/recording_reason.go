package capture

import (
	"context"

	value "asservat.local/asservat/internal/domain/capture"
)

func validOptionalReason(text *string) bool {
	return text == nil || value.ValidReason(*text)
}

// preparePreviewReason records the optional descriptive reason as plain
// preview data (ADR-330 D8). It changes no collection scope or authority.
func (s ContextInvestigation) preparePreviewReason(_ context.Context, p *value.ContextPreview, text *string) error {
	if !validOptionalReason(text) {
		return value.ErrInvalid
	}
	if text == nil {
		return nil
	}
	if p == nil || p.Intent.Reason != nil {
		return value.ErrUnavailable
	}
	reason := *text
	p.Intent.Reason = &reason
	return nil
}
