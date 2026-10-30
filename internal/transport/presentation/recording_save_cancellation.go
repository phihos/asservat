package presentation

import (
	identities "asservat.local/asservat/internal/application/identity"
	value "asservat.local/asservat/internal/domain/capture"
	"context"
)

type RecordingCancellationUseCase interface {
	Cancel(context.Context, identities.CurrentIdentity, value.CancellationRequest) (value.Cancellation, error)
}
type RecordingCancellationData struct {
	CaptureID     string `json:"capture_id"`
	Phase         string `json:"phase"`
	Revision      int64  `json:"revision"`
	Requested     bool   `json:"cancellation_requested"`
	NavigationURI string `json:"navigation_uri"`
}
