package identity

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/identity"
)

type BrowserSettingsReader interface {
	BrowserSettings(context.Context) (value.BrowserSettings, error)
}
type BrowserSettingsProjection interface {
	ObserveBrowserSettings(context.Context, value.BrowserSettings) error
	FenceBrowserSettings(context.Context, time.Time) error
}
type BrowserSettingsObserver struct {
	Source     BrowserSettingsReader
	Projection BrowserSettingsProjection
	Now        func() time.Time
}

// Reconcile never treats a failed read as an instruction to retain a fresh
// enabled projection. The fenced failure cannot override a later success.
func (s BrowserSettingsObserver) Reconcile(ctx context.Context) error {
	if s.Source == nil || s.Projection == nil || s.Now == nil {
		return value.ErrUnavailable
	}
	started := s.Now()
	read, cancel := context.WithTimeout(ctx, 5*time.Second)
	settings, err := s.Source.BrowserSettings(read)
	if err == nil && (!settings.Valid(s.Now()) || settings.ObservedAt.Before(started) || s.Now().Before(started)) {
		err = value.ErrUnavailable
	}
	if err == nil {
		err = s.Projection.ObserveBrowserSettings(read, settings)
	}
	cancel()
	if err == nil {
		return nil
	}
	fence, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer stop()
	_ = s.Projection.FenceBrowserSettings(fence, started)
	return value.ErrUnavailable
}
