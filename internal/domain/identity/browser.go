package identity

import (
	"errors"
	"time"
)

var ErrSessionBusy = errors.New("session refresh in progress")
var ErrSessionCapacity = errors.New("session capacity reached")

const MaxSessionCiphertext = 256 << 10

type BrowserLogin struct {
	ID, Browser          [32]byte
	Ciphertext           []byte
	CreatedAt, ExpiresAt time.Time
}
type BrowserSession struct {
	ID                                               [32]byte
	Principal                                        Principal
	ProviderSession                                  string
	Ciphertext                                       []byte
	CreatedAt, AuthenticatedAt, ExpiresAt, RefreshAt time.Time
	Version                                          int64
	// Observation is supplied by current SQL reads/creation, never persisted as
	// a reusable lease. CSRF-only reads deliberately leave it empty.
	Observation SessionObservation
}

type SessionObservation struct {
	Settings               Revision
	ObservedAt, FreshUntil time.Time
}

func (s BrowserSession) Current(now time.Time) bool {
	return s.Valid(now) && s.Observation.Settings.Valid() && Fresh(s.Observation.ObservedAt, s.Observation.FreshUntil, now, 5*time.Second) && !s.Observation.FreshUntil.After(s.ExpiresAt)
}

func (l BrowserLogin) Valid(now time.Time) bool {
	return l.ID != ([32]byte{}) && l.Browser != ([32]byte{}) && len(l.Ciphertext) > 0 && len(l.Ciphertext) <= MaxSessionCiphertext && Fresh(l.CreatedAt, l.ExpiresAt, now, 5*time.Minute)
}
func (s BrowserSession) Valid(now time.Time) bool {
	return s.ID != ([32]byte{}) && s.Principal.Valid() && s.Principal.Kind == Human && Text(s.ProviderSession, 256) && len(s.Ciphertext) > 0 && len(s.Ciphertext) <= MaxSessionCiphertext && s.Version > 0 && Fresh(s.CreatedAt, s.ExpiresAt, now, 24*time.Hour) && !s.AuthenticatedAt.IsZero() && !s.AuthenticatedAt.After(now) && s.RefreshAt.After(s.CreatedAt) && !s.RefreshAt.After(s.ExpiresAt)
}
