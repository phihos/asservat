package identity

import (
	"errors"
	"time"
)

var ErrSessionBusy = errors.New("session refresh in progress")

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
}

func (l BrowserLogin) Valid(now time.Time) bool {
	return l.ID != ([32]byte{}) && l.Browser != ([32]byte{}) && len(l.Ciphertext) > 0 && len(l.Ciphertext) <= MaxSessionCiphertext && Fresh(l.CreatedAt, l.ExpiresAt, now, 5*time.Minute)
}
func (s BrowserSession) Valid(now time.Time) bool {
	return s.ID != ([32]byte{}) && s.Principal.Valid() && s.Principal.Kind == Human && Text(s.ProviderSession, 256) && len(s.Ciphertext) > 0 && len(s.Ciphertext) <= MaxSessionCiphertext && s.Version > 0 && !s.CreatedAt.IsZero() && !s.CreatedAt.After(now) && now.Before(s.ExpiresAt) && !s.AuthenticatedAt.IsZero() && !s.AuthenticatedAt.After(now) && s.RefreshAt.After(s.CreatedAt) && !s.RefreshAt.After(s.ExpiresAt)
}
