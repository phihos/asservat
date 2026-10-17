package identity

import (
	"context"
	"time"
)

// BrowserTokens is transient server-side credential material. Never serialize
// it to a public response, audit record or ordinary log.
type BrowserTokens struct {
	Access, Refresh, Subject, SessionID  string
	IssuedAt, ExpiresAt, AuthenticatedAt time.Time
}

type BrowserProvider interface {
	AuthorizationURL(state, nonce, verifier string) (string, error)
	Exchange(context.Context, string, string, string) (BrowserTokens, error)
	Refresh(context.Context, string, string, string, string) (BrowserTokens, error)
}

type LogoutEvent struct {
	Issuer, ClientID, Subject, SessionID, ID string
	IssuedAt                                 time.Time
}

type LogoutVerifier interface {
	VerifyLogout(context.Context, string) (LogoutEvent, error)
}
