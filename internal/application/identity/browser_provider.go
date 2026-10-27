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

// StepUpBrowserProvider requests configured assurance during login. The redirect
// itself never establishes assurance; signed claims are checked on every use.
type StepUpBrowserProvider interface {
	StepUpAuthorizationURL(state, nonce, verifier string, acrValues []string) (string, error)
}

type LogoutEvent struct {
	Issuer, ClientID, Subject, SessionID, ID string
	IssuedAt                                 time.Time
}

type LogoutVerifier interface {
	VerifyLogout(context.Context, string) (LogoutEvent, error)
}
