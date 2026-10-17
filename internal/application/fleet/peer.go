package fleet

import (
	"context"
	"time"

	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

type PeerRegistry interface {
	PeerRegistration(context.Context, value.PeerBinding) (value.PeerRegistration, error)
}

// ExactPeerRegistry avoids enumerating retained process history. The input leaf
// has already been independently verified from the actual TLS connection.
// A failed exact lookup must never fall back to legacy logical-peer slots.
type ExactPeerRegistry interface {
	PeerCertificateRegistration(context.Context, value.PeerCertificate) (value.PeerRegistration, error)
}

type PeerAuthenticator struct {
	Registry PeerRegistry
	Now      func() time.Time
}

// AuthenticatePeer requires an independently verified TLS certificate. The
// current registry check runs on each request, including reused TLS sessions.
// No peer claim or TLS success alone confers cluster or node authority.
func (a PeerAuthenticator) AuthenticatePeer(ctx context.Context, c value.PeerCertificate) (value.AuthenticatedPeer, error) {
	var out value.AuthenticatedPeer
	if a.Registry == nil || a.Now == nil {
		return out, value.ErrUnavailable
	}
	if !c.Valid(a.Now()) {
		return out, value.ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var r value.PeerRegistration
	var err error
	if exact, ok := a.Registry.(ExactPeerRegistry); ok {
		r, err = exact.PeerCertificateRegistration(ctx, c)
	} else {
		r, err = a.Registry.PeerRegistration(ctx, c.Binding)
	}
	if err != nil {
		return out, value.ErrUnavailable
	}
	now := a.Now()
	if ctx.Err() != nil || !r.Valid(now) || r.Binding != c.Binding || !c.Valid(now) {
		return out, value.ErrDenied
	}
	found := false
	for _, current := range r.Certificates {
		if current == c {
			found = true
		}
	}
	if !found {
		return out, value.ErrDenied
	}
	return value.AuthenticatedPeer{Certificate: c, RegistrationRevision: r.Revision, VerifiedAt: now, ValidUntil: identity.Earlier(c.NotAfter, r.FreshUntil)}, nil
}
