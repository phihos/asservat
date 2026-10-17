package evidence

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"context"
	"time"
)

// The coordinator authenticates the caller over its private channel. The
// bearer token must never come from headers trusted by a public request.
type DownloadPeerToken interface {
	// Return a fresh caller-owned buffer. The consumer clears it after use;
	// implementations must not return a shared cache or retain its contents.
	ReadDownloadPeerToken(context.Context) ([]byte, error)
}
type DownloadPeerProofReader interface {
	ReadDownloadPeerProof(context.Context, string, authorization.KeyPeer) (authorization.KeyWorkerProof, error)
}
type DownloadKeyBindingLedger interface {
	BindAttestedDownloadKeys(context.Context, string, artifact.DownloadAuthority, string, int64, authorization.KeyScope, authorization.KeyPeer, authorization.KeyWorkerProof) error
}
type AttestedDownloadKeyGrants struct {
	Proofs DownloadPeerProofReader
	Ledger DownloadKeyBindingLedger
	Now    func() time.Time
}

var _ DownloadKeyGrants = (*AttestedDownloadKeyGrants)(nil)

func (s *AttestedDownloadKeyGrants) BindDownloadKeys(ctx context.Context, session string, a artifact.DownloadAuthority, batch string, generation int64, scope authorization.KeyScope, peer authorization.KeyPeer) error {
	if s == nil || ctx == nil || s.Proofs == nil || s.Ledger == nil || s.Now == nil || !authorization.UUID(session) || !a.Valid(s.Now()) || !peer.Valid(s.Now()) || !peer.CanRequest(scope, "unwrap") {
		return artifact.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p, e := s.Proofs.ReadDownloadPeerProof(ctx, session, peer)
	if e != nil || ctx.Err() != nil || !p.Valid(s.Now()) || p.Binding.DownloadID != session || p.Peer != peer {
		return artifact.ErrInvalid
	}
	effect, end := context.WithDeadline(ctx, p.FreshUntil)
	defer end()
	if e = s.Ledger.BindAttestedDownloadKeys(effect, session, a, batch, generation, scope, peer, p); e != nil {
		return e
	}
	if effect.Err() != nil || !p.Valid(s.Now()) {
		return artifact.ErrInvalid
	}
	return nil
}
