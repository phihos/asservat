package bootstrap

import (
	"context"
	"encoding/hex"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"github.com/tink-crypto/tink-go/v2/tink"
)

type operationCredentialFixture struct {
	until time.Time
	reads atomic.Int32
}

func (s *operationCredentialFixture) ReadAuditCredentials(ctx context.Context) (contracts.OwnerStorageCredential, time.Time, error) {
	s.reads.Add(1)
	if ctx.Err() != nil {
		return contracts.OwnerStorageCredential{}, time.Time{}, ctx.Err()
	}
	return contracts.OwnerStorageCredential{AccessKeyID: "synthetic", SecretAccessKey: "synthetic"}, s.until, nil
}

type operationAuditKeys struct {
	a              tink.AEAD
	wraps, unwraps int
	waitOpen       bool
	enteredOpen    chan struct{}
	releaseOpen    <-chan struct{}
}

func (s *operationAuditKeys) Seal(ctx context.Context, b, ad []byte) (artifact.SealedKey, error) {
	s.wraps++
	c, e := s.a.Encrypt(b, ad)
	return artifact.SealedKey{Reference: "synthetic", Ciphertext: hex.EncodeToString(c)}, e
}
func (s *operationAuditKeys) Open(ctx context.Context, k artifact.SealedKey, ad []byte) ([]byte, error) {
	s.unwraps++
	if s.enteredOpen != nil {
		close(s.enteredOpen)
		<-s.releaseOpen
	}
	if s.waitOpen {
		<-ctx.Done()
	}
	c, e := hex.DecodeString(k.Ciphertext)
	if e != nil {
		return nil, e
	}
	return s.a.Decrypt(c, ad)
}
