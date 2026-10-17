// Package evidence defines the application-owned boundaries for evidence custody.
package evidence

import (
	"context"
	"io"

	"asservat.local/asservat/internal/domain/artifact"
)

// KeySealer is the collector's wrap-only capability. Implementations must bind
// keysets to binding, use the configured KMS key and never log their arguments.
// Clear keysets exist only in bounded process memory. A wrap failure prevents
// source acquisition. There is deliberately no Unseal method on this port.
type KeySealer interface {
	Seal(context.Context, []byte, []byte) (artifact.SealedKey, error)
}

// KeyOpener belongs to the separately authorized regional acquisition role.
// The adapter must refuse key references outside its configured authorization.
type KeyOpener interface {
	Open(context.Context, artifact.SealedKey, []byte) ([]byte, error)
}

// CipherSource reads exact ranges of an already pinned immutable data/index
// object. Implementations reject changed versions, short/oversized replies and
// unrequested ranges. It exposes no bucket listing or arbitrary object lookup.
type CipherSource interface {
	ReadRange(context.Context, int64, int64) ([]byte, error)
}

// Delivery is called before every <=1 MiB native batch. The caller implements
// current authority, durable byte spend, absolute deadline and audit checks.
// Returning an error stops output. This port is not satisfied by a browser flag.
type Delivery interface {
	Send(context.Context, []byte) error
}

// StorageEncoder consumes a bounded native stream after keys are prepared.
// Destination writers receive ciphertext only. Successful encoding is not an
// artifact commit; the commit service must verify stored objects and custody.
type StorageEncoder interface {
	Encode(context.Context, io.Reader, io.Writer, io.Writer, int64) (artifact.Layout, error)
}
