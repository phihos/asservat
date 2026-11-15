package native

import (
	"context"
	"crypto/x509"
	"net"
)

// Serve serves one native handler alone, for tests of the handler.
func Serve(ctx context.Context, listener net.Listener, roots *x509.CertPool, credentials ServerCredentials, handler *Handler, connections int) error {
	if handler == nil {
		return nil
	}
	return serve(ctx, listener, roots, nil, credentials, handler.host, handler, nil, nil, connections, 0)
}
