// Package edge records how a public request reached the hub-api (ADR-327).
package edge

import (
	"context"
	"net/http"
)

type tlsProxyKey struct{}

// WithTLSProxy marks a listener's base context: the operator's Ingress or
// Gateway terminated TLS for the https origin and forwarded plain HTTP.
func WithTLSProxy(ctx context.Context) context.Context {
	return context.WithValue(ctx, tlsProxyKey{}, true)
}

// Secure reports whether the request arrived over TLS at the hub-api or at
// the operator's TLS-terminating proxy. Forwarded headers are never read.
func Secure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	proxied, _ := r.Context().Value(tlsProxyKey{}).(bool)
	return proxied
}
