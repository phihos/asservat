package edge

import (
	"context"
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

func TestSecureRequiresTLSOrAMarkedProxyListener(t *testing.T) {
	plain := httptest.NewRequest("GET", "http://hub/", nil)
	if Secure(plain) {
		t.Fatal("plain HTTP without a proxy listener counted as secure")
	}
	direct := httptest.NewRequest("GET", "https://hub/", nil)
	direct.TLS = &tls.ConnectionState{}
	if !Secure(direct) {
		t.Fatal("direct TLS refused")
	}
	if !Secure(plain.WithContext(WithTLSProxy(context.Background()))) {
		t.Fatal("proxy listener refused")
	}
	spoofed := httptest.NewRequest("GET", "http://hub/", nil)
	spoofed.Header.Set("X-Forwarded-Proto", "https")
	if Secure(spoofed) {
		t.Fatal("forwarded header conferred transport trust")
	}
}
