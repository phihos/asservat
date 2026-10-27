//go:build ignore

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Exercise the actual helper config against real local TLS without PostgreSQL,
// a second SQL bridge, a probe in the helper, or a provider/authority fallback.
func TestSQLTrustTransferPreservesVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong := &x509.Certificate{SerialNumber: big.NewInt(42), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	wrongRoot, err := x509.CreateCertificate(rand.Reader, wrong, wrong, public, key)
	if err != nil {
		t.Fatal(err)
	}
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	for _, mode := range []string{"verified", "wrong-root", "wrong-name", "absent-tls"} {
		t.Run(mode, func(t *testing.T) {
			in := input{Postgres: "postgres://native_owner_runtime:synthetic@127.0.0.1:1/custody_test?sslmode=disable", SQLRoots: root, SQLServerName: "127.0.0.1", SQLMinimumVersion: tls.VersionTLS12}
			switch mode {
			case "wrong-root":
				in.SQLRoots = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrongRoot})
			case "wrong-name":
				in.SQLServerName = "different.invalid"
			case "absent-tls":
				in.SQLRoots = nil
			}
			config, err := postgresConfig(in)
			if mode == "absent-tls" {
				if err == nil {
					t.Fatal("absent TLS configuration accepted")
				}
				return
			}
			if err != nil || config.ConnConfig.TLSConfig.InsecureSkipVerify || len(config.ConnConfig.Fallbacks) != 0 {
				t.Fatal("verified config lost pinned TLS", err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			conn, err := (&tls.Dialer{Config: config.ConnConfig.TLSConfig}).DialContext(ctx, "tcp", strings.TrimPrefix(server.URL, "https://"))
			if mode != "verified" {
				if err == nil {
					conn.Close()
					t.Fatal("wrong SQL root/name authenticated")
				}
				return
			}
			if err != nil {
				t.Fatal("transferred SQL trust failed real TLS", err)
			}
			conn.Close()
		})
	}
}
