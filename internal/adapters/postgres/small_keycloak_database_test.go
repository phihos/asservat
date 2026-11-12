package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"github.com/jackc/pgx/v5/pgproto3"
)

// This is a protocol/TLS consumer test, not a real PostgreSQL catalog test.
// The returned booleans are synthetic; production SQL still needs real PG.
func smallKeycloakDatabaseWire(t *testing.T, mode string) (contracts.OwnerPostgresEndpoint, *atomic.Int32, <-chan struct{}) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic PostgreSQL"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var starts atomic.Int32
	queried := make(chan struct{}, 1)
	var wg sync.WaitGroup
	var mu sync.Mutex
	active := map[net.Conn]struct{}{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			starts.Add(1)
			mu.Lock()
			active[raw] = struct{}{}
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { raw.Close(); mu.Lock(); delete(active, raw); mu.Unlock() }()
				raw.SetDeadline(time.Now().Add(3 * time.Second))
				backend := pgproto3.NewBackend(raw, raw)
				message, err := backend.ReceiveStartupMessage()
				if err != nil {
					return
				}
				if _, ok := message.(*pgproto3.CancelRequest); ok {
					return
				}
				if _, ok := message.(*pgproto3.SSLRequest); !ok {
					t.Error("PostgreSQL connection did not request TLS")
					return
				}
				if mode == "plaintext" {
					raw.Write([]byte("N"))
					return
				}
				if _, err = raw.Write([]byte("S")); err != nil {
					return
				}
				encrypted := tls.Server(raw, serverTLS)
				backend = pgproto3.NewBackend(encrypted, encrypted)
				message, err = backend.ReceiveStartupMessage()
				if err != nil {
					return
				}
				startup, ok := message.(*pgproto3.StartupMessage)
				if !ok {
					return
				}
				if startup.Parameters["user"] != "keycloak" || startup.Parameters["database"] != "keycloak" || startup.Parameters["default_transaction_read_only"] != "on" || startup.Parameters["statement_timeout"] != "5000ms" {
					t.Error("changed exact database/user/read-only startup")
				}
				backend.Send(&pgproto3.AuthenticationOk{})
				backend.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
				backend.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})
				backend.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{1, 2, 3, 4}})
				backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				if backend.Flush() != nil {
					return
				}
				message, err = backend.Receive()
				if err != nil {
					return
				}
				query, ok := message.(*pgproto3.Query)
				if !ok || !strings.HasPrefix(query.String, "SELECT") {
					t.Error("unexpected non-read-only statement")
					return
				}
				select {
				case queried <- struct{}{}:
				default:
				}
				if mode == "cancel" {
					for {
						if _, err = backend.Receive(); err != nil {
							return
						}
					}
				}
				if mode == "query-error" {
					backend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42501", Message: "synthetic private database diagnostic"})
				} else {
					same, present := "t", "f"
					if mode == "nonempty" {
						present = "t"
					}
					if mode == "wrong-identity" {
						same = "f"
					}
					backend.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("same"), DataTypeOID: 16, DataTypeSize: 1}, {Name: []byte("present"), DataTypeOID: 16, DataTypeSize: 1}}})
					backend.Send(&pgproto3.DataRow{Values: [][]byte{[]byte(same), []byte(present)}})
					backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
				}
				backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				if backend.Flush() != nil {
					return
				}
				backend.Receive()
			}()
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		mu.Lock()
		for conn := range active {
			conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return contracts.OwnerPostgresEndpoint{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, Database: "keycloak", Roots: [][]byte{der}, MaxConnections: 1}, &starts, queried
}

func TestSmallKeycloakDatabasePresenceUsesVerifiedTLSAndExactReadOnlyIdentity(t *testing.T) {
	for _, mode := range []string{"empty", "nonempty", "wrong-identity", "query-error", "plaintext"} {
		t.Run(mode, func(t *testing.T) {
			endpoint, starts, _ := smallKeycloakDatabaseWire(t, mode)
			proof, err := NewSmallKeycloakDatabasePresence(endpoint, contracts.OwnerSQLCredential{Username: "keycloak", Password: "synthetic-private-password"})
			if err != nil {
				t.Fatal(err)
			}
			if proof.config.TLSConfig.InsecureSkipVerify || proof.config.TLSConfig.ServerName != endpoint.Host || proof.config.TLSConfig.MinVersion != tls.VersionTLS13 || len(proof.config.Fallbacks) != 0 || proof.config.Password != "synthetic-private-password" {
				t.Fatal("weakened explicit connection inputs")
			}
			exists, err := proof.Exists(t.Context())
			if mode == "empty" || mode == "nonempty" {
				if err != nil || exists != (mode == "nonempty") {
					t.Fatal("wire result changed", err)
				}
			} else {
				if !errors.Is(err, cfg.ErrUnavailable) || exists || strings.Contains(err.Error(), "synthetic") {
					t.Fatal("failed proof admitted state or exposed provider details")
				}
			}
			if starts.Load() != 1 {
				t.Fatal("successful/ordinary refused proof retried connection")
			}
		})
	}
}

func TestSmallKeycloakDatabasePresencePreservesCancellationAndExplicitInputs(t *testing.T) {
	endpoint, _, queried := smallKeycloakDatabaseWire(t, "cancel")
	credential := contracts.OwnerSQLCredential{Username: "keycloak", Password: "synthetic-private-password"}
	proof, err := NewSmallKeycloakDatabasePresence(endpoint, credential)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := proof.Exists(ctx); done <- err }()
	select {
	case <-queried:
	case <-time.After(time.Second):
		t.Fatal("query not reached")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, cfg.ErrUnavailable) {
			t.Fatal("cancellation supplied empty proof")
		}
	case <-time.After(time.Second):
		t.Fatal("caller cancellation did not bound read")
	}
	for _, change := range []func(*contracts.OwnerPostgresEndpoint){func(p *contracts.OwnerPostgresEndpoint) { p.Roots = nil }, func(p *contracts.OwnerPostgresEndpoint) { p.Host = "/var/run/postgresql" }, func(p *contracts.OwnerPostgresEndpoint) { p.MaxConnections = 5 }, func(p *contracts.OwnerPostgresEndpoint) { p.Database = "" }} {
		p := endpoint
		change(&p)
		if _, err := NewSmallKeycloakDatabasePresence(p, credential); err == nil {
			t.Fatal("invalid explicit source accepted")
		}
	}
	t.Setenv("PGDATABASE", "ambient-replacement")
	if _, err := NewSmallKeycloakDatabasePresence(endpoint, credential); err == nil {
		t.Fatal("ambient PostgreSQL configuration accepted")
	}
}
