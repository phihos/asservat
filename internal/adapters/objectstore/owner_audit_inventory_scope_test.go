package objectstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
)

func TestOwnerAuditInventoryExpiredIssuerAndDeletedSourceAreHistoricalOnly(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c := ownerInventoryConfiguration()
	c.IssuerRoots = [][]byte{der}
	old := fleet.OwnerConfigurationObservation{Configuration: c, ObservedAt: cert.NotBefore, FreshUntil: cert.NotBefore.Add(5 * time.Second)}
	if old.Valid(time.Now()) || !time.Now().After(cert.NotAfter) {
		t.Fatal("historical fixture unexpectedly current")
	}
	body := ownerInventoryBodies(c)
	reader, calls := ownerInventoryFixture(t, old.Configuration, func(kind string, w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body[kind]) })
	// The diagnostic has no current Kubernetes/source or credential-activation
	// reader. Deleting the test-owned original source variable cannot prevent
	// inventory of bytes still identified by the independently copied history.
	old = fleet.OwnerConfigurationObservation{}
	got, err := reader.Read(context.Background())
	if err != nil || len(got.Versions) != 1 || calls.Load() != 3 || !got.Configuration.Equal(c) {
		t.Fatal("expired issuer history blocked physical diagnosis", err)
	}
	if got.ReadUntil.Sub(got.ReadStartedAt) > 5*time.Second {
		t.Fatal("diagnostic interval expanded")
	}
}

func TestOwnerAuditInventoryRejectsInvalidPinsBeforeProviderIO(t *testing.T) {
	c := ownerInventoryConfiguration()
	body := ownerInventoryBodies(c)
	reader, calls := ownerInventoryFixture(t, c, func(kind string, w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body[kind]) })
	for _, mode := range []string{"nil-store", "zero-store", "bad-store-id", "empty-configuration", "zero-generation", "bad-original-root"} {
		t.Run(mode, func(t *testing.T) {
			store, storeID, original := reader.store, reader.storeID, c.Clone()
			switch mode {
			case "nil-store":
				store = nil
			case "zero-store":
				store = &Store{}
			case "bad-store-id":
				storeID = "replacement"
			case "empty-configuration":
				original = fleet.OwnerConfiguration{}
			case "zero-generation":
				original.Revision.Generation = 0
			case "bad-original-root":
				original.Pool.InstallationID = "replacement"
			}
			got, err := NewOwnerConfigurationAuditInventory(store, storeID, original)
			if !errors.Is(err, artifact.ErrInvalid) || got != nil || calls.Load() != 0 {
				t.Fatal("invalid original pin admitted provider read", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reader.Read(ctx); !errors.Is(err, context.Canceled) || calls.Load() != 0 {
		t.Fatal("cancelled read reached provider", err)
	}
	past, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := reader.Read(past); !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 0 {
		t.Fatal("expired caller reached provider", err)
	}
}

func TestOwnerAuditInventoryPreservesOversizedPhysicalVersion(t *testing.T) {
	c := ownerInventoryConfiguration()
	body := ownerInventoryBodies(c)
	key := audit.OwnerConfigurationAuditKey(c)
	body["versions"] = strings.Replace(body["versions"], "</ListVersionsResult>", ownerInventoryVersion(key, "unexpected-large-copy", "9223372036854775807", false)+"</ListVersionsResult>", 1)
	reader, _ := ownerInventoryFixture(t, c, func(kind string, w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body[kind]) })
	got, err := reader.Read(context.Background())
	if err != nil || len(got.Versions) != 2 || got.Versions[1].CiphertextBytes != int64(1<<63-1) {
		t.Fatal("unexpected physical copy hidden behind logical audit limit", err)
	}
	// There is deliberately no unchecked byte summation, capacity admission,
	// payload GET or refund derived from this metadata diagnostic.
}
