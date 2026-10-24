package bootstrap

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
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
func installedAuditIntent(t *testing.T) audit.OperationIntent {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := "10000000-0000-4000-8000-000000000031"
	in := audit.OperationIntent{ID: id, RootID: id, TraceID: id, Name: "preview_capture", InputFormat: "context-input/v1", MACVersion: "v1", AccountVersion: "synthetic-v1", Actor: identity.Principal{Issuer: "https://id.invalid", Subject: "synthetic", ClientID: "console", Kind: identity.Human}, PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{2}, CreatedAt: now, RequestUntil: now.Add(5 * time.Second), WriteUntil: now.Add(30 * time.Second), RetainUntil: now.Add(time.Hour)}
	p := audit.OperationLifecyclePolicy{RootID: id, Lane: "normal", InstallationID: id, StoreID: id, PolicyID: id, BackupProfileID: id, PolicyDigest: artifact.Digest{1}, BackupProfileDigest: artifact.Digest{2}, BackingRevision: 1, MetadataSlots: 10, MaxPurgeLeases: 16, CleanupBudgetSeconds: 10, ProofWindowSeconds: 60, ValidUntil: now.Add(time.Hour)}
	p.History = &audit.OperationHistoryQualification{ID: id, Digest: artifact.Digest{4}, Layout: audit.OperationVerificationHistoryLayout, MaximumRowFootprintBytes: 128 << 10, MaximumTransitionWALBytes: 128 << 10, BackupCopies: 2, WALCopies: 2}
	b, w := p.History.SlotBacking(p.MaxPurgeLeases)
	p.BackupReservedBytes, p.WALReservedBytes = b*p.MetadataSlots, w*p.MetadataSlots
	in, e := auditapp.BindOperationLifecycle(in, p)
	if e != nil {
		t.Fatal(e)
	}
	return in
}

// Actual TLS/S3 SDK requests, Tink seal and exact readback; all API/provider
// authority and credentials are synthetic. A returned credential interval must
// bound already signed I/O, not merely a future SDK Retrieve call.
func TestInstalledOperationAuditOwnsOriginalCredentialDeadline(t *testing.T) {
	for _, mode := range []string{"success", "blocked-put", "blocked-get", "expired", "cancelled", "exists", "wrong-version", "find"} {
		t.Run(mode, func(t *testing.T) {
			in := installedAuditIntent(t)
			var puts, gets atomic.Int32
			var ciphertext []byte
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PUT" {
					puts.Add(1)
					if r.Header.Get("If-None-Match") != "*" {
						t.Error("PUT not conditional")
					}
					ciphertext, _ = io.ReadAll(r.Body)
				} else if r.Method == "GET" {
					gets.Add(1)
				} else {
					t.Error("unexpected method", r.Method)
					w.WriteHeader(400)
					return
				}
				if mode == "blocked-put" && r.Method == "PUT" || mode == "blocked-get" && r.Method == "GET" {
					<-r.Context().Done()
					return
				}
				if mode == "exists" && r.Method == "PUT" {
					w.WriteHeader(412)
					fmt.Fprint(w, "<Error><Code>PreconditionFailed</Code></Error>")
					return
				}
				if mode == "find" {
					w.WriteHeader(404)
					fmt.Fprint(w, "<Error><Code>NoSuchKey</Code></Error>")
					return
				}
				w.Header().Set("ETag", "\"synthetic-etag\"")
				w.Header().Set("x-amz-version-id", "synthetic-v1")
				if r.Method == "GET" {
					if r.URL.Query().Get("versionId") != "synthetic-v1" || r.Header.Get("If-Match") != "\"synthetic-etag\"" {
						t.Error("read not pinned", r.URL, r.Header.Get("If-Match"))
					}
					if mode == "wrong-version" {
						w.Header().Set("x-amz-version-id", "synthetic-v2")
					}
					w.Header().Set("Content-Length", strconv.Itoa(len(ciphertext)))
					w.Write(bytes.Clone(ciphertext))
				}
			}))
			defer srv.Close()
			h, e := keyset.NewHandle(aead.AES256GCMKeyTemplate())
			if e != nil {
				t.Fatal(e)
			}
			a, e := aead.New(h)
			if e != nil {
				t.Fatal(e)
			}
			keys := &operationAuditKeys{a: a}
			creds := &operationCredentialFixture{until: time.Now().Add(2 * time.Second)}
			if mode == "blocked-put" || mode == "blocked-get" {
				creds.until = time.Now().Add(100 * time.Millisecond)
			}
			if mode == "expired" {
				creds.until = time.Now().Add(-time.Second)
			}
			var input contracts.OwnerDeployment
			input.AuditStore.Endpoint = srv.URL
			input.AuditStore.Region = "us-east-1"
			input.AuditStore.Bucket = "synthetic"
			s := &installedOperationAudit{input: input, providers: creds, http: srv.Client(), seal: keys, open: keys, storeID: in.RootID, slots: make(chan struct{}, 1)}
			call, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			start := time.Now()
			if mode == "find" {
				if _, e = s.FindOperationIntent(call, in); e == nil || puts.Load() != 0 || gets.Load() != 1 || keys.wraps != 0 {
					t.Fatal("lookup issued creation or accepted missing object", e)
				}
				return
			}
			result, e := s.CreateClosedOperationIntent(call, in)
			if mode == "success" {
				if e != nil || !result.Valid(in.RootID, in.ID, in.RootID, "intent", in.CreatedAt, in.WriteUntil) {
					var named interface{ FixedStep() string }
					if errors.As(e, &named) {
						t.Fatal("exact joined result missing", named.FixedStep())
					}
					t.Fatal("exact joined result missing", e)
				}
				if puts.Load() != 1 || gets.Load() != 1 || keys.wraps != 1 || keys.unwraps != 1 {
					t.Fatal("unexpected audit effects")
				}
			} else if e == nil || result != (audit.OperationWriteCompletion{}) {
				t.Fatal("failed operation issued completion", e)
			}
			if mode == "blocked-put" || mode == "blocked-get" {
				if time.Since(start) > 350*time.Millisecond {
					t.Fatalf("credential deadline discarded; blocked %s for %s", mode, time.Since(start))
				}
			}
			if mode == "expired" || mode == "cancelled" {
				if puts.Load() != 0 || gets.Load() != 0 || keys.wraps != 0 {
					t.Fatal("unavailable credential performed audit work")
				}
			}
			if mode == "success" && creds.reads.Load() != 1 {
				t.Fatalf("one audit operation repeated current credential proof %d times", creds.reads.Load())
			}
		})
	}
}
