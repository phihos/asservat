package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	auditapp "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Real C08 coordinator, S3 SDK signing, and independently limited native
// observer/probe clients. SQL/audit key authority, ciphertext and API responses
// are synthetic. This measures proof multiplication and complete intent/outcome
// request time; it does not qualify provider latency or the installed preview.
// No QPS, burst, retry or freshness override is used. Three-second cases model
// an already observed original source bound, not a newly shortened product TTL.
func exerciseProviderCredentialAuditBudget(t *testing.T, reader *InstalledOwnerIdentityReader, x *ownerIdentityObjectFixture, mounted []byte) {
	for _, scenario := range []struct {
		scoped    bool
		remaining time.Duration
		finish    bool
	}{{false, 5 * time.Second, false}, {false, 3 * time.Second, false}, {true, 3 * time.Second, false}, {false, 5 * time.Second, true}, {true, 5 * time.Second, true}} {
		scoped := scenario.scoped
		t.Run(fmt.Sprintf("operation-scoped-%t-original-tail-%s-outcome-%t", scoped, scenario.remaining, scenario.finish), func(t *testing.T) {
			var api, proofs, puts, gets atomic.Int32
			original := x.extra
			x.extra = func(w http.ResponseWriter, r *http.Request) bool { api.Add(1); return original(w, r) }
			defer func() { x.extra = original }()
			payload := []byte("synthetic audit ciphertext")
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PUT" {
					puts.Add(1)
					_, _ = io.Copy(io.Discard, r.Body)
				} else if r.Method == "GET" {
					gets.Add(1)
				} else {
					t.Error("unexpected storage operation")
					w.WriteHeader(400)
					return
				}
				w.Header().Set("ETag", "\"synthetic\"")
				w.Header().Set("x-amz-version-id", "v1")
				if r.Method == "GET" {
					w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
					w.Write(payload)
				}
			}))
			defer server.Close()
			start := time.Now().UTC().Truncate(time.Microsecond)
			call, cancel := context.WithDeadline(context.Background(), start.Add(scenario.remaining))
			defer cancel()
			write := func(ctx context.Context, in audit.OperationIntent, phase string) (audit.Receipt, error) {
				live := ctx
				var selected aws.CredentialsProvider = aws.CredentialsProviderFunc(func(c context.Context) (aws.Credentials, error) {
					proofs.Add(1)
					material, _, e := reader.ReadProviderAuditCredential(c, x.manifest, x.mounted, mounted)
					return aws.Credentials{AccessKeyID: material.AccessKeyID, SecretAccessKey: material.SecretAccessKey}, e
				})
				if scoped {
					proofs.Add(1)
					c, until, e := reader.ReadProviderAuditCredential(live, x.manifest, x.mounted, mounted)
					if e != nil {
						return audit.Receipt{}, e
					}
					var narrow context.CancelFunc
					live, narrow = context.WithDeadline(live, until)
					defer narrow()
					selected = credentials.NewStaticCredentialsProvider(c.AccessKeyID, c.SecretAccessKey, c.SessionToken)
				}
				store := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), UsePathStyle: true, Credentials: selected, HTTPClient: server.Client(), RetryMaxAttempts: 1})
				key := audit.OperationAuditKey(in.RootID, in.ID, phase)
				o, e := store.PutObject(live, &s3.PutObjectInput{Bucket: aws.String("synthetic"), Key: &key, Body: bytes.NewReader(payload), IfNoneMatch: aws.String("*")})
				if e != nil {
					return audit.Receipt{}, e
				}
				got, e := store.GetObject(live, &s3.GetObjectInput{Bucket: aws.String("synthetic"), Key: &key, VersionId: o.VersionId, IfMatch: o.ETag})
				if e != nil {
					return audit.Receipt{}, e
				}
				b, e := io.ReadAll(io.LimitReader(got.Body, int64(len(payload)+1)))
				closeErr := got.Body.Close()
				if e != nil || closeErr != nil || !bytes.Equal(b, payload) || aws.ToString(got.VersionId) != aws.ToString(o.VersionId) || aws.ToString(got.ETag) != aws.ToString(o.ETag) {
					return audit.Receipt{}, auditapp.ErrUnavailable
				}
				return audit.Receipt{Key: key, Version: aws.ToString(o.VersionId), ETag: aws.ToString(o.ETag), Bytes: int64(len(payload)), SHA256: artifact.Digest(sha256.Sum256(payload))}, nil
			}
			f := &providerBudgetAudit{write: write}
			service := auditapp.OperationAuditor{Journal: f, Acknowledgements: f, Objects: f, Now: time.Now}
			id := "10000000-0000-4000-8000-000000000031"
			in := audit.OperationIntent{ID: id, RootID: id, TraceID: id, Name: "preview_capture", InputFormat: "context-input/v1", MACVersion: "v1", AccountVersion: "synthetic-v1", Actor: identity.Principal{Issuer: "https://id.invalid", Subject: "synthetic", ClientID: "console", Kind: identity.Human}, PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{2}, CreatedAt: start, RequestUntil: start.Add(5 * time.Second), WriteUntil: start.Add(30 * time.Second), RetainUntil: start.Add(time.Hour)}
			e := service.Begin(call, in)
			if e == nil && scenario.finish {
				e = service.Finish(call, audit.OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "none", ClientReceipt: "unknown", OutputDigest: artifact.Digest{3}, OutputBytes: 1, MetadataUntil: in.RequestUntil, RecordedAt: time.Now().UTC().Truncate(time.Microsecond)})
			}
			t.Logf("scoped=%t outcome=%t elapsed=%s native_api_calls=%d credential_proofs=%d puts=%d gets=%d error=%v", scoped, scenario.finish, time.Since(start), api.Load(), proofs.Load(), puts.Load(), gets.Load(), e)
			phases := int32(1)
			if scenario.finish {
				phases = 2
			}
			if scoped {
				if e != nil || proofs.Load() != phases || api.Load() != 51*phases || puts.Load() != phases || gets.Load() != phases {
					t.Fatal("original bounded audit operation did not complete", e)
				}
			} else if scenario.remaining == 5*time.Second && !scenario.finish {
				if e != nil || proofs.Load() != 2 || api.Load() != 102 {
					t.Fatal("fresh five-second single-phase baseline changed", e)
				}
			} else if e == nil {
				t.Fatal("per-SDK proof multiplication unexpectedly fit the original request/source bound")
			}
		})
	}
}

// Minimized in-memory journal/acknowledgements supply no production authority.
// The real coordinator must still distinguish fresh create from lookup and
// retain the intent acknowledgement before freezing its outcome.
type providerBudgetAudit struct {
	write   func(context.Context, audit.OperationIntent, string) (audit.Receipt, error)
	receipt *audit.Receipt
}

func (s *providerBudgetAudit) ReserveOperation(_ context.Context, in audit.OperationIntent) (audit.OperationSnapshot, error) {
	return audit.OperationSnapshot{Intent: in}, nil
}
func (s *providerBudgetAudit) ClaimOperationWrite(context.Context, audit.OperationIntent, string) (bool, error) {
	return true, nil
}
func (s *providerBudgetAudit) FreezeOperationOutcome(_ context.Context, out audit.OperationOutcome) (audit.OperationSnapshot, error) {
	return audit.OperationSnapshot{Intent: out.Intent, Outcome: &out, IntentReceipt: s.receipt}, nil
}
func (s *providerBudgetAudit) AcknowledgeOperation(_ context.Context, _ audit.OperationIntent, phase string, r audit.Receipt) error {
	if phase == "intent" {
		s.receipt = &r
	}
	return nil
}
func (s *providerBudgetAudit) CreateOperationIntent(ctx context.Context, in audit.OperationIntent) (audit.Receipt, error) {
	return s.write(ctx, in, "intent")
}
func (s *providerBudgetAudit) CreateOperationOutcome(ctx context.Context, out audit.OperationOutcome) (audit.Receipt, error) {
	return s.write(ctx, out.Intent, "outcome")
}
func (s *providerBudgetAudit) FindOperationIntent(context.Context, audit.OperationIntent) (audit.Receipt, error) {
	return audit.Receipt{}, auditapp.ErrUnavailable
}
func (s *providerBudgetAudit) FindOperationOutcome(context.Context, audit.OperationOutcome) (audit.Receipt, error) {
	return audit.Receipt{}, auditapp.ErrUnavailable
}
