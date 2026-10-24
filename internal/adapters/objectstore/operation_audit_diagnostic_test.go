package objectstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/audit"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestOperationAuditFindNamesClosedReadStatusWithoutRetry(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden, http.StatusServiceUnavailable} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var calls atomic.Int32
			store := auditObjectStore(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodGet {
					t.Error("reconciliation attempted a write", r.Method)
				}
				w.WriteHeader(status)
				_, _ = w.Write([]byte("private-provider-detail"))
			}))
			reader := OperationAuditObjects{Store: store, Seal: windowTestKeys{}, Open: windowTestKeys{}}
			now := time.Now().UTC().Truncate(time.Microsecond)
			in := value.OperationIntent{ID: operationTestID, RootID: operationTestID, TraceID: operationTestID,
				Name: "get_capture", InputFormat: "context-input/v1", MACVersion: "input-v1", AccountVersion: "account-v1",
				Actor:           identity.Principal{Issuer: "https://identity.invalid", Subject: "synthetic", ClientID: "console", Kind: identity.Human},
				PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{2}, CreatedAt: now,
				RequestUntil: now.Add(5 * time.Second), WriteUntil: now.Add(30 * time.Second), RetainUntil: now.Add(time.Hour)}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := reader.FindOperationIntent(ctx, in)
			var step interface{ FixedStep() string }
			if !errors.Is(err, app.ErrUnavailable) || !errors.As(err, &step) || step.FixedStep() != "read/http-"+strconv.Itoa(status) ||
				strings.Contains(err.Error(), "private") || calls.Load() != 1 {
				t.Fatal("reconciliation lost closed HTTP status or retried", err, step, calls.Load())
			}
			// The shared reader keeps its original storage classification;
			// only a finite private HTTP status is added.
			_, _, err = store.readControlAudit(ctx, "synthetic-read", 16)
			if !errors.Is(err, ErrStorage) || calls.Load() != 2 {
				t.Fatal("shared read changed storage classification or retry count", err, calls.Load())
			}
		})
	}
}

type privateReadCredentialError struct{}

func (privateReadCredentialError) Error() string     { return "private-provider-detail" }
func (privateReadCredentialError) FixedStep() string { return "private-provider-detail" }
func (privateReadCredentialError) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, privateReadCredentialError{}
}

func TestOperationAuditFindDoesNotCopyPrivateCredentialLabel(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	store, err := New(server.URL, "test", "synthetic", privateReadCredentialError{}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	reader := OperationAuditObjects{Store: store, Seal: windowTestKeys{}, Open: windowTestKeys{}}
	now := time.Now().UTC().Truncate(time.Microsecond)
	in := value.OperationIntent{ID: operationTestID, RootID: operationTestID, TraceID: operationTestID,
		Name: "get_capture", InputFormat: "context-input/v1", MACVersion: "input-v1", AccountVersion: "account-v1",
		Actor:           identity.Principal{Issuer: "https://identity.invalid", Subject: "synthetic", ClientID: "console", Kind: identity.Human},
		PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{2}, CreatedAt: now,
		RequestUntil: now.Add(5 * time.Second), WriteUntil: now.Add(30 * time.Second), RetainUntil: now.Add(time.Hour)}
	_, err = reader.FindOperationIntent(context.Background(), in)
	var step interface{ FixedStep() string }
	if !errors.Is(err, app.ErrUnavailable) || !errors.As(err, &step) || step.FixedStep() != "read" ||
		strings.Contains(err.Error(), "private") || calls.Load() != 0 {
		t.Fatal("private credential diagnostic escaped or reached HTTP", err, step, calls.Load())
	}
}
