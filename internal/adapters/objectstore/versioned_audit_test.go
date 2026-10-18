package objectstore

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"asservat.local/asservat/internal/domain/artifact"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// Real TLS exercises the existing SDK and concrete store; the synthetic server
// does not establish backend IAM, persistent versioning or installation safety.
func TestVersionedAuditRejectsUnpinnedReceipts(t *testing.T) {
	for _, operation := range []string{"put", "read", "pin"} {
		for _, version := range []string{"", "null", strings.Repeat("v", 1025), "original-version"} {
			label := version
			if len(label) > 32 {
				label = "oversized"
			}
			t.Run(operation+"/"+label, func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.Method == http.MethodPut && r.Header.Get("If-None-Match") != "*" {
						t.Error("missing conditional create")
					}
					w.Header().Set("ETag", `"original"`)
					if version != "" {
						w.Header().Set("X-Amz-Version-Id", version)
					}
					if r.Method == http.MethodGet {
						w.Header().Set("Content-Length", "4")
						_, _ = w.Write([]byte("data"))
					}
				}))
				defer server.Close()
				store, err := NewVersionedAudit(server.URL, "test", "audit", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), server.Client())
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				valid := version == "original-version"
				switch operation {
				case "put":
					object, err := store.PutSmall(context.Background(), "audit-record", []byte("data"))
					if valid {
						if err != nil || object.VersionID != version {
							t.Fatal("exact version receipt rejected", err)
						}
					} else if !errors.Is(err, ErrStorage) || object != (Object{}) {
						t.Fatal("unversioned write acknowledged", err)
					}
				case "read":
					object, body, err := store.readControlAudit(context.Background(), "audit-record", 16)
					if valid {
						if err != nil || object.VersionID != version || string(body) != "data" {
							t.Fatal("exact version read rejected", err)
						}
					} else if !errors.Is(err, artifact.ErrIntegrity) || object != (Object{}) || body != nil {
						t.Fatal("unversioned audit read accepted", err)
					}
				case "pin":
					source, err := store.Pin(Object{Key: "audit-record", VersionID: version, ETag: `"original"`, Bytes: 4})
					if valid {
						if err != nil || source == nil {
							t.Fatal("exact version pin rejected", err)
						}
					} else if !errors.Is(err, artifact.ErrInvalid) || source != nil {
						t.Fatal("unversioned pin accepted", err)
					}
				}
				want := int32(1)
				if operation == "pin" {
					want = 0
				}
				if calls.Load() != want {
					t.Fatalf("request count %d, want %d", calls.Load(), want)
				}
			})
		}
	}
}

func TestVersionedAuditPinnedReadSurvivesLatestReplacement(t *testing.T) {
	for _, responseVersion := range []string{"original-version", "other-version", "null", ""} {
		t.Run(responseVersion, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Query().Get("versionId") != "original-version" || r.Header.Get("If-Match") != `"original"` || r.Header.Get("Range") != "bytes=0-3" {
					t.Error("original receipt read constraints lost")
				}
				w.Header().Set("ETag", `"original"`)
				w.Header().Set("X-Amz-Version-Id", responseVersion)
				w.Header().Set("Content-Range", "bytes 0-3/4")
				w.Header().Set("Content-Length", "4")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write([]byte("data"))
			}))
			defer server.Close()
			store, err := NewVersionedAudit(server.URL, "test", "audit", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			source, err := store.Pin(Object{Key: "audit-record", VersionID: "original-version", ETag: `"original"`, Bytes: 4})
			if err != nil {
				t.Fatal(err)
			}
			got, err := source.ReadRange(context.Background(), 0, 4)
			if responseVersion == "original-version" {
				if err != nil || string(got) != "data" {
					t.Fatal("original version rejected", err)
				}
			} else if !errors.Is(err, artifact.ErrIntegrity) || len(got) != 0 {
				t.Fatal("changed version disclosed", err)
			}
		})
	}
}

func TestLegacyStoreRetainsVersionOptionalContract(t *testing.T) {
	for _, version := range []string{"", "null"} {
		t.Run(fmt.Sprintf("version-%q", version), func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"legacy"`)
				w.Header().Set("X-Amz-Version-Id", version)
			}))
			defer server.Close()
			store, err := New(server.URL, "test", "audit", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			object, err := store.PutSmall(context.Background(), "audit-record", []byte("data"))
			if err != nil || object.VersionID != version {
				t.Fatal("legacy backend behavior changed", err)
			}
			if _, err = store.Pin(object); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A refused or unacceptable write names its closed cause for diagnostics and
// still matches ErrStorage.
func TestPutSmallNamesTheStorageCause(t *testing.T) {
	for _, c := range []struct {
		name    string
		status  int
		version string
		want    string
	}{{"refused", http.StatusForbidden, "v", "http-403"}, {"unversioned", http.StatusOK, "", "unversioned"}} {
		t.Run(c.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"original"`)
				if c.version != "" {
					w.Header().Set("X-Amz-Version-Id", c.version)
				}
				w.WriteHeader(c.status)
			}))
			defer server.Close()
			store, err := NewVersionedAudit(server.URL, "test", "audit", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), server.Client())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			_, err = store.PutSmall(context.Background(), "audit-record", []byte("data"))
			var step interface{ FixedStep() string }
			if !errors.Is(err, ErrStorage) || !errors.As(err, &step) || step.FixedStep() != c.want {
				t.Fatal(err)
			}
		})
	}
}

type namedCredentialFailure struct{}

func (namedCredentialFailure) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, namedStepError{}
}

type namedStepError struct{}

func (namedStepError) Error() string     { return "credentials unavailable" }
func (namedStepError) FixedStep() string { return "credentials-verify" }

// A credential provider that names its failure is named through the SDK's
// error chain; the request never reaches the server.
func TestPutSmallNamesACredentialFailure(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer server.Close()
	store, err := NewVersionedAudit(server.URL, "test", "audit", namedCredentialFailure{}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, err = store.PutSmall(context.Background(), "audit-record", []byte("data"))
	var step interface{ FixedStep() string }
	if !errors.Is(err, ErrStorage) || !errors.As(err, &step) || step.FixedStep() != "credentials-verify" || calls.Load() != 0 {
		t.Fatal(err, calls.Load())
	}
}
