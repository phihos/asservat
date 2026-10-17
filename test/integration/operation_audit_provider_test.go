package integration

import (
	"asservat.local/asservat/internal/adapters/kms"
	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/identity"
	"context"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Actual OpenBao+S3 requests and elapsed time for six bounded audit pairs. This
// characterizes this fixture only, not production throughput/default ceilings.
func TestOperationAuditWithRealProviders(t *testing.T) {
	path := os.Getenv("ASSERVAT_CONTEXT_FIXTURES")
	if path == "" {
		t.Skip("run owned context-integration provider fixture")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("fixture unavailable")
	}
	var f fixture
	if json.Unmarshal(b, &f) != nil || f.KMS == "" || f.S3 == "" {
		t.Fatal("provider fixture unavailable")
	}
	clear(b)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	suffix := strings.ReplaceAll(custodyID(), "-", "")
	mount := "audit-" + suffix
	request(t, f.KMS, "synthetic-root", "sys/mounts/"+mount, map[string]any{"type": "transit"}, 204)
	request(t, f.KMS, "synthetic-root", mount+"/keys/operation", map[string]any{"type": "aes256-gcm96"}, 200)
	tokens := map[string]string{}
	for _, purpose := range []string{"encrypt", "decrypt"} {
		name := "audit-" + purpose + "-" + suffix
		policy := `path "` + mount + `/` + purpose + `/operation" { capabilities = ["update"] }`
		request(t, f.KMS, "synthetic-root", "sys/policies/acl/"+name, map[string]any{"policy": policy}, 204)
		v := request(t, f.KMS, "synthetic-root", "auth/token/create", map[string]any{"policies": []string{name}, "no_default_policy": true, "ttl": "5m"}, 200)
		tokens[purpose] = v["auth"].(map[string]any)["client_token"].(string)
	}
	var wraps, unwraps, puts, gets atomic.Int64
	bridge := func(endpoint string, observe func(*http.Request)) *httptest.Server {
		u, e := url.Parse(endpoint)
		if e != nil {
			t.Fatal(e)
		}
		proxy := httputil.NewSingleHostReverseProxy(u)
		proxy.Transport = &http.Transport{Proxy: nil}
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { observe(r); proxy.ServeHTTP(w, r) }))
		t.Cleanup(s.Close)
		return s
	}
	keyTLS := bridge(f.KMS, func(r *http.Request) {
		if strings.Contains(r.URL.Path, "/encrypt/") {
			wraps.Add(1)
		}
		if strings.Contains(r.URL.Path, "/decrypt/") {
			unwraps.Add(1)
		}
	})
	storeTLS := bridge(f.S3, func(r *http.Request) {
		if !strings.Contains(r.URL.Path, "operation-audit/v1/") {
			return
		}
		if r.Method == http.MethodPut {
			puts.Add(1)
		}
		if r.Method == http.MethodGet {
			gets.Add(1)
		}
	})
	seal, e := kms.NewSealer(keyTLS.URL, tokens["encrypt"], mount, "operation", keyTLS.Client())
	if e != nil {
		t.Fatal(e)
	}
	defer seal.Close()
	open, e := kms.NewOpener(keyTLS.URL, tokens["decrypt"], mount, "operation", keyTLS.Client())
	if e != nil {
		t.Fatal(e)
	}
	defer open.Close()
	cred := credentials.NewStaticCredentialsProvider("synthetic-only", "synthetic-only-secret", "")
	bucket := "audit-" + suffix
	admin := s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(storeTLS.URL), UsePathStyle: true, Credentials: cred, HTTPClient: storeTLS.Client(), RetryMaxAttempts: 1})
	if _, e = admin.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket}); e != nil {
		t.Fatal("audit bucket unavailable")
	}
	store, e := objectstore.New(storeTLS.URL, "us-east-1", bucket, cred, storeTLS.Client())
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	objects := &objectstore.OperationAuditObjects{Store: store, Seal: seal, Open: open}
	durations := make([]time.Duration, 0, 6)
	var last audit.OperationIntent
	for n := 0; n < 6; n++ {
		now := time.Now().UTC().Truncate(time.Microsecond)
		id := custodyID()
		in := audit.OperationIntent{ID: id, TraceID: id, RootID: "00000000-0000-4000-8000-000000000002", Name: "get_capture", InputFormat: "context-input/v1", MACVersion: "audit-v1", AccountVersion: "accounts-v1", Actor: identity.Principal{Issuer: "https://identity.invalid", Subject: "synthetic", ClientID: "console", Kind: identity.Human}, PrincipalDigest: artifact.Digest{1}, InputDigest: artifact.Digest{2}, CreatedAt: now, RequestUntil: now.Add(5 * time.Second), WriteUntil: now.Add(30 * time.Second), RetainUntil: now.Add(time.Hour)}
		last = in
		start := time.Now()
		if _, e = objects.CreateOperationIntent(ctx, in); e != nil {
			t.Fatal("actual intent", e)
		}
		out := audit.OperationOutcome{Intent: in, Status: "success", Reason: "prepared", Effect: "none", ClientReceipt: "unknown", OutputDigest: artifact.Digest{3}, OutputBytes: 100, MetadataUntil: in.RequestUntil, RecordedAt: time.Now().UTC().Truncate(time.Microsecond)}
		if _, e = objects.CreateOperationOutcome(ctx, out); e != nil {
			t.Fatal("actual outcome", e)
		}
		durations = append(durations, time.Since(start))
	}
	if wraps.Load() != 12 || unwraps.Load() != 12 || puts.Load() != 12 || gets.Load() != 12 {
		t.Fatal("unexpected provider call counts", wraps.Load(), unwraps.Load(), puts.Load(), gets.Load())
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	t.Logf("actual OpenBao/S3 six operation intent+outcome pairs: wraps=%d unwraps=%d PUT=%d GET=%d p50=%s max=%s; distinct from artifact three wraps; synthetic small fixture, no production load qualification", wraps.Load(), unwraps.Load(), puts.Load(), gets.Load(), durations[len(durations)/2], durations[len(durations)-1])
	if _, e = objects.FindOperationIntent(ctx, last); e != nil {
		t.Fatal(e)
	}
	if wraps.Load() != 12 || puts.Load() != 12 || unwraps.Load() != 13 || gets.Load() != 13 {
		t.Fatal("lookup retry resealed or created")
	}
}
