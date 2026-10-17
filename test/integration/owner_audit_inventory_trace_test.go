package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// The owned server records only fixed API names and actual status codes. The
// product client retains the real *http.Transport required by objectstore.New;
// no request, response, credential, path, body or identity is copied into logs.
type nativeOwnerAuditTrace struct {
	mu    sync.Mutex
	calls []nativeOwnerAuditCall
}
type nativeOwnerAuditCall struct {
	Operation string
	Status    int
}

func nativeOwnerAuditBridge(t *testing.T, endpoint string) (*httptest.Server, *nativeOwnerAuditTrace) {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal("invalid synthetic upstream")
	}
	trace := &nativeOwnerAuditTrace{}
	proxy := httputil.NewSingleHostReverseProxy(u)
	transport := &http.Transport{Proxy: nil}
	proxy.Transport = transport
	proxy.ModifyResponse = func(r *http.Response) error { trace.record(r.Request, r.StatusCode); return nil }
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, _ error) {
		trace.record(r, http.StatusBadGateway)
		http.Error(w, "synthetic upstream unavailable", http.StatusBadGateway)
	}
	s := httptest.NewTLSServer(proxy)
	t.Cleanup(func() { s.Close(); transport.CloseIdleConnections() })
	return s, trace
}
func (t *nativeOwnerAuditTrace) record(r *http.Request, status int) {
	name := "unexpected"
	q := r.URL.Query()
	if r.Method == http.MethodGet {
		switch {
		case q.Has("versions"):
			name = "ListObjectVersions"
		case q.Has("uploads"):
			name = "ListMultipartUploads"
		case q.Get("list-type") == "2":
			name = "ListObjectsV2"
		}
	}
	t.mu.Lock()
	t.calls = append(t.calls, nativeOwnerAuditCall{Operation: name, Status: status})
	t.mu.Unlock()
}
func (t *nativeOwnerAuditTrace) observations() []nativeOwnerAuditCall {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]nativeOwnerAuditCall(nil), t.calls...)
}

// No external service opt-in: catch constructor incompatibility before another
// native run. Exercise the actual adapter's partial read through real TLS, then
// the same reader with a new independently bounded operation.
func TestOwnerAuditInventoryTraceUsesActualConstructor(t *testing.T) {
	const id = "a9a9b231-0d4c-4d72-89aa-1a4516be9e9c"
	c := fleet.OwnerConfiguration{Pool: fleet.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "hub", NamespaceUID: id, Service: "owner", ServiceUID: id, Deployment: "owner", DeploymentUID: id, ServiceAccount: "owner", AccountUID: id, Port: 8443}, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{{3}}}
	key := audit.OwnerConfigurationAuditKey(c)
	var permitted atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		w.Header().Set("Content-Type", "application/xml")
		if r.Method != http.MethodGet || q.Get("prefix") != key {
			t.Error("unexpected product request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch {
		case q.Has("versions"):
			fmt.Fprintf(w, "<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>%s</Key><VersionId>null</VersionId><IsLatest>true</IsLatest><Size>0</Size><ETag>original</ETag></Version></ListVersionsResult>", key)
		case q.Has("uploads"):
			if !permitted.Load() {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, "<Error><Code>AccessDenied</Code></Error>")
				return
			}
			fmt.Fprint(w, "<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>")
		case q.Get("list-type") == "2":
			fmt.Fprintf(w, "<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>%s</Key><Size>0</Size><ETag>original</ETag></Contents></ListBucketResult>", key)
		default:
			t.Error("unexpected product API")
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer upstream.Close()
	bridge, trace := nativeOwnerAuditBridge(t, upstream.URL)
	store, err := objectstore.New(bridge.URL, "us-east-1", "synthetic", credentials.NewStaticCredentialsProvider("synthetic", "synthetic", ""), bridge.Client())
	if err != nil {
		t.Fatal("actual Store constructor rejected native fixture transport", err)
	}
	defer store.Close()
	reader, err := objectstore.NewOwnerConfigurationAuditInventory(store, id, c)
	if err != nil {
		t.Fatal(err)
	}
	page, err := reader.Read(context.Background())
	if !errors.Is(err, objectstore.ErrStorage) || !page.VersionsComplete || page.UploadsComplete || page.CurrentComplete || len(page.Versions) != 1 || page.Versions[0].VersionID != "null" {
		t.Fatal("actual partial inventory changed", err, page)
	}
	want := []nativeOwnerAuditCall{{"ListObjectVersions", 200}, {"ListMultipartUploads", 403}}
	if !reflect.DeepEqual(trace.observations(), want) {
		t.Fatal("original native failure trace changed", trace.observations())
	}
	permitted.Store(true)
	page, err = reader.Read(context.Background())
	if err != nil || !page.VersionsComplete || !page.UploadsComplete || !page.CurrentComplete || page.CurrentUnmatched || page.Current == nil || len(page.Versions) != 1 {
		t.Fatal("actual successful inventory changed", err, page)
	}
	want = append(want, nativeOwnerAuditCall{"ListObjectVersions", 200}, nativeOwnerAuditCall{"ListMultipartUploads", 200}, nativeOwnerAuditCall{"ListObjectsV2", 200})
	got := trace.observations()
	if !reflect.DeepEqual(got, want) {
		t.Fatal("successful native trace changed", got)
	}
	got[0].Status = 999
	if trace.observations()[0].Status != 200 {
		t.Fatal("trace caller mutated retained observations")
	}
}
