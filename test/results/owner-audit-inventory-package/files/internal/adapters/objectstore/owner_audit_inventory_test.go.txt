package objectstore

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

func ownerInventoryConfiguration() fleet.OwnerConfiguration {
	const id = "10000000-0000-4000-8000-000000000001"
	return fleet.OwnerConfiguration{
		Pool:     fleet.OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "original", NamespaceUID: id, Service: "owner", ServiceUID: id, Deployment: "owner", DeploymentUID: id, ServiceAccount: "owner", AccountUID: id, Port: 9444},
		Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, IssuerRoots: [][]byte{{3}},
	}
}

func ownerInventoryVersion(key, id, size string, latest bool) string {
	return fmt.Sprintf("<Version><Key>%s</Key><VersionId>%s</VersionId><Size>%s</Size><IsLatest>%t</IsLatest><ETag>&quot;original&quot;</ETag></Version>", key, id, size, latest)
}
func ownerInventoryMarker(key, id string) string {
	return fmt.Sprintf("<DeleteMarker><Key>%s</Key><VersionId>%s</VersionId><IsLatest>false</IsLatest></DeleteMarker>", key, id)
}
func ownerInventoryUpload(key, id string) string {
	return fmt.Sprintf("<Upload><Key>%s</Key><UploadId>%s</UploadId></Upload>", key, id)
}
func ownerInventoryCurrent(key string) string {
	return fmt.Sprintf("<Contents><Key>%s</Key><Size>4</Size><ETag>&quot;original&quot;</ETag></Contents>", key)
}
func ownerInventoryBodies(c fleet.OwnerConfiguration) map[string]string {
	key := audit.OwnerConfigurationAuditKey(c)
	return map[string]string{
		"versions": "<ListVersionsResult><IsTruncated>false</IsTruncated>" + ownerInventoryVersion(key, "original", "4", true) + "</ListVersionsResult>",
		"uploads":  "<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>",
		"current":  "<ListBucketResult><IsTruncated>false</IsTruncated>" + ownerInventoryCurrent(key) + "</ListBucketResult>",
	}
}

func ownerInventoryFixture(t *testing.T, c fleet.OwnerConfiguration, response func(string, http.ResponseWriter, *http.Request)) (*OwnerConfigurationAuditInventory, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/fixture" || r.URL.Query().Get("prefix") != audit.OwnerConfigurationAuditKey(c) {
			t.Error("non-LIST or foreign original scope", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		kind, limit := "current", "max-keys"
		if r.URL.Query().Has("versions") {
			kind = "versions"
		} else if r.URL.Query().Has("uploads") {
			kind, limit = "uploads", "max-uploads"
		} else if r.URL.Query().Get("list-type") != "2" {
			t.Error("unexpected GET, not inventory")
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Query().Get(limit) != "128" {
			t.Error("inventory page bound changed")
		}
		w.Header().Set("Content-Type", "application/xml")
		response(kind, w, r)
	}))
	t.Cleanup(server.Close)
	store, err := New(server.URL, "test", "fixture", credentials.NewStaticCredentialsProvider("synthetic-inspection", "synthetic-only", ""), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	reader, err := NewOwnerConfigurationAuditInventory(store, "20000000-0000-4000-8000-000000000002", c)
	if err != nil {
		t.Fatal(err)
	}
	return reader, &calls
}

func TestOwnerAuditInventoryPreservesPhysicalKindsAndHistoricalScope(t *testing.T) {
	configuration := ownerInventoryConfiguration()
	configuration.Suspended = true // Historical identity remains inspectable.
	old := fleet.OwnerConfigurationObservation{Configuration: configuration, ObservedAt: time.Now().Add(-time.Hour), FreshUntil: time.Now().Add(-time.Hour + 5*time.Second)}
	if old.Valid(time.Now()) {
		t.Fatal("fixture accidentally supplies current source authority")
	}
	key := audit.OwnerConfigurationAuditKey(configuration)
	body := ownerInventoryBodies(configuration)
	body["versions"] = strings.Replace(body["versions"], "</ListVersionsResult>", ownerInventoryVersion(key, "null", "0", false)+ownerInventoryMarker(key, "marker")+ownerInventoryVersion(key+"0", "generation-10", "99", true)+ownerInventoryMarker(key+"1", "generation-11-marker")+"</ListVersionsResult>", 1)
	body["uploads"] = strings.Replace(body["uploads"], "</ListMultipartUploadsResult>", ownerInventoryUpload(key, "upload")+ownerInventoryUpload(key+"0", "foreign-upload")+"</ListMultipartUploadsResult>", 1)
	body["current"] = strings.Replace(body["current"], "</ListBucketResult>", ownerInventoryCurrent(key+"1")+"</ListBucketResult>", 1)
	reader, calls := ownerInventoryFixture(t, old.Configuration, func(kind string, w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body[kind]) })
	// Caller mutation, or deletion of its source copy, cannot replace the pin.
	old.Configuration.IssuerRoots[0][0] = 99
	old.Configuration.Revision.Generation = 11
	old.Configuration = fleet.OwnerConfiguration{}
	ctx, end := context.WithTimeout(context.Background(), time.Second)
	defer end()
	until, _ := ctx.Deadline()
	got, err := reader.Read(ctx)
	if err != nil || got.Key != key || got.StoreID != "20000000-0000-4000-8000-000000000002" || got.Configuration.Revision.Generation != 1 || got.Configuration.IssuerRoots[0][0] != 3 || got.ReadUntil != until || got.ReadStartedAt.After(time.Now()) {
		t.Fatal("original historical pin/caller bound not retained", err)
	}
	if len(got.Versions) != 3 || got.Versions[1].VersionID != "null" || got.Versions[1].CiphertextBytes != 0 || got.Versions[2].Kind != OwnerAuditDeleteMarker || len(got.Uploads) != 1 || got.Uploads[0].UploadID != "upload" || got.Current == nil || got.Current.Bytes != 4 || got.CurrentUnmatched {
		t.Fatal("physical entries conflated or foreign generation adopted", got)
	}
	if !got.VersionsComplete || !got.UploadsComplete || !got.CurrentComplete || calls.Load() != 3 {
		t.Fatal("bounded listings incomplete or repeated", calls.Load())
	}
	got.Configuration.IssuerRoots[0][0] = 88
	if reader.configuration.IssuerRoots[0][0] != 3 {
		t.Fatal("returned page aliases immutable original pin")
	}
}

func TestOwnerAuditInventoryKeepsTruncatedNeighborPagesIncomplete(t *testing.T) {
	for _, kind := range []string{"versions", "uploads", "current"} {
		t.Run(kind, func(t *testing.T) {
			c := ownerInventoryConfiguration()
			key := audit.OwnerConfigurationAuditKey(c)
			body := ownerInventoryBodies(c)
			if kind == "uploads" {
				body[kind] = strings.Replace(body[kind], "</ListMultipartUploadsResult>", ownerInventoryUpload(key, "neighbor-upload")+"</ListMultipartUploadsResult>", 1)
			}
			body[kind] = strings.ReplaceAll(body[kind], key, key+"0")
			body[kind] = strings.Replace(body[kind], "<IsTruncated>false</IsTruncated>", "<IsTruncated>true</IsTruncated>", 1)
			reader, calls := ownerInventoryFixture(t, c, func(k string, w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body[k]) })
			got, err := reader.Read(context.Background())
			if err != nil || calls.Load() != 3 {
				t.Fatal("truncated page lost as diagnostic", err)
			}
			if kind == "versions" && (got.VersionsComplete || len(got.Versions) != 0) || kind == "uploads" && (got.UploadsComplete || len(got.Uploads) != 0) || kind == "current" && (got.CurrentComplete || got.Current != nil) {
				t.Fatal("neighbor-only truncated page claimed complete exact-key inventory")
			}
		})
	}
}

func TestOwnerAuditInventoryDoesNotInventVersionFromCurrentKey(t *testing.T) {
	c := ownerInventoryConfiguration()
	body := ownerInventoryBodies(c)
	body["versions"] = "<ListVersionsResult><IsTruncated>false</IsTruncated></ListVersionsResult>"
	reader, _ := ownerInventoryFixture(t, c, func(k string, w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body[k]) })
	got, err := reader.Read(context.Background())
	if err != nil || !got.CurrentUnmatched || len(got.Versions) != 0 || got.Current == nil {
		t.Fatal("current key became invented null version or absence", err)
	}
}

func TestOwnerAuditInventoryRejectsMalformedAndForeignProviderRows(t *testing.T) {
	for _, mode := range []string{"missing-truncation", "foreign-key", "missing-version", "control-version", "negative-size", "duplicate-version", "marker-alias", "two-latest", "duplicate-upload", "duplicate-current", "over-page", "denied"} {
		t.Run(mode, func(t *testing.T) {
			c := ownerInventoryConfiguration()
			key := audit.OwnerConfigurationAuditKey(c)
			body := ownerInventoryBodies(c)
			switch mode {
			case "missing-truncation":
				body["versions"] = strings.Replace(body["versions"], "<IsTruncated>false</IsTruncated>", "", 1)
			case "foreign-key":
				body["versions"] = strings.ReplaceAll(body["versions"], key, "hub-owner-configuration/v1/another-root")
			case "missing-version":
				body["versions"] = strings.Replace(body["versions"], "<VersionId>original</VersionId>", "", 1)
			case "control-version":
				body["versions"] = strings.Replace(body["versions"], "<VersionId>original</VersionId>", "<VersionId>original&#10;</VersionId>", 1)
			case "negative-size":
				body["versions"] = strings.Replace(body["versions"], "<Size>4</Size>", "<Size>-1</Size>", 1)
			case "duplicate-version":
				body["versions"] = strings.Replace(body["versions"], "</ListVersionsResult>", ownerInventoryVersion(key, "original", "4", false)+"</ListVersionsResult>", 1)
			case "marker-alias":
				body["versions"] = strings.Replace(body["versions"], "</ListVersionsResult>", ownerInventoryMarker(key, "original")+"</ListVersionsResult>", 1)
			case "two-latest":
				body["versions"] = strings.Replace(body["versions"], "</ListVersionsResult>", ownerInventoryVersion(key, "other", "4", true)+"</ListVersionsResult>", 1)
			case "duplicate-upload":
				body["uploads"] = strings.Replace(body["uploads"], "</ListMultipartUploadsResult>", strings.Repeat(ownerInventoryUpload(key, "upload"), 2)+"</ListMultipartUploadsResult>", 1)
			case "duplicate-current":
				body["current"] = strings.Replace(body["current"], "</ListBucketResult>", ownerInventoryCurrent(key)+"</ListBucketResult>", 1)
			case "over-page":
				body["versions"] = "<ListVersionsResult><IsTruncated>false</IsTruncated>" + strings.Repeat(ownerInventoryVersion(key+"0", "neighbor", "4", true), 129) + "</ListVersionsResult>"
			}
			reader, calls := ownerInventoryFixture(t, c, func(k string, w http.ResponseWriter, _ *http.Request) {
				if mode == "denied" {
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprint(w, "<Error><Code>AccessDenied</Code></Error>")
					return
				}
				fmt.Fprint(w, body[k])
			})
			got, err := reader.Read(context.Background())
			want, maxCalls := artifact.ErrIntegrity, int32(1)
			if mode == "denied" {
				want = ErrStorage
			} else if mode == "duplicate-upload" {
				maxCalls = 2
			} else if mode == "duplicate-current" {
				maxCalls = 3
			}
			if !errors.Is(err, want) || got.Key != key || got.CurrentComplete || calls.Load() != maxCalls {
				t.Fatal("invalid provider response completed inventory or continued I/O", err, calls.Load())
			}
			if maxCalls < 2 && got.VersionsComplete || maxCalls < 3 && got.UploadsComplete {
				t.Fatal("failed listing marked complete")
			}
		})
	}
}

func TestOwnerAuditInventoryCancellationJoinsBlockedFinalRead(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(fmt.Sprint(deadline), func(t *testing.T) {
			c := ownerInventoryConfiguration()
			body := ownerInventoryBodies(c)
			entered := make(chan struct{})
			returned := make(chan struct{})
			reader, calls := ownerInventoryFixture(t, c, func(k string, w http.ResponseWriter, r *http.Request) {
				if k == "current" {
					close(entered)
					<-r.Context().Done()
					close(returned)
					return
				}
				fmt.Fprint(w, body[k])
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if deadline {
				var end context.CancelFunc
				ctx, end = context.WithTimeout(ctx, time.Second)
				defer end()
			}
			result := make(chan error, 1)
			go func() {
				v, err := reader.Read(ctx)
				if v.Key != audit.OwnerConfigurationAuditKey(c) || len(v.Versions) != 1 || !v.VersionsComplete || !v.UploadsComplete || v.CurrentComplete || v.Current != nil {
					result <- fmt.Errorf("cancelled final read lost prior facts or claimed complete")
					return
				}
				result <- err
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				t.Fatal("final actual read not reached")
			}
			if !deadline {
				cancel()
			}
			var err error
			select {
			case err = <-result:
			case <-time.After(2 * time.Second):
				t.Fatal("read did not join original cancellation")
			}
			want := context.Canceled
			if deadline {
				want = context.DeadlineExceeded
			}
			if !errors.Is(err, want) || calls.Load() != 3 {
				t.Fatal("original cancellation/deadline replaced", err, calls.Load())
			}
			select {
			case <-returned:
			case <-time.After(time.Second):
				t.Fatal("native body request not cancelled")
			}
		})
	}
}

// A later error cannot erase already observed physical obligations. Only the
// fully checked LIST's own flag may be complete; there is no global certificate.
func TestOwnerAuditInventoryRetainsFactsBeforeFailure(t *testing.T) {
	for _, phase := range []string{"versions", "uploads", "current"} {
		for _, fault := range []string{"unavailable", "missing-truncation", "malformed-tail"} {
			t.Run(phase+"/"+fault, func(t *testing.T) {
				c := ownerInventoryConfiguration()
				key := audit.OwnerConfigurationAuditKey(c)
				body := ownerInventoryBodies(c)
				body["uploads"] = strings.Replace(body["uploads"], "</ListMultipartUploadsResult>", ownerInventoryUpload(key, "original-upload")+"</ListMultipartUploadsResult>", 1)
				if fault == "missing-truncation" {
					body[phase] = strings.Replace(body[phase], "<IsTruncated>false</IsTruncated>", "", 1)
				}
				if fault == "malformed-tail" {
					switch phase {
					case "versions":
						body[phase] = strings.Replace(body[phase], "</ListVersionsResult>", "<Version><Key>foreign</Key></Version></ListVersionsResult>", 1)
					case "uploads":
						body[phase] = strings.Replace(body[phase], "</ListMultipartUploadsResult>", "<Upload><Key>foreign</Key></Upload></ListMultipartUploadsResult>", 1)
					case "current":
						body[phase] = strings.Replace(body[phase], "</ListBucketResult>", "<Contents><Key>foreign</Key></Contents></ListBucketResult>", 1)
					}
				}
				reader, calls := ownerInventoryFixture(t, c, func(kind string, w http.ResponseWriter, _ *http.Request) {
					if kind == phase && fault == "unavailable" {
						w.WriteHeader(http.StatusServiceUnavailable)
						fmt.Fprint(w, "<Error><Code>ServiceUnavailable</Code></Error>")
						return
					}
					fmt.Fprint(w, body[kind])
				})
				got, err := reader.Read(context.Background())
				want := artifact.ErrIntegrity
				if fault == "unavailable" {
					want = ErrStorage
				}
				expectedCalls := map[string]int32{"versions": 1, "uploads": 2, "current": 3}[phase]
				if !errors.Is(err, want) || got.Key != key || !got.Configuration.Equal(c) || got.StoreID != reader.storeID || calls.Load() != expectedCalls || got.CurrentComplete {
					t.Fatal("failed read lost original identity, repeated I/O or claimed completion", err, calls.Load())
				}
				wantVersions := phase != "versions" || fault == "malformed-tail"
				wantUploads := phase == "current" || phase == "uploads" && fault == "malformed-tail"
				wantCurrent := phase == "current" && fault == "malformed-tail"
				if wantVersions != (len(got.Versions) == 1) || wantUploads != (len(got.Uploads) == 1) || wantCurrent != (got.Current != nil) {
					t.Fatal("previously validated physical entries were lost or unissued entries invented", got)
				}
				if got.VersionsComplete != (phase != "versions") || got.UploadsComplete != (phase == "current") {
					t.Fatal("failed/unissued LIST claimed complete", got)
				}
			})
		}
	}
}

func TestOwnerAuditInventoryLatestMarkerNeverInventsDataVersion(t *testing.T) {
	c := ownerInventoryConfiguration()
	key := audit.OwnerConfigurationAuditKey(c)
	body := ownerInventoryBodies(c)
	body["versions"] = "<ListVersionsResult><IsTruncated>false</IsTruncated>" + ownerInventoryVersion(key, "historical-zero-byte", "0", false) + strings.Replace(ownerInventoryMarker(key, "null"), "<IsLatest>false</IsLatest>", "<IsLatest>true</IsLatest>", 1) + "</ListVersionsResult>"
	reader, _ := ownerInventoryFixture(t, c, func(kind string, w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, body[kind]) })
	got, err := reader.Read(context.Background())
	if err != nil || len(got.Versions) != 2 || got.Versions[0].CiphertextBytes != 0 || got.Versions[0].Kind != OwnerAuditVersion || got.Versions[1].VersionID != "null" || got.Versions[1].Kind != OwnerAuditDeleteMarker || !got.Versions[1].Latest || !got.CurrentUnmatched {
		t.Fatal("latest marker or historical zero-byte body treated as absent/current data", err, got)
	}
}
