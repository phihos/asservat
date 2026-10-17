package bootstrap

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"asservat.local/asservat/internal/adapters/objectstore"
	"asservat.local/asservat/internal/contracts"
)

// This exercises the actual mounted-input format selection and real signed TLS
// storage requests. The backend is synthetic; IAM and physical-copy retirement
// require their separate native qualifications.
func TestInitialInstallerRequiresVersionBeforeAuditReceipt(t *testing.T) {
	for _, tc := range []struct {
		name, format, version string
		accepted              bool
	}{
		{"required-missing", contracts.InitialInstallerVersionedAuditFormat, "", false},
		{"required-null", contracts.InitialInstallerVersionedAuditFormat, "null", false},
		{"required-pinned", contracts.InitialInstallerVersionedAuditFormat, "original-version", true},
		{"legacy-missing", contracts.InitialInstallerFormat, "", false},
		{"legacy-null", contracts.InitialInstallerFormat, "null", false},
		{"legacy-pinned", contracts.InitialInstallerFormat, "legacy-version", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var puts, reads atomic.Int32
			body := []byte("synthetic encrypted audit bytes")
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/audit/initial/test" || r.Header.Get("Authorization") == "" {
					t.Error("unexpected path or unsigned request")
					w.WriteHeader(403)
					return
				}
				w.Header().Set("ETag", `"synthetic-etag"`)
				if tc.version != "" {
					w.Header().Set("X-Amz-Version-Id", tc.version)
				}
				switch r.Method {
				case http.MethodPut:
					puts.Add(1)
					got, err := io.ReadAll(r.Body)
					if err != nil || string(got) != string(body) || r.Header.Get("If-None-Match") != "*" {
						t.Error("write lost original bytes or conditional creation")
					}
					w.WriteHeader(200)
				case http.MethodGet:
					reads.Add(1)
					if r.URL.Query().Get("versionId") != tc.version || r.Header.Get("If-Match") != `"synthetic-etag"` || r.Header.Get("Range") != "bytes=0-"+strconv.Itoa(len(body)-1) {
						t.Error("read lost pinned version, etag or range")
					}
					w.Header().Set("Content-Length", strconv.Itoa(len(body)))
					w.Header().Set("Content-Range", "bytes 0-"+strconv.Itoa(len(body)-1)+"/"+strconv.Itoa(len(body)))
					w.WriteHeader(206)
					_, _ = w.Write(body)
				default:
					t.Error("unexpected storage effect")
					w.WriteHeader(405)
				}
			}))
			defer srv.Close()
			base, dir, c := initialInputFixture(t)
			c.Format, c.AuditStore.Endpoint, c.AuditStore.Roots = tc.format, srv.URL, [][]byte{srv.Certificate().Raw}
			writeOwnerJSON(t, dir, "deployment.json", c)
			writeOwnerJSON(t, dir, "audit-storage.json", contracts.OwnerStorageCredential{AccessKeyID: "synthetic", SecretAccessKey: "synthetic-secret"})
			in, err := readInitialInputs(context.Background(), base.files)
			if err != nil {
				t.Fatal(err)
			}
			store, err := in.auditStore(srv.Client())
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			receipt, err := store.PutSmall(context.Background(), "initial/test", body)
			if puts.Load() != 1 {
				t.Fatal("initial write retried or was never sent", puts.Load())
			}
			if !tc.accepted {
				if !errors.Is(err, objectstore.ErrStorage) || receipt.Key != "" {
					t.Fatal("missing immutable version produced a usable initial receipt", err, receipt)
				}
				if reads.Load() != 0 {
					t.Fatal("unversioned result triggered read/fallback")
				}
				return
			}
			if err != nil || receipt.VersionID != tc.version {
				t.Fatal("original receipt not retained", err)
			}
			pinned, err := store.Pin(receipt)
			if err != nil {
				t.Fatal(err)
			}
			got, err := pinned.ReadRange(context.Background(), 0, int64(len(body)))
			if err != nil || string(got) != string(body) || reads.Load() != 1 {
				t.Fatal("original pinned bytes unavailable", err)
			}
			if puts.Load() != 1 {
				t.Fatal("verification repeated the storage effect")
			}
		})
	}
}

func TestInitialInstallerAuditFormatIsImmutablePlan(t *testing.T) {
	base, dir, c := initialInputFixture(t)
	writeOwnerJSON(t, dir, "deployment.json", c)
	legacy, err := readInitialInputs(context.Background(), base.files)
	if err != nil {
		t.Fatal(err)
	}
	c.Format = contracts.InitialInstallerVersionedAuditFormat
	writeOwnerJSON(t, dir, "deployment.json", c)
	versioned, err := readInitialInputs(context.Background(), base.files)
	if err != nil || legacy.plan == versioned.plan {
		t.Fatal("audit enforcement omitted from immutable plan", err)
	}
	c.Format = "asservat-initial-installer/v999"
	writeOwnerJSON(t, dir, "deployment.json", c)
	if _, err = readInitialInputs(context.Background(), base.files); err == nil {
		t.Fatal("unknown format accepted by mounted input loader")
	}
	versioned.config.Format = c.Format
	if _, err = versioned.auditStore(http.DefaultClient); err == nil {
		t.Fatal("unknown audit format selected a fallback")
	}
}
