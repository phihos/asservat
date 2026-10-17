package bootstrap

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
)

func TestWorkerNativeCredentialProjectionNoFallback(t *testing.T) {
	for _, kind := range []string{"valid", "token", "empty", "oversized", "control", "unknown-endpoint", "duplicate", "absent", "escape", "writable", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			v := contracts.WorkerStoreCredentials{AccessKeyID: "synthetic-reader", SecretAccessKey: "synthetic-secret"}
			switch kind {
			case "token":
				v.SessionToken = "synthetic-session"
				v.ExpiresAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
			case "empty":
				v.SecretAccessKey = ""
			case "oversized":
				v.SessionToken = string(make([]byte, 8193))
			case "control":
				v.AccessKeyID = "synthetic\nreader"
			}
			b, _ := json.Marshal(v)
			if kind == "unknown-endpoint" {
				b = append(b[:len(b)-1], []byte(`,"endpoint":"https://other.invalid"}`)...)
			}
			if kind == "duplicate" {
				b = append(b[:len(b)-1], []byte(`,"accessKeyID":"synthetic-reader"}`)...)
			}
			path := filepath.Join(dir, "credentials.json")
			if kind != "absent" {
				if err = os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "escape" {
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink("../credentials.json", path); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "writable" {
				if err = os.Chmod(path, 0660); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if kind == "cancelled" {
				cancel()
			}
			got, err := readWorkerStoreCredentials(ctx, root)
			valid := kind == "valid" || kind == "token"
			if (err == nil) != valid || valid && got != v {
				t.Fatalf("credential projection %s err=%v", kind, err)
			}
			if !valid && got != (contracts.WorkerStoreCredentials{}) {
				t.Fatal("failure leaked partial credentials")
			}
		})
	}
}

func TestWorkerNativeHTTPDoesNotUseAmbientTrustOrRedirect(t *testing.T) {
	for _, env := range []string{"HTTP_PROXY", "HTTPS_PROXY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
		t.Setenv(env, "synthetic-unused")
	}
	client := workerNativeHTTP(x509.NewCertPool(), nil)
	transport := client.Transport.(*http.Transport)
	if transport.Proxy != nil || transport.TLSClientConfig.RootCAs == nil || transport.TLSClientConfig.GetClientCertificate != nil || transport.TLSClientConfig.InsecureSkipVerify || !transport.DisableKeepAlives {
		t.Fatal("native store inherited ambient or identity configuration")
	}
	if client.CheckRedirect(&http.Request{URL: &url.URL{Scheme: "https", Host: "other.invalid"}}, nil) != http.ErrUseLastResponse {
		t.Fatal("native client followed redirect")
	}
}

func TestWorkerTemporaryStorageCredentialNeedsKnownExpiry(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	raw := []byte(`{"accessKeyID":"synthetic-reader","secretAccessKey":"synthetic-secret","sessionToken":"synthetic-session"}`)
	if err = os.WriteFile(filepath.Join(dir, "credentials.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = readWorkerStoreCredentials(t.Context(), root); err == nil {
		t.Fatal("temporary storage credentials with unknown expiry admitted for a finite worker")
	}
}

func TestWorkerStorageCredentialCoversOriginalLifetime(t *testing.T) {
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	until := now.Add(time.Hour)
	for _, test := range []struct {
		name, token, expiry string
		valid               bool
	}{
		{"static", "", "", true},
		{"temporary exact end", "synthetic", until.Format(time.RFC3339Nano), true},
		{"temporary later end", "synthetic", until.Add(time.Second).Format(time.RFC3339Nano), true},
		{"unknown", "synthetic", "", false},
		{"ends during download", "synthetic", until.Add(-time.Nanosecond).Format(time.RFC3339Nano), false},
		{"expired", "synthetic", now.Format(time.RFC3339Nano), false},
		{"malformed", "synthetic", "later", false},
		{"noncanonical", "synthetic", "2026-10-12T01:00:00+00:00", false},
		{"bounded static", "", now.Format(time.RFC3339Nano), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := contracts.WorkerStoreCredentials{SessionToken: test.token, ExpiresAt: test.expiry}
			if err := workerStoreCredentialLifetime(c, now, until); (err == nil) != test.valid {
				t.Fatalf("credential lifetime result: %v", err)
			}
			if err := workerStoreCredentialLifetime(c, until, until); err == nil {
				t.Fatal("ended worker accepted")
			}
		})
	}
}
