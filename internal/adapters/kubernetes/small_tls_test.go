package kubernetes

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Go's verifier accepts some certificate profiles rejected by strict TLS
// clients. Exercise the actual generated public bytes with that independent
// verifier; no server, provider credentials or relaxed TLS settings are used.
func TestSmallServiceTLSStrictOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("OpenSSL is required for independent strict certificate verification")
	}
	for _, provider := range []string{"postgres", "seaweed"} {
		t.Run(provider, func(t *testing.T) {
			var data map[string][]byte
			var host string
			leafFile := "tls.crt"
			var err error
			if provider == "postgres" {
				p := smallPostgresTestPlan()
				host = p.Host()
				leafFile = "server.crt"
				data, err = BuildSmallPostgresMaterial(p, time.Now())
			} else {
				p := smallSeaweedTestPlan()
				host = p.Host()
				data, err = BuildSmallSeaweedMaterial(p, time.Now())
			}
			if err != nil {
				t.Fatal(err)
			}
			defer clearSmallSeaweedData(data)
			dir := t.TempDir()
			for _, name := range []string{"ca.crt", "tls.crt"} {
				key := name
				if name == "tls.crt" {
					key = leafFile
				}
				if len(data[key]) == 0 {
					t.Fatal("missing generated certificate", key)
				}
				if err := os.WriteFile(filepath.Join(dir, name), data[key], 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			verify := func(name string) ([]byte, error) {
				return exec.CommandContext(ctx, "openssl", "verify", "-x509_strict", "-CAfile", filepath.Join(dir, "ca.crt"), "-verify_hostname", name, filepath.Join(dir, "tls.crt")).CombinedOutput()
			}
			if output, err := verify(host); err != nil {
				t.Fatalf("generated %s certificate rejected by strict verifier: %v: %s", provider, err, output)
			}
			if _, err := verify("another.invalid"); err == nil {
				t.Fatal("wrong service hostname accepted")
			}
		})
	}
}
