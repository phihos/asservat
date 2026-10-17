package bootstrap

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"asservat.local/asservat/internal/adapters/mounts"
	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
)

func workerCredentialText(s string, max int) bool {
	if len(s) < 1 || len(s) > max {
		return false
	}
	for _, c := range s {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

// root is opened by the private runtime at the fixed projection directory.
// No CLI, environment credential, home-directory or metadata fallback exists.
func readWorkerStoreCredentials(ctx context.Context, root *os.Root) (contracts.WorkerStoreCredentials, error) {
	var zero contracts.WorkerStoreCredentials
	b, err := mounts.Read(ctx, root, filepath.Base(contracts.WorkerStoreCredentialsPath), contracts.WorkerStoreCredentialsMaxBytes)
	if err != nil {
		return zero, artifact.ErrDownloadUnavailable
	}
	defer clear(b)
	c, err := contracts.DecodeWorkerStoreCredentials(bytes.NewReader(b))
	if err != nil || !workerCredentialText(c.AccessKeyID, 256) || !workerCredentialText(c.SecretAccessKey, 4096) || c.SessionToken != "" && !workerCredentialText(c.SessionToken, 8192) {
		return zero, artifact.ErrInvalid
	}
	if c.SessionToken != "" && c.ExpiresAt == "" {
		return zero, artifact.ErrInvalid
	}
	if c.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
		if err != nil || expires.IsZero() || expires.UTC().Format(time.RFC3339Nano) != c.ExpiresAt {
			return zero, artifact.ErrInvalid
		}
	}
	return c, nil
}

// Validate the local immutable projection before certificate enrollment spends
// any provider work. The same original lifetime is checked again before reads.
func loadWorkerNativeCredentials(ctx context.Context, until time.Time) (contracts.WorkerStoreCredentials, error) {
	root, err := os.OpenRoot(filepath.Dir(contracts.WorkerStoreCredentialsPath))
	if err != nil {
		return contracts.WorkerStoreCredentials{}, artifact.ErrDownloadUnavailable
	}
	defer root.Close()
	c, err := readWorkerStoreCredentials(ctx, root)
	if err != nil {
		return contracts.WorkerStoreCredentials{}, err
	}
	if err = workerStoreCredentialLifetime(c, time.Now(), until); err != nil {
		return contracts.WorkerStoreCredentials{}, err
	}
	return c, nil
}

// Immutable projected credentials cannot renew in place. A temporary credential
// must cover the original admitted worker lifetime before any native work starts.
// Provider revocation/failure still interrupts work; this date grants no access.
func workerStoreCredentialLifetime(c contracts.WorkerStoreCredentials, now, until time.Time) error {
	if !until.After(now) || c.SessionToken != "" && c.ExpiresAt == "" {
		return artifact.ErrInvalid
	}
	if c.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
		if err != nil || expires.IsZero() || expires.UTC().Format(time.RFC3339Nano) != c.ExpiresAt || !now.Before(expires) || until.After(expires) {
			return artifact.ErrInvalid
		}
	}
	return nil
}

// Finite S3/key requests only: I-13 uses its separate live HTTP/2 transport.
// Trust pools remain separate and the object store never gets the process
// acquisition certificate. No proxy, redirect, system CA or retry.
func workerNativeHTTP(roots *x509.CertPool, credentials *mtls.WorkerCredentials) *http.Client {
	config := &tls.Config{RootCAs: roots.Clone(), MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	if credentials != nil {
		config.GetClientCertificate = credentials.GetClientCertificate
	}
	transport := &http.Transport{TLSClientConfig: config, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, IdleConnTimeout: 5 * time.Second, MaxConnsPerHost: 1, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, MaxResponseHeaderBytes: 4096, DisableCompression: true, DisableKeepAlives: true}
	return &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
