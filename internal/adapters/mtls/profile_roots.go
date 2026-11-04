package mtls

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/execution"
)

var ErrProfileRoots = errors.New("invalid named profile TLS roots")

// CanonicalProfileRoots accepts only a bounded explicit certificate bundle.
// It parses every block, rejects ignored text/headers, and fixes PEM formatting
// before hashing public material. It grants no peer or capture authority.
func CanonicalProfileRoots(input string) (string, artifact.Digest, error) {
	var zero artifact.Digest
	if len(input) == 0 || len(input) > execution.GoProfileTLSRootsLimit {
		return "", zero, ErrProfileRoots
	}
	rest := []byte(input)
	var out bytes.Buffer
	for len(bytes.TrimSpace(rest)) > 0 {
		rest = bytes.TrimSpace(rest)
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return "", zero, ErrProfileRoots
		}
		// pem.Decode may skip malformed leading blocks. Isolate the first block
		// and reject nested beginnings instead of accepting a later certificate.
		endMarker := []byte("-----END CERTIFICATE-----")
		end := bytes.Index(rest, endMarker)
		if end < 0 {
			return "", zero, ErrProfileRoots
		}
		end += len(endMarker)
		first := rest[:end]
		if bytes.Count(first, []byte("-----BEGIN ")) != 1 {
			return "", zero, ErrProfileRoots
		}
		block, next := pem.Decode(first)
		if len(next) != 0 || block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return "", zero, ErrProfileRoots
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return "", zero, ErrProfileRoots
		}
		if err := pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}); err != nil || out.Len() > execution.GoProfileTLSRootsLimit {
			return "", zero, ErrProfileRoots
		}
		rest = rest[end:]
	}
	if out.Len() == 0 {
		return "", zero, ErrProfileRoots
	}
	canonical := out.String()
	return canonical, artifact.Digest(sha256.Sum256([]byte(canonical))), nil
}
