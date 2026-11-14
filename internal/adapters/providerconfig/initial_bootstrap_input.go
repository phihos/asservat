package providerconfig

import (
	"bytes"
	"encoding/pem"
	"slices"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

// TrustRootsPEM parses at most four exact certificate blocks into sorted,
// currently valid trust roots, as for the public bootstrap input.
func TrustRootsPEM(raw []byte, now time.Time) ([][]byte, error) { return initialBootstrapPEM(raw, now) }

func initialBootstrapPEM(raw []byte, now time.Time) ([][]byte, error) {
	if len(raw) == 0 || len(raw) > 32<<10 {
		return nil, cfg.ErrInvalid
	}
	var roots [][]byte
	for rest := bytes.TrimSpace(raw); len(rest) > 0; {
		// pem.Decode skips preceding junk; that would silently ignore private
		// keys or contradictory input. Only exact certificate blocks are legal.
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, cfg.ErrInvalid
		}
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(roots) == 4 {
			return nil, cfg.ErrInvalid
		}
		roots = append(roots, append([]byte(nil), block.Bytes...))
		rest = bytes.TrimSpace(next)
	}
	if _, _, err := mtls.OwnerTrustRoots(roots, now); err != nil {
		return nil, cfg.ErrInvalid
	}
	slices.SortFunc(roots, bytes.Compare)
	return roots, nil
}
