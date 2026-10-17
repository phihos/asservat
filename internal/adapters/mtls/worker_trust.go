package mtls

import (
	"crypto/x509"
	"sync/atomic"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// WorkerTrustCatalog holds public, immutable control documents supplied by
// installation composition. It cannot accept a profile or authorize a worker.
// Every lookup must use the profile from current audited dispatch state.
type WorkerTrustCatalog struct {
	installation string
	current      atomic.Pointer[workerTrustSnapshot]
}
type workerTrustSnapshot struct {
	controls map[artifact.Digest]*WorkerControlTrust
}

func NewWorkerTrustCatalog(installation string, controls [][]byte) (*WorkerTrustCatalog, error) {
	if !value.UUID(installation) {
		return nil, artifact.ErrInvalid
	}
	c := &WorkerTrustCatalog{installation: installation}
	if err := c.Replace(controls); err != nil {
		return nil, err
	}
	return c, nil
}

// Replace atomically installs a complete bounded snapshot. Invalid input leaves
// the previous snapshot unchanged; an empty snapshot deliberately removes all
// trust. The installation loader owns updates; no network handler exposes this.
func (c *WorkerTrustCatalog) Replace(controls [][]byte) error {
	if c == nil || !value.UUID(c.installation) || len(controls) > 256 {
		return artifact.ErrInvalid
	}
	next := &workerTrustSnapshot{controls: make(map[artifact.Digest]*WorkerControlTrust, len(controls))}
	for _, raw := range controls {
		t, err := ParseWorkerControl(raw)
		if err != nil || t.InstallationID != c.installation {
			return artifact.ErrInvalid
		}
		d, err := WorkerControlDigest(map[string]string{"worker.json": string(raw)})
		if err != nil || next.controls[d] != nil {
			return artifact.ErrInvalid
		}
		next.controls[d] = t
	}
	c.current.Store(next)
	return nil
}

func (c *WorkerTrustCatalog) ForInstallation(installation string) bool {
	return c != nil && c.installation == installation && c.current.Load() != nil
}

// IssuerRoots returns a new pool for one exact control digest and cluster. It
// never merges roots across clusters or uses system roots. Endpoint strings are
// digest-bound configuration only; this catalog never dials them.
func (c *WorkerTrustCatalog) IssuerRoots(p value.DownloadWorkerProfile, now time.Time) (*x509.CertPool, error) {
	if !p.Valid() || !c.ForInstallation(p.InstallationID) {
		return nil, artifact.ErrInvalid
	}
	t := c.current.Load().controls[p.ControlDigest]
	if t == nil || t.ClusterID != p.ClusterID {
		return nil, artifact.ErrDownloadUnavailable
	}
	_, roots, err := t.Roots(now)
	return roots, err
}
