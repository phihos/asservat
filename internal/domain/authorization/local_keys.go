package authorization

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// LocalKeyConfiguration contains public fingerprints only. Private material
// never enters a projection, audit event or SQL record.
type LocalKeyVersion struct {
	Version     int
	Fingerprint artifact.Digest
}
type LocalKeyConfiguration struct {
	Scope                                  KeyScope
	ClusterID, NamespaceUID, RecoveryEpoch string
	Revision                               identity.Revision
	SecretUID                              string
	SecretDigest                           artifact.Digest
	ActiveVersion                          int
	Versions                               []LocalKeyVersion
	Suspended                              bool
	ObservedAt, FreshUntil                 time.Time
}

func (c LocalKeyConfiguration) Valid(now time.Time) bool {
	if !c.Scope.Valid() || !UUID(c.ClusterID) || !identity.Text(c.NamespaceUID, 64) || !UUID(c.RecoveryEpoch) || !c.Revision.Valid() || !identity.Text(c.SecretUID, 64) || c.SecretDigest == (artifact.Digest{}) || c.ActiveVersion < 1 || c.ActiveVersion > 2147483647 || len(c.Versions) < 1 || len(c.Versions) > 16 || !identity.Fresh(c.ObservedAt, c.FreshUntil, now, 5*time.Second) {
		return false
	}
	active, last := false, 0
	seen := map[artifact.Digest]bool{}
	for _, k := range c.Versions {
		if k.Version <= last || k.Version > 2147483647 || k.Fingerprint == (artifact.Digest{}) || seen[k.Fingerprint] {
			return false
		}
		seen[k.Fingerprint] = true
		last = k.Version
		active = active || k.Version == c.ActiveVersion
	}
	return active
}
func (c LocalKeyConfiguration) SameSnapshot(b LocalKeyConfiguration) bool {
	if c.Scope != b.Scope || c.ClusterID != b.ClusterID || c.NamespaceUID != b.NamespaceUID || c.RecoveryEpoch != b.RecoveryEpoch || c.Revision != b.Revision || c.SecretUID != b.SecretUID || c.SecretDigest != b.SecretDigest || c.ActiveVersion != b.ActiveVersion || c.Suspended != b.Suspended || len(c.Versions) != len(b.Versions) {
		return false
	}
	for i := range c.Versions {
		if c.Versions[i] != b.Versions[i] {
			return false
		}
	}
	return true
}
