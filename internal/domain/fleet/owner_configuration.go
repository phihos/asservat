package fleet

import (
	"bytes"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// OwnerConfiguration is a protected observation, not certificate activation,
// durable revision acceptance, recovery state or request/evidence authority.
type OwnerConfiguration struct {
	Pool             OwnerPool
	Revision         identity.Revision
	ProtectionDigest artifact.Digest
	Suspended        bool
	IssuerRoots      [][]byte // Public DER roots, never signing keys.
}

func (c OwnerConfiguration) Valid() bool {
	if !c.Pool.Valid() || !c.Revision.Valid() || c.Revision.Generation > 2147483647 || c.ProtectionDigest == (artifact.Digest{}) || len(c.IssuerRoots) < 1 || len(c.IssuerRoots) > 4 {
		return false
	}
	total := 0
	for i, r := range c.IssuerRoots {
		total += len(r)
		if len(r) < 1 || len(r) > 16<<10 || total > 32<<10 {
			return false
		}
		for j := 0; j < i; j++ {
			if bytes.Equal(r, c.IssuerRoots[j]) {
				return false
			}
		}
	}
	return true
}
func (c OwnerConfiguration) Equal(other OwnerConfiguration) bool {
	if c.Pool != other.Pool || c.Revision != other.Revision || c.ProtectionDigest != other.ProtectionDigest || c.Suspended != other.Suspended || len(c.IssuerRoots) != len(other.IssuerRoots) {
		return false
	}
	for i, r := range c.IssuerRoots {
		if !bytes.Equal(r, other.IssuerRoots[i]) {
			return false
		}
	}
	return true
}
func (c OwnerConfiguration) Clone() OwnerConfiguration {
	c.IssuerRoots = append([][]byte(nil), c.IssuerRoots...)
	for i, r := range c.IssuerRoots {
		c.IssuerRoots[i] = bytes.Clone(r)
	}
	return c
}

type OwnerConfigurationObservation struct {
	Configuration          OwnerConfiguration
	ObservedAt, FreshUntil time.Time
}

func (o OwnerConfigurationObservation) Valid(now time.Time) bool {
	return o.Configuration.Valid() && identity.Fresh(o.ObservedAt, o.FreshUntil, now, 5*time.Second)
}

// OwnerRoute joins original configuration and endpoint observations. It remains
// routing/trust input only; authentication and current ownership are separate.
type OwnerRoute struct {
	Configuration          OwnerConfigurationObservation
	Endpoint               OwnerEndpoint
	ObservedAt, FreshUntil time.Time
}

func (r OwnerRoute) Valid(now time.Time) bool {
	return r.Configuration.Valid(now) && !r.Configuration.Configuration.Suspended && r.Endpoint.Valid(now) && r.Endpoint.Pool == r.Configuration.Configuration.Pool && identity.Fresh(r.ObservedAt, r.FreshUntil, now, 5*time.Second) && !r.FreshUntil.After(r.Configuration.FreshUntil) && !r.FreshUntil.After(r.Endpoint.FreshUntil)
}
