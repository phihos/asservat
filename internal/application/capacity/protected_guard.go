package capacity

import (
	"context"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

type CapacitySourceProtection struct {
	ClusterID, ControlNamespaceUID string
	Digest                         artifact.Digest
	ObservedAt, FreshUntil         time.Time
}

func (p CapacitySourceProtection) Valid(now time.Time) bool {
	return authorization.UUID(p.ClusterID) && identity.Text(p.ControlNamespaceUID, 64) && p.Digest != (artifact.Digest{}) && identity.Fresh(p.ObservedAt, p.FreshUntil, now, CapacitySourceInterval)
}

type CapacitySourceProtectionReader interface {
	CapacityProtection(context.Context) (CapacitySourceProtection, error)
}
type CapacityNamespaceProtection struct {
	ClusterID              string
	Digest                 artifact.Digest
	Keys                   []string
	ObservedAt, FreshUntil time.Time
}

func (p CapacityNamespaceProtection) Valid(now time.Time) bool {
	if !authorization.UUID(p.ClusterID) || p.Digest == (artifact.Digest{}) || !identity.Fresh(p.ObservedAt, p.FreshUntil, now, CapacitySourceInterval) || !identity.Strings(p.Keys, 256, 253) || len(p.Keys) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, k := range p.Keys {
		if seen[k] {
			return false
		}
		seen[k] = true
	}
	return true
}

type CapacityNamespaceProtectionReader interface {
	CapacityNamespaceProtection(context.Context) (CapacityNamespaceProtection, error)
}
