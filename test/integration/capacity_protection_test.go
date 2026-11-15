package integration

import (
	"context"
	"encoding/hex"
	"time"

	capacity "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
)

// capacitySyntheticProtection is the fixture source protection observation.
type capacitySyntheticProtection struct {
	cluster, namespace string
	digest             artifact.Digest
}

func (s capacitySyntheticProtection) CapacityProtection(ctx context.Context) (capacity.CapacitySourceProtection, error) {
	if ctx.Err() != nil {
		return capacity.CapacitySourceProtection{}, ctx.Err()
	}
	n := time.Now().UTC().Truncate(time.Microsecond)
	until := n.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	return capacity.CapacitySourceProtection{ClusterID: s.cluster, ControlNamespaceUID: s.namespace, Digest: s.digest, ObservedAt: n, FreshUntil: until}, nil
}

func capacityGuardHex(v artifact.Digest) string { return hex.EncodeToString(v[:]) }
