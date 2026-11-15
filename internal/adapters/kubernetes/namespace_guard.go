package kubernetes

import (
	"context"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// Metadata reads for Deployments, StatefulSets and Pods.
const capacityMetadataAccept = "application/json;as=PartialObjectMetadata;g=meta.k8s.io;v=v1"
const capacityMetadataListAccept = "application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1"

// capacityGuard observes that the probe namespace still exists with its
// UID; Kubernetes RBAC decides who may write the guarded metadata. The digest
// names the cluster and namespace.
type capacityGuard struct {
	observer  *PermissionClient
	namespace cfg.NamespaceRef
	digest    artifact.Digest
}

type capacityGuardDiagnostic struct {
	step  string
	cause error
}

func (e *capacityGuardDiagnostic) Error() string     { return "guard: " + e.step }
func (e *capacityGuardDiagnostic) Unwrap() error     { return e.cause }
func (e *capacityGuardDiagnostic) FixedStep() string { return e.step }

func newCapacityGuard(observer *PermissionClient, namespace cfg.NamespaceRef, _ GuardPin, _ any) (*capacityGuard, error) {
	if observer == nil || observer.control != namespace {
		return nil, cfg.ErrInvalid
	}
	return &capacityGuard{observer: observer, namespace: namespace, digest: artifact.Digest(contracts.NamespaceSourceDigest(observer.clusterID, namespace.Name))}, nil
}

func (g *capacityGuard) current(ctx context.Context) (time.Time, time.Time, error) {
	fail := func(step string, err error) (time.Time, time.Time, error) {
		return time.Time{}, time.Time{}, &capacityGuardDiagnostic{step: step, cause: err}
	}
	if g == nil || ctx == nil || ctx.Err() != nil {
		return fail("request", cfg.ErrUnavailable)
	}
	start := g.observer.now()
	until := start.Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	ns, err := g.observer.namespace(call, g.namespace)
	if err != nil || ns.Deleting {
		return fail("namespace", cfg.ErrChanged)
	}
	if call.Err() != nil || !identity.Fresh(start, until, g.observer.now(), 5*time.Second) {
		return fail("freshness", cfg.ErrUnavailable)
	}
	return start, until, nil
}
