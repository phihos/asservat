package kubernetes

import (
	"context"
	"slices"
	"time"

	port "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Only these two capacity-specific readers share this private state. They
// observe that the control (or probe) namespace still exists with its UID;
// Kubernetes RBAC decides who may write the capacity sources and namespace
// labels. The runtime no longer re-verifies an admission policy, the probe
// account or a dry-run denial (helm-native-install plan, slice 0). The
// digest names the cluster and namespace, so the SQL capacity setup and
// regional qualifications stay comparable without installer pins.
type capacityGuard struct {
	observer  *PermissionClient
	namespace cfg.NamespaceRef
	digest    artifact.Digest
}
type CapacityGuard struct{ guard *capacityGuard }
type CapacityNamespaceGuard struct {
	guard *capacityGuard
	keys  []string
}

type capacityGuardDiagnostic struct {
	step  string
	cause error
}

func (e *capacityGuardDiagnostic) Error() string     { return "capacity guard: " + e.step }
func (e *capacityGuardDiagnostic) Unwrap() error     { return e.cause }
func (e *capacityGuardDiagnostic) FixedStep() string { return e.step }

var _ port.CapacitySourceProtectionReader = (*CapacityGuard)(nil)
var _ port.CapacityNamespaceProtectionReader = (*CapacityNamespaceGuard)(nil)

func newCapacityGuard(observer *PermissionClient, namespace cfg.NamespaceRef, pin GuardPin, plan any) (*capacityGuard, error) {
	if observer == nil || observer.control != namespace {
		return nil, cfg.ErrInvalid
	}
	// The digest names the cluster and observed namespace only (field map
	// coupling 3); plan and pin no longer enter it.
	return &capacityGuard{observer: observer, namespace: namespace, digest: namedDigest("asservat-capacity-protection/v2", observer.clusterID, namespace.Name)}, nil
}
func NewCapacityGuard(observer *PermissionClient, plan cfg.CapacityAdministration, pin GuardPin) (*CapacityGuard, error) {
	g, err := newCapacityGuard(observer, plan.ControlNamespace, pin, plan)
	if err != nil {
		return nil, err
	}
	return &CapacityGuard{guard: g}, nil
}
func NewCapacityNamespaceGuard(observer *PermissionClient, plan cfg.CapacityNamespaceAdministration, pin GuardPin) (*CapacityNamespaceGuard, error) {
	// The keys are the namespace label keys this cluster's selectors use.
	if len(plan.Keys) == 0 || !identity.Strings(plan.Keys, 256, 253) {
		return nil, cfg.ErrInvalid
	}
	for i, k := range plan.Keys {
		if len(validation.IsQualifiedName(k)) != 0 || slices.Contains(plan.Keys[:i], k) {
			return nil, cfg.ErrInvalid
		}
	}
	g, err := newCapacityGuard(observer, plan.ProbeNamespace, pin, plan)
	if err != nil {
		return nil, err
	}
	return &CapacityNamespaceGuard{guard: g, keys: slices.Clone(plan.Keys)}, nil
}
func (g *capacityGuard) current(ctx context.Context) (time.Time, time.Time, error) {
	fail := func(step string, err error) (time.Time, time.Time, error) {
		return time.Time{}, time.Time{}, &capacityGuardDiagnostic{step: step, cause: err}
	}
	if g == nil || ctx == nil || ctx.Err() != nil {
		return fail("request", cfg.ErrUnavailable)
	}
	start := g.observer.now()
	until := start.Add(port.CapacitySourceInterval)
	if d, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, d)
	}
	call, cancel := context.WithDeadline(ctx, until)
	defer cancel()
	ns, err := g.observer.namespace(call, g.namespace)
	if err != nil || ns.Deleting {
		return fail("namespace", cfg.ErrChanged)
	}
	if call.Err() != nil || !identity.Fresh(start, until, g.observer.now(), port.CapacitySourceInterval) {
		return fail("freshness", cfg.ErrUnavailable)
	}
	return start, until, nil
}

func (g *CapacityGuard) CapacityProtection(ctx context.Context) (port.CapacitySourceProtection, error) {
	var out port.CapacitySourceProtection
	if g == nil || g.guard == nil {
		return out, cfg.ErrUnavailable
	}
	s := g.guard
	start, until, err := s.current(ctx)
	if err != nil {
		return out, err
	}
	return port.CapacitySourceProtection{ClusterID: s.observer.clusterID, ControlNamespaceUID: s.namespace.UID, Digest: s.digest, ObservedAt: start, FreshUntil: until}, nil
}

func (g *CapacityNamespaceGuard) CapacityNamespaceProtection(ctx context.Context) (port.CapacityNamespaceProtection, error) {
	var out port.CapacityNamespaceProtection
	if g == nil || g.guard == nil {
		return out, cfg.ErrUnavailable
	}
	s := g.guard
	start, until, err := s.current(ctx)
	if err != nil {
		return out, err
	}
	return port.CapacityNamespaceProtection{ClusterID: s.observer.clusterID, Digest: s.digest, Keys: slices.Clone(g.keys), ObservedAt: start, FreshUntil: until}, nil
}
