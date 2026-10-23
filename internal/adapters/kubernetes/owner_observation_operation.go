package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"slices"
	"sync"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// OwnerObservationOperationReader is ADR150's v2 native component only. It does
// not implement any general authentication/source port. SQL registration, actual
// TLS, process-owned keys and installed v2 selection remain separate mandatory
// consumers; a native snapshot alone cannot authorize a network or metadata call.
type OwnerObservationOperationReader struct {
	client *PermissionClient
	guard  *OwnerWorkloadProtection
	pin    value.OwnerObservationPin
}

// OwnerObservationNativeFacts are native observations, not authentication. Dates
// always describe the first original boundary, including after Final succeeds.
type OwnerObservationNativeFacts = value.OwnerObservationNativeFacts
type OwnerObservationNativePeer = value.OwnerObservationNativePeer

// Each Begin creates independent private state, even for identical request IDs.
// Nothing is indexed or reusable by request ID, and no background read runs.
type OwnerObservationOperation struct {
	reader              *OwnerObservationOperationReader
	root                context.Context
	cancel              context.CancelFunc
	mu                  sync.Mutex
	reads               sync.WaitGroup
	busy, closed, final bool
	original            OwnerObservationNativeFacts
	service             artifact.Digest
	local               *ownerLocalCallerBoundary
}

func NewOwnerObservationOperationReader(c *PermissionClient, guard *OwnerWorkloadProtection, pin value.OwnerObservationPin) (*OwnerObservationOperationReader, error) {
	p := pin.Pool
	if c == nil || guard == nil || guard.observer != c || !pin.Valid() || c.clusterID != p.ClusterID || c.control != (cfg.NamespaceRef{Name: p.Namespace, UID: p.NamespaceUID}) || guard.plan.ControlNamespace != c.control || guard.plan.Deployment != p.Deployment || guard.plan.DeploymentUID != p.DeploymentUID || guard.digest != pin.ProtectionDigest {
		return nil, cfg.ErrInvalid
	}
	// Fresh zero decode owns every nested slice/pointer. Neither the caller's
	// administration plan nor another reader's private guard can mutate this one.
	var plan cfg.OwnerWorkloadAdministration
	raw, err := json.Marshal(guard.plan)
	if err != nil || json.Unmarshal(raw, &plan) != nil {
		return nil, cfg.ErrInvalid
	}
	owned, err := NewOwnerWorkloadProtection(c, guard.probe, plan, guard.pin)
	if err != nil || owned.digest != pin.ProtectionDigest {
		return nil, cfg.ErrInvalid
	}
	return &OwnerObservationOperationReader{c, guard.share(owned), pin}, nil
}

func (s *OwnerObservationOperationReader) Begin(ctx context.Context, r value.OwnerObservationRequest, peers []value.OwnerBinding) (*OwnerObservationOperation, error) {
	return s.beginLocal(ctx, r, peers, nil)
}

// The optional participant is a fixed concrete local caller, never an arbitrary
// callback. Legacy Begin has no participant and retains every existing read.
func (s *OwnerObservationOperationReader) beginLocal(ctx context.Context, r value.OwnerObservationRequest, peers []value.OwnerBinding, local *ownerLocalCallerBoundary) (*OwnerObservationOperation, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !r.Valid(s.client.now()) || r.RootID != s.pin.RootID || len(peers) < 1 || len(peers) > 2 {
		return nil, value.ErrInvalid
	}
	end, finite := ctx.Deadline()
	if !finite || !s.client.now().Before(end) {
		return nil, value.ErrInvalid
	}
	until := identity.Earlier(end, r.NotAfter)
	if !s.client.now().Before(until) {
		return nil, value.ErrUnavailable
	}
	p := s.pin.Pool
	owned := slices.Clone(peers)
	for i, b := range owned {
		if !b.Valid() || b.InstallationID != p.InstallationID || b.ClusterID != p.ClusterID || b.IssuerEpoch != p.IssuerEpoch || slices.Contains(owned[:i], b) {
			return nil, value.ErrInvalid
		}
	}
	root, cancel := context.WithDeadline(ctx, until)
	at := s.client.now()
	facts, service, err := s.boundaryLocal(root, r, owned, at, until, local)
	if err != nil {
		cancel()
		return nil, err
	}
	return &OwnerObservationOperation{reader: s, root: root, cancel: cancel, original: facts, service: service, local: local}, nil
}

func cloneOwnerNativeFacts(v OwnerObservationNativeFacts) OwnerObservationNativeFacts {
	v.Peers = slices.Clone(v.Peers)
	for i := range v.Peers {
		v.Peers[i].Addresses = slices.Clone(v.Peers[i].Addresses)
	}
	return v
}
func (o *OwnerObservationOperation) currentLocked(ctx context.Context) bool {
	return !o.closed && ctx != nil && ctx.Err() == nil && o.root.Err() == nil && o.reader.client.now().Before(o.original.FreshUntil)
}

// Original returns the original observation without I/O or renewed dates. This
// is deliberately not named Current and cannot mint another proof/operation.
func (o *OwnerObservationOperation) Original(ctx context.Context) (OwnerObservationNativeFacts, error) {
	if o == nil {
		return OwnerObservationNativeFacts{}, value.ErrInvalid
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.currentLocked(ctx) || o.busy || o.final {
		o.closed = true
		o.cancel()
		return OwnerObservationNativeFacts{}, value.ErrUnavailable
	}
	return cloneOwnerNativeFacts(o.original), nil
}

// Final performs the second actual native boundary exactly once. Any mutation,
// failed/unknown read, expiry or cancellation permanently closes the operation.
func (o *OwnerObservationOperation) Final(ctx context.Context) (OwnerObservationNativeFacts, error) {
	var zero OwnerObservationNativeFacts
	if o == nil {
		return zero, value.ErrInvalid
	}
	o.mu.Lock()
	deadline, finite := time.Time{}, false
	if ctx != nil {
		deadline, finite = ctx.Deadline()
	}
	if !o.currentLocked(ctx) || !finite || o.busy || o.final {
		o.closed = true
		o.cancel()
		o.mu.Unlock()
		return zero, value.ErrUnavailable
	}
	o.busy = true
	o.reads.Add(1)
	before := cloneOwnerNativeFacts(o.original)
	o.mu.Unlock()
	defer o.reads.Done()
	until := identity.Earlier(deadline, before.FreshUntil)
	call, cancel := context.WithDeadline(o.root, until)
	joined := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { cancel(); close(joined) })
	defer func() {
		cancel()
		if !stop() {
			<-joined
		}
	}()
	peers := make([]value.OwnerBinding, len(before.Peers))
	for i := range peers {
		peers[i] = before.Peers[i].Binding
	}
	after, service, err := o.reader.boundaryLocal(call, before.Request, peers, before.ObservedAt, until, o.local)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.busy = false
	if err != nil || !o.currentLocked(ctx) || call.Err() != nil || service != o.service || !sameOwnerNativePeers(before.Peers, after.Peers) {
		o.closed = true
		o.cancel()
		if err != nil {
			return zero, err
		}
		return zero, value.ErrUnavailable
	}
	o.final = true
	after.Final = true
	return cloneOwnerNativeFacts(after), nil
}
func sameOwnerNativePeers(a, b []OwnerObservationNativePeer) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		y := b[i]
		if x.Binding != y.Binding || x.Pod != y.Pod || x.ReplicaSetUID != y.ReplicaSetUID || x.WorkloadDigest != y.WorkloadDigest || !slices.Equal(x.Addresses, y.Addresses) {
			return false
		}
	}
	return true
}

// Close cancels and joins the actual admitted Final read. It does not interpret
// local cleanup as remote completion, and does not release another owner's slot.
func (o *OwnerObservationOperation) Close() {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.closed = true
	o.cancel()
	o.mu.Unlock()
	o.reads.Wait()
}

func (s *OwnerObservationOperationReader) boundary(ctx context.Context, r value.OwnerObservationRequest, bindings []value.OwnerBinding, start, until time.Time) (OwnerObservationNativeFacts, artifact.Digest, error) {
	return s.boundaryLocal(ctx, r, bindings, start, until, nil)
}

func (s *OwnerObservationOperationReader) boundaryLocal(ctx context.Context, r value.OwnerObservationRequest, bindings []value.OwnerBinding, start, until time.Time, local *ownerLocalCallerBoundary) (OwnerObservationNativeFacts, artifact.Digest, error) {
	var zero OwnerObservationNativeFacts
	var noDigest artifact.Digest
	if ctx.Err() != nil || !s.client.now().Before(until) {
		return zero, noDigest, value.ErrUnavailable
	}
	p, g := s.pin.Pool, s.guard
	ns, err := s.client.namespace(ctx, s.client.control)
	if err != nil || ns.Deleting {
		return zero, noDigest, cfg.ErrChanged
	}
	guard, err := checkAdmissionGuard(ctx, s.client, g.plan.Name, g.pin, g.policy, g.binding)
	if err != nil {
		return zero, noDigest, err
	}
	deployment, err := g.proveObject(ctx, start)
	if err != nil {
		return zero, noDigest, err
	}
	route := &OwnerEndpoints{client: s.client, pool: p}
	service, err := route.service(ctx)
	if err != nil {
		return zero, noDigest, err
	}
	base := "/api/v1/namespaces/" + p.Namespace + "/"
	account, err := ownerResource[core.ServiceAccount](route, ctx, base+"serviceaccounts/"+p.ServiceAccount, "v1", "ServiceAccount")
	if err != nil || !ownerMetadata(account.ObjectMeta, p.Namespace, p.ServiceAccount, p.AccountUID) {
		return zero, noDigest, value.ErrUnavailable
	}
	routes, err := route.observationOperationRoutes(ctx, bindings)
	if err != nil {
		return zero, noDigest, err
	}
	out := OwnerObservationNativeFacts{Request: r, Pin: s.pin, ObservedAt: start, FreshUntil: until}
	observed := make(map[string]OwnerObservationNativePeer)
	for _, b := range bindings {
		peer, found := observed[b.PodUID]
		if !found {
			location := routes[b.PodUID]
			pod, e := ownerResource[core.Pod](route, ctx, base+"pods/"+location.pod, "v1", "Pod")
			if e != nil {
				return zero, noDigest, e
			}
			ref, ok := ownerController(pod.OwnerReferences, "ReplicaSet", "apps/v1")
			if !ok {
				return zero, noDigest, cfg.ErrChanged
			}
			rs, e := ownerResource[apps.ReplicaSet](route, ctx, "/apis/apps/v1/namespaces/"+p.Namespace+"/replicasets/"+ref.Name, "apps/v1", "ReplicaSet")
			if e != nil {
				return zero, noDigest, e
			}
			digest, e := s.validateObjects(service, deployment, rs, pod, b, location)
			if e != nil {
				return zero, noDigest, e
			}
			last, e := ownerResource[core.Pod](route, ctx, base+"pods/"+location.pod, "v1", "Pod")
			if e != nil || last.ResourceVersion != pod.ResourceVersion || !equalJSON(last, pod) {
				return zero, noDigest, cfg.ErrChanged
			}
			peer = OwnerObservationNativePeer{Pod: pod.Name, ReplicaSetUID: string(rs.UID), Addresses: slices.Clone(location.addresses), WorkloadDigest: digest}
			observed[b.PodUID] = peer
		}
		peer.Binding = b
		out.Peers = append(out.Peers, peer)
	}
	if local != nil {
		end, err := local.read(ctx, start, until)
		if err != nil {
			return zero, noDigest, err
		}
		until = identity.Earlier(until, end)
		out.FreshUntil = until
		var stop context.CancelFunc
		ctx, stop = context.WithDeadline(ctx, until)
		defer stop()
	}
	latest, err := route.service(ctx)
	if err != nil || latest.ResourceVersion != service.ResourceVersion || !equalJSON(latest.Spec, service.Spec) {
		return zero, noDigest, cfg.ErrChanged
	}
	current, err := checkAdmissionGuard(ctx, s.client, g.plan.Name, g.pin, g.policy, g.binding)
	if err != nil || current != guard {
		return zero, noDigest, cfg.ErrChanged
	}
	ns, err = s.client.namespace(ctx, s.client.control)
	if err != nil || ns.Deleting || ctx.Err() != nil || !s.client.now().Before(until) {
		return zero, noDigest, value.ErrUnavailable
	}
	raw, err := json.Marshal(service.Spec)
	if err != nil {
		return zero, noDigest, value.ErrUnavailable
	}
	return out, artifact.Digest(sha256.Sum256(raw)), nil
}

func (s *OwnerObservationOperationReader) validateObjects(service core.Service, d apps.Deployment, rs apps.ReplicaSet, pod core.Pod, binding value.OwnerBinding, route ownerOperationRoute) (artifact.Digest, error) {
	var zero artifact.Digest
	p := s.pin.Pool
	if !ownerMetadata(d.ObjectMeta, p.Namespace, p.Deployment, p.DeploymentUID) || d.Spec.Replicas == nil || *d.Spec.Replicas < 1 || d.Spec.Template.Spec.ServiceAccountName != p.ServiceAccount || !ownerMetadata(pod.ObjectMeta, p.Namespace, route.pod, binding.PodUID) || pod.Spec.ServiceAccountName != p.ServiceAccount || pod.Spec.HostNetwork || pod.Spec.HostPID || pod.Spec.HostIPC || pod.Spec.NodeName == "" || pod.Spec.NodeName != route.node || pod.Status.Phase != core.PodRunning || len(pod.Status.PodIPs) < 1 || len(pod.Status.PodIPs) > 2 {
		return zero, value.ErrUnavailable
	}
	ready, count := false, 0
	for _, c := range pod.Status.Conditions {
		if c.Type == core.PodReady {
			count++
			ready = c.Status == core.ConditionTrue
		}
	}
	sel, err := meta.LabelSelectorAsSelector(d.Spec.Selector)
	if err != nil || !ready || count != 1 || !sel.Matches(labels.Set(pod.Labels)) || !labels.SelectorFromSet(service.Spec.Selector).Matches(labels.Set(pod.Labels)) {
		return zero, value.ErrUnavailable
	}
	for _, ip := range route.addresses {
		if !slices.ContainsFunc(pod.Status.PodIPs, func(v core.PodIP) bool { return v.IP == ip }) {
			return zero, value.ErrUnavailable
		}
	}
	ref, ok := ownerController(pod.OwnerReferences, "ReplicaSet", "apps/v1")
	if !ok || !ownerMetadata(rs.ObjectMeta, p.Namespace, ref.Name, string(ref.UID)) || rs.Spec.Replicas == nil || *rs.Spec.Replicas < 1 || !ownerEnrollmentSelector(rs.Spec.Selector, pod.Labels) {
		return zero, cfg.ErrChanged
	}
	owner, ok := ownerController(rs.OwnerReferences, "Deployment", "apps/v1")
	if !ok || owner.Name != p.Deployment || string(owner.UID) != p.DeploymentUID || connectorAPITemplateMatch(&d, &rs, &pod, s.pin.TemplateDigest, s.pin.ImageDigest) != nil {
		return zero, cfg.ErrChanged
	}
	// Same canonical native facts on both boundaries; no certificate, token,
	// private input or caller-supplied digest enters this local comparison.
	raw, err := json.Marshal(struct {
		Pin                      value.OwnerObservationPin
		Pod                      core.PodSpec
		Replica                  apps.ReplicaSetSpec
		Deployment               apps.DeploymentSpec
		Labels, Annotations      map[string]string
		PodOwners, ReplicaOwners []meta.OwnerReference
	}{s.pin, pod.Spec, rs.Spec, d.Spec, pod.Labels, pod.Annotations, pod.OwnerReferences, rs.OwnerReferences})
	if err != nil || len(raw) > 128<<10 {
		return zero, value.ErrUnavailable
	}
	canonical := jsontext.Value(raw)
	if canonical.Canonicalize() != nil {
		return zero, value.ErrUnavailable
	}
	h := sha256.New()
	h.Write([]byte("asservat-owner-observation-native-operation/v2\x00"))
	h.Write(canonical)
	copy(zero[:], h.Sum(nil))
	return zero, nil
}
