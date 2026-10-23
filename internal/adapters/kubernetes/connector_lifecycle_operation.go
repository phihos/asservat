package kubernetes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// ConnectorLifecycleReader owns only ADR153's explicit enrollment/signing
// native composition. General attestation, retirement and ADR150 stay separate.
type ConnectorLifecycleReader struct {
	client *PermissionClient
	source *ConnectorIdentitySource
	guard  *OwnerWorkloadProtection
	tokens app.ConnectorPodToken
}

var _ app.ConnectorLifecycleOperationReader = (*ConnectorLifecycleReader)(nil)

func NewConnectorLifecycleReader(c *PermissionClient, source *ConnectorIdentitySource, guard *OwnerWorkloadProtection, tokens app.ConnectorPodToken) (*ConnectorLifecycleReader, error) {
	if c == nil || source == nil || source.protection == nil || source.protection.configMapProtection == nil || guard == nil || tokens == nil ||
		source.client != c || source.protection.observer != c || guard.observer != c || source.binding.ClusterID != c.clusterID ||
		source.protection.plan.ControlNamespace != c.control || guard.plan.ControlNamespace != c.control {
		return nil, cfg.ErrInvalid
	}
	var workPlan cfg.OwnerWorkloadAdministration
	raw, err := json.Marshal(guard.plan)
	if err != nil || json.Unmarshal(raw, &workPlan) != nil {
		return nil, cfg.ErrInvalid
	}
	work, err := NewOwnerWorkloadProtection(c, guard.probe, workPlan, guard.pin)
	if err != nil || work.digest != guard.digest {
		return nil, cfg.ErrInvalid
	}
	work = guard.share(work)
	var sourcePlan cfg.ConfigMapAdministration
	raw, err = json.Marshal(source.protection.plan)
	if err != nil || json.Unmarshal(raw, &sourcePlan) != nil {
		return nil, cfg.ErrInvalid
	}
	protection, err := NewConnectorIdentityProtection(c, source.protection.probe, sourcePlan, source.protection.pin)
	if err != nil || protection.digest != source.protection.digest {
		return nil, cfg.ErrInvalid
	}
	owned, err := NewConnectorIdentitySource(c, protection, source.name, source.uid, source.root, source.binding)
	if err != nil {
		return nil, err
	}
	return &ConnectorLifecycleReader{c, owned, work, tokens}, nil
}

type connectorLifecycleOperation struct {
	reader       *ConnectorLifecycleReader
	root         context.Context
	cancel       context.CancelFunc
	request      app.ConnectorLifecycleRequest
	clientKey    artifact.Digest
	serverKey    artifact.Digest
	token        []byte
	mu           sync.Mutex
	joined       sync.WaitGroup
	busy, closed bool
	phase        value.ConnectorLifecyclePhase
	until, last  time.Time
	first        *value.ConnectorLifecycleObservation
	prior        *value.ConnectorLifecycleObservation
	backing      *app.ConnectorIdentityBacking
}

func (s *ConnectorLifecycleReader) BeginConnectorLifecycle(ctx context.Context, r app.ConnectorLifecycleRequest) (app.ConnectorLifecycleOperation, error) {
	if s == nil || ctx == nil || ctx.Err() != nil || !r.Binding.Valid(s.client.now()) || !r.Request.Valid() || r.Request.Process != r.Binding.Process || r.Binding.Process.Binding != s.source.binding {
		return nil, value.ErrInvalid
	}
	deadline, finite := ctx.Deadline()
	if !finite || deadline.After(r.Binding.NotAfter) || !s.client.now().Before(deadline) {
		return nil, value.ErrInvalid
	}
	r.Request.ClientCSRDER = bytes.Clone(r.Request.ClientCSRDER)
	r.Request.ServerCSRDER = bytes.Clone(r.Request.ServerCSRDER)
	client, err := mtls.EnrollmentKey(r.Request.ClientCSRDER)
	if err != nil {
		return nil, value.ErrDenied
	}
	server, err := mtls.EnrollmentKey(r.Request.ServerCSRDER)
	if err != nil || client == server {
		return nil, value.ErrDenied
	}
	root, cancel := context.WithDeadline(ctx, deadline)
	return &connectorLifecycleOperation{reader: s, root: root, cancel: cancel, request: r, clientKey: client, serverKey: server, until: deadline, last: r.Binding.RequestedAt}, nil
}

func (o *connectorLifecycleOperation) validLocked(ctx context.Context) bool {
	now := o.reader.client.now()
	return !o.closed && ctx != nil && ctx.Err() == nil && o.root.Err() == nil && !now.Before(o.last) && now.Before(o.until)
}

func lifecycleNext(prior, next value.ConnectorLifecyclePhase) bool {
	return prior == 0 && next == value.ConnectorLifecycleInitial ||
		prior == value.ConnectorLifecycleInitial && (next == value.ConnectorLifecycleBeforeEffect || next == value.ConnectorLifecycleBeforeActivation) ||
		prior == value.ConnectorLifecycleBeforeEffect && next == value.ConnectorLifecycleBeforeActivation ||
		prior == value.ConnectorLifecycleBeforeActivation && next == value.ConnectorLifecycleFinal
}

func (o *connectorLifecycleOperation) Read(ctx context.Context, phase value.ConnectorLifecyclePhase) (value.ConnectorLifecycleObservation, error) {
	var zero value.ConnectorLifecycleObservation
	if o == nil {
		return zero, value.ErrInvalid
	}
	o.mu.Lock()
	deadline, finite := time.Time{}, false
	if ctx != nil {
		deadline, finite = ctx.Deadline()
	}
	if !o.validLocked(ctx) || !finite || o.busy || !lifecycleNext(o.phase, phase) {
		o.closed = true
		o.cancel()
		o.mu.Unlock()
		return zero, value.ErrUnavailable
	}
	o.phase, o.busy = phase, true
	o.joined.Add(1)
	until := identity.Earlier(o.until, deadline)
	start := o.reader.client.now()
	o.mu.Unlock()
	defer o.joined.Done()
	call, cancel := context.WithDeadline(o.root, until)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { cancel(); close(done) })
	defer func() {
		cancel()
		if !stop() {
			<-done
		}
	}()
	var proof value.ConnectorProcessProof
	var configuration app.ConnectorIdentityConfiguration
	var err error
	if phase == value.ConnectorLifecycleInitial {
		o.token, err = o.reader.tokens.ReadConnectorPodToken(call)
		if err == nil && (len(o.token) < 1 || len(o.token) > 16<<10 || !bytes.Equal(bytes.TrimSpace(o.token), o.token)) {
			err = value.ErrDenied
		}
		// The token getter transfers an owned buffer; hold only this original
		// token for this operation. Projection rotation cannot renew it.
	}
	if err == nil {
		if phase == value.ConnectorLifecycleInitial || phase == value.ConnectorLifecycleFinal {
			proof, configuration, until, err = o.boundary(call, start, until)
		} else {
			proof, configuration, until, err = o.currentValues(call, start, until)
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.busy = false
	out := value.ConnectorLifecycleObservation{Binding: o.request.Binding, Phase: phase, Original: proof, Source: configuration.Source, Until: until}
	if o.first != nil {
		out.Original = o.first.Original.Clone()
		if phase == value.ConnectorLifecycleFinal {
			final := proof.Clone()
			out.FinalProof = &final
		}
	}
	if err != nil || !o.validLocked(ctx) || call.Err() != nil || !out.Valid(o.reader.client.now()) ||
		out.Original.ClientKeyDigest != o.clientKey || out.Original.ServerKeyDigest != o.serverKey ||
		o.backing != nil && !connectorBackingEqual(*o.backing, configuration.Backing) ||
		o.prior != nil && !out.Continues(*o.prior) ||
		o.first != nil && !sameLifecycleProofFacts(o.first.Original, proof) {
		o.closed = true
		o.cancel()
		if err != nil {
			return zero, err
		}
		return zero, value.ErrUnavailable
	}
	o.until, o.last = until, o.reader.client.now()
	owned := out.Clone()
	o.prior = &owned
	if o.first == nil {
		first, backing := out.Clone(), configuration.Backing.Clone()
		o.first, o.backing = &first, &backing
	}
	return out.Clone(), nil
}

func sameLifecycleProofFacts(a, b value.ConnectorProcessProof) bool {
	return a.Process == b.Process && a.Configuration.SameSource(b.Configuration) &&
		a.Pod == b.Pod && a.ReplicaSet == b.ReplicaSet && a.ReplicaSetUID == b.ReplicaSetUID &&
		a.ClientKeyDigest == b.ClientKeyDigest && a.ServerKeyDigest == b.ServerKeyDigest &&
		a.TokenDigest == b.TokenDigest && a.WorkloadDigest == b.WorkloadDigest && a.ProtectionDigest == b.ProtectionDigest
}

func (o *connectorLifecycleOperation) proof(w ownerEnrollmentWorkload, source value.ConnectorIdentitySource, start, until time.Time) value.ConnectorProcessProof {
	return value.ConnectorProcessProof{Process: o.request.Binding.Process, Configuration: source.Observation, Pod: w.Pod, ReplicaSet: w.ReplicaSet, ReplicaSetUID: w.ReplicaSetUID, ClientKeyDigest: o.clientKey, ServerKeyDigest: o.serverKey, TokenDigest: artifact.Digest(sha256.Sum256(o.token)), WorkloadDigest: w.Digest, ProtectionDigest: o.reader.guard.digest, ObservedAt: start, FreshUntil: until}
}

func (o *connectorLifecycleOperation) Close() {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.closed = true
	o.cancel()
	o.mu.Unlock()
	o.joined.Wait()
	o.mu.Lock()
	clear(o.token)
	clear(o.request.Request.ClientCSRDER)
	clear(o.request.Request.ServerCSRDER)
	o.mu.Unlock()
}
