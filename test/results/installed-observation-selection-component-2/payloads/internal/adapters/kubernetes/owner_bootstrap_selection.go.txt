package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	"github.com/google/uuid"
	core "k8s.io/api/core/v1"
)

type OwnerBootstrapAdvanceStatus string

const (
	OwnerBootstrapIntentRecorded OwnerBootstrapAdvanceStatus = "intent-recorded"
	OwnerBootstrapPending        OwnerBootstrapAdvanceStatus = "pending"
	OwnerBootstrapComplete       OwnerBootstrapAdvanceStatus = "complete"
	OwnerBootstrapStopped        OwnerBootstrapAdvanceStatus = "stopped"
)

type OwnerBootstrapAdvance struct {
	Stop        OwnerInstallationStop
	OperationID string
	Status      OwnerBootstrapAdvanceStatus
	Snapshot    contracts.InitialRuntimeResourceSnapshot
	Selection   contracts.OwnerBootstrapSelection
	Input       contracts.OwnerDeployment
}

// This fixed installer owns only original public allocation and its immutable
// child. It cannot create SQL permissions, enroll a peer or read credentials.
// The caller retains the root; Close cancels and joins this producer's calls.
type OwnerBootstrapSelectionProducer struct {
	self                                              *OwnerBootstrapSelectionProducer
	root                                              *OwnerIdentityRoleRoot
	plan                                              contracts.OwnerBootstrapPlan
	ctx                                               context.Context
	cancel                                            context.CancelFunc
	mu                                                sync.Mutex
	closed, busy                                      bool
	joined                                            sync.WaitGroup
	parentAttempted, childAttempted, receiptAttempted bool
	pendingParent                                     *contracts.OwnerBootstrapSelectionClaim
	pendingChild                                      *contracts.OwnerBootstrapObjectAttempt
	pendingReceipt                                    *contracts.OwnerBootstrapObjectReceipt
	observedChild                                     *contracts.OwnerBootstrapObjectReceipt
}

func NewOwnerBootstrapSelectionProducer(root *OwnerIdentityRoleRoot, plan contracts.OwnerBootstrapPlan) (*OwnerBootstrapSelectionProducer, error) {
	if root == nil || root.ctx == nil || root.resources == nil || root.input.OwnerLayout != contracts.OwnerProviderInstalledLayout || !ownerBootstrapPlanValid(plan, root.resources.now()) || plan.ObservationFormat != root.resources.observationFormat || plan.PKIMount == root.resources.initial.KeyService.AuditMount {
		return nil, cfg.ErrInvalid
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		return nil, cfg.ErrInvalid
	}
	clone, err := contracts.DecodeOwnerBootstrapPlan(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(root.ctx)
	s := &OwnerBootstrapSelectionProducer{root: root, plan: clone, ctx: life, cancel: cancel}
	s.self = s
	return s, nil
}
func (s *OwnerBootstrapSelectionProducer) Close() {
	if s == nil || s.self != s {
		return
	}
	s.mu.Lock()
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	s.joined.Wait()
}
func (s *OwnerBootstrapSelectionProducer) enter(ctx context.Context) (context.Context, func(), error) {
	if s == nil || s.self != s || ctx == nil || ctx.Err() != nil {
		return nil, nil, cfg.ErrUnavailable
	}
	s.mu.Lock()
	if s.closed || s.busy || s.ctx.Err() != nil || ctx.Err() != nil {
		s.mu.Unlock()
		return nil, nil, cfg.ErrUnavailable
	}
	s.busy = true
	s.joined.Add(1)
	s.mu.Unlock()
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	done := make(chan struct{})
	stop := context.AfterFunc(s.ctx, func() { cancel(); close(done) })
	return call, func() {
		cancel()
		if !stop() {
			<-done
		}
		s.mu.Lock()
		s.busy = false
		s.mu.Unlock()
		s.joined.Done()
	}, nil
}
func (s *OwnerBootstrapSelectionProducer) Advance(ctx context.Context) (OwnerBootstrapAdvance, error) {
	return s.advance(ctx, false)
}
func (s *OwnerBootstrapSelectionProducer) Inspect(ctx context.Context) (OwnerBootstrapAdvance, error) {
	return s.advance(ctx, true)
}

// At most three admitted phases, then one lookup after an uncertain result.
// A missing original result is a stopped installation, never a CREATE retry or
// an unbounded polling loop. This driver does not reset any original interval.
func (s *OwnerBootstrapSelectionProducer) Complete(ctx context.Context) (OwnerBootstrapAdvance, error) {
	for i := 0; i < 3; i++ {
		out, err := s.Advance(ctx)
		if err != nil {
			observed, readErr := s.Inspect(ctx)
			if readErr == nil && observed.Status == OwnerBootstrapComplete {
				return observed, nil
			}
			out.Status = OwnerBootstrapStopped
			checks := [...]ownerOperationCheck{ownerSelectionFirstPhase, ownerSelectionSecondPhase, ownerSelectionThirdPhase}
			return out, ownerOperationError(checks[i], err)
		}
		if out.Status == OwnerBootstrapComplete {
			return out, nil
		}
	}
	return OwnerBootstrapAdvance{Status: OwnerBootstrapStopped, Stop: OwnerInstallationUnverified}, cfg.ErrUnavailable
}

type ownerBootstrapPhase struct {
	producer *OwnerBootstrapSelectionProducer
	initial  ownerIdentityOperationNative
	snapshot contracts.InitialRuntimeResourceSnapshot
	object   *core.Secret
	body     contracts.OwnerBootstrapSelection
	until    time.Time
}

func (s *OwnerBootstrapSelectionProducer) advance(ctx context.Context, inspect bool) (OwnerBootstrapAdvance, error) {
	var out OwnerBootstrapAdvance
	call, done, err := s.enter(ctx)
	if err != nil {
		return OwnerBootstrapAdvance{Status: OwnerBootstrapStopped, Stop: OwnerInstallationClosed}, ownerOperationError(ownerSelectionEnter, err)
	}
	defer done()
	entered, completed, preflightFailed := false, false, false
	err = s.root.providerOperation(call, false, func(bounded context.Context) (ownerIdentityOperationNative, error) {
		first, err := s.root.readOwnerIdentityOperationNative(bounded, s.root.input.LayoutDigest, false)
		if err != nil {
			preflightFailed = true
			return ownerIdentityOperationNative{}, ownerOperationError(ownerSelectionInitialNative, err)
		}
		return first, nil
	}, func(bounded context.Context, first ownerIdentityOperationNative) error {
		entered = true
		phase := &ownerBootstrapPhase{producer: s, initial: first, snapshot: first.retained.resources, object: first.retained.object, until: first.until}
		current, end := context.WithDeadline(bounded, phase.until)
		defer end()
		status, err := phase.apply(current, inspect)
		if err != nil {
			return ownerOperationError(ownerSelectionApply, err)
		}
		// Actual exact child GET follows CREATE/CAS, then an independently proved
		// final native bracket follows all effects. Its dates only narrow the call.
		current, narrow := context.WithDeadline(current, phase.until)
		defer narrow()
		if p := phase.snapshot.State.OwnerBootstrap; p != nil && p.Child != nil {
			if _, err = phase.readChild(current); err != nil {
				return ownerOperationError(ownerSelectionChildRead, err)
			}
		}
		last, err := s.root.readOwnerIdentityOperationNative(current, s.root.input.LayoutDigest, false)
		expected := first
		expected.retained.resources = phase.snapshot
		phase.until = identity.Earlier(phase.until, last.until)
		if err != nil {
			return ownerOperationUnavailable(ownerSelectionFinalNative, err)
		}
		if check := ownerIdentityOperationOriginalDifference(expected, last); check != ownerOperationNoFailure {
			return ownerOperationError(check, cfg.ErrUnavailable)
		}
		if initialHandoverDeadline(current, s.root.resources.now, phase.until) != nil {
			return ownerOperationError(ownerSelectionFinalDeadline, cfg.ErrUnavailable)
		}
		raw, err := json.Marshal(phase.snapshot)
		if err != nil {
			return ownerOperationError(ownerSelectionSnapshotEncode, err)
		}
		var snapshot contracts.InitialRuntimeResourceSnapshot
		if err = json.Unmarshal(raw, &snapshot); err != nil {
			return ownerOperationError(ownerSelectionSnapshotDecode, err)
		}
		snapshot.ValidUntil = identity.Earlier(snapshot.ValidUntil, phase.until)
		out = OwnerBootstrapAdvance{Status: status, Snapshot: snapshot, Selection: phase.body, OperationID: snapshot.State.OwnerBootstrap.OperationID}
		if status == OwnerBootstrapComplete {
			out.Input, err = ownerBootstrapDeployment(s.root, phase.body, last)
			if err != nil {
				return ownerOperationError(ownerSelectionDeployment, err)
			}
			if initialHandoverDeadline(current, s.root.resources.now, phase.until) != nil {
				return ownerOperationError(ownerSelectionDeploymentDeadline, cfg.ErrUnavailable)
			}
		}
		completed = true
		return nil
	})
	if err != nil {
		// The outer boundary includes lifecycle/source admission and the SQL
		// bridge. These labels do not attribute a pre-callback failure to SQL.
		if !entered && !preflightFailed {
			err = ownerOperationError(ownerSelectionOuterBefore, err)
		} else if completed {
			err = ownerOperationError(ownerSelectionOuterAfter, err)
		}
		out.Status = OwnerBootstrapStopped
		out.Stop = OwnerInstallationUnverified
		if s.pendingParent != nil {
			out.OperationID = s.pendingParent.OperationID
		}
		if s.pendingChild != nil {
			out.OperationID = s.pendingChild.OperationID
		}
		if !s.root.resources.now().Before(s.root.resourceUntil) {
			out.Stop = OwnerInstallationExpired
		} else if call.Err() != nil {
			out.Stop = OwnerInstallationCancelled
		}
		return out, err
	}
	return out, nil
}
func (p *ownerBootstrapPhase) claimDates(ctx context.Context) (time.Time, time.Time, error) {
	now := p.producer.root.resources.now().UTC().Truncate(time.Microsecond)
	end, ok := ctx.Deadline()
	end = identity.Earlier(end, identity.Earlier(p.until, p.snapshot.State.Until)).UTC().Truncate(time.Microsecond)
	if !ok || ctx.Err() != nil || !now.Before(end) {
		return time.Time{}, time.Time{}, cfg.ErrUnavailable
	}
	return now, end, nil
}
func (p *ownerBootstrapPhase) apply(ctx context.Context, inspect bool) (OwnerBootstrapAdvanceStatus, error) {
	s := p.producer
	old := p.snapshot.State.OwnerBootstrap
	if !s.originalAttempt(old) {
		return "", cfg.ErrChanged
	}
	if old == nil {
		if inspect || s.parentAttempted || p.snapshot.State.OwnerIdentity != nil || p.snapshot.State.OwnerLaunch != nil {
			return "", cfg.ErrUnavailable
		}
		now, end, err := p.claimDates(ctx)
		if err != nil {
			return "", err
		}
		claim := &contracts.OwnerBootstrapSelectionClaim{ObservationFormat: s.plan.ObservationFormat, IssuerEpoch: s.root.resources.initial.IssuerEpoch, OperationID: uuid.NewString(), PermissionRootID: uuid.NewString(), PKIMount: s.plan.PKIMount, Connections: s.plan.Connections, Concurrency: s.plan.Concurrency, ClaimedAt: now, Until: end}
		for _, peer := range s.plan.Peers {
			claim.Peers = append(claim.Peers, contracts.OwnerBootstrapPeerAllocation{ClusterID: peer.ClusterID, PeerID: uuid.NewString(), RootsDigest: ownerBootstrapDigest("roots", peer.Roots)})
		}
		p.body, err = ownerBootstrapBody(s.root, claim, s.plan)
		if err != nil {
			return "", err
		}
		claim.PublicDigest = ownerBootstrapDigest("selection", p.body)
		next := p.snapshot.State
		next.OwnerBootstrap = claim
		s.parentAttempted = true
		s.pendingParent = claim
		if err = p.write(ctx, next, end); err != nil {
			return "", ownerOperationError(ownerSelectionParentCAS, err)
		}
		return OwnerBootstrapIntentRecorded, nil
	}
	var err error
	p.body, err = ownerBootstrapBody(s.root, old, s.plan)
	if err != nil || !ownerBootstrapBodyBound(s.root, old, p.body) {
		return "", cfg.ErrChanged
	}
	if old.Child == nil {
		if inspect {
			return OwnerBootstrapIntentRecorded, nil
		}
		if s.childAttempted || p.snapshot.State.OwnerIdentity != nil || p.snapshot.State.OwnerLaunch != nil {
			return "", cfg.ErrUnavailable
		}
		now, end, err := p.claimDates(ctx)
		if err != nil {
			return "", err
		}
		claim := *old
		claim.Child = &contracts.OwnerBootstrapObjectAttempt{OperationID: uuid.NewString(), ClaimedAt: now, Until: end}
		next := p.snapshot.State
		next.OwnerBootstrap = &claim
		s.childAttempted = true
		s.pendingChild = claim.Child
		if err = p.write(ctx, next, end); err != nil {
			return "", ownerOperationError(ownerSelectionChildCAS, err)
		}
		// Only this positively acknowledged child CAS permits this CREATE. On every
		// later call the persisted child exists and only its exact result is read.
		p.until = identity.Earlier(p.until, end)
		effect, stop := context.WithDeadline(ctx, p.until)
		defer stop()
		if err = p.createChild(effect); err != nil {
			return "", ownerOperationError(ownerSelectionChildCreate, err)
		}
		return OwnerBootstrapPending, nil
	}
	receipt, err := p.readChild(ctx)
	if err != nil {
		return "", ownerOperationError(ownerSelectionReceiptRead, err)
	}
	if old.Child.Receipt != nil {
		return OwnerBootstrapComplete, nil
	}
	if inspect {
		return OwnerBootstrapPending, nil
	}
	if s.receiptAttempted {
		return "", cfg.ErrUnavailable
	}
	_, end, err := p.claimDates(ctx)
	if err != nil {
		return "", err
	}
	claim := *old
	child := *old.Child
	claim.Child = &child
	child.Receipt = &receipt
	next := p.snapshot.State
	next.OwnerBootstrap = &claim
	s.receiptAttempted = true
	s.pendingReceipt = &receipt
	if err = p.write(ctx, next, end); err != nil {
		return "", ownerOperationError(ownerSelectionReceiptCAS, err)
	}
	return OwnerBootstrapComplete, nil
}

// Retain exact locally issued unknown CAS values as well as the persisted
// original. Another valid-shaped claim cannot replace this producer's attempt.
func (s *OwnerBootstrapSelectionProducer) originalAttempt(p *contracts.OwnerBootstrapSelectionClaim) bool {
	if s.pendingParent != nil && p != nil {
		a, b := *s.pendingParent, *p
		a.Child = nil
		b.Child = nil
		if !equalJSON(a, b) {
			return false
		}
	}
	if s.pendingChild != nil && p != nil && p.Child != nil {
		a, b := *s.pendingChild, *p.Child
		a.Receipt = nil
		b.Receipt = nil
		if !equalJSON(a, b) {
			return false
		}
	}
	return s.pendingReceipt == nil || p == nil || p.Child == nil || p.Child.Receipt == nil || equalJSON(*s.pendingReceipt, *p.Child.Receipt)
}
