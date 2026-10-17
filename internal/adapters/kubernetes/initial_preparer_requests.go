package kubernetes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	cfg "asservat.local/asservat/internal/domain/configuration"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

var ErrInitialPreparationRequestsUnresolved = errors.New("initial preparation has unresolved original requests")

// Close prohibits additional CREATE ownership, cancels local requests and joins
// every admitted local invocation. Joining is not server-side quiescence after
// an uncertain response; only the invocation's own positive result records that.
func (s *InitialPreparer) Close() {
	if s == nil {
		return
	}
	s.requestMu.Lock()
	s.requestClosed = true
	cancel := s.requestCancel
	s.requestMu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.requestJoin.Wait()
	s.requestMu.Lock()
	clear(s.providerResponses)
	s.providerResponses = nil
	clear(s.probeResponses)
	s.probeResponses = nil
	s.requestMu.Unlock()
}

func (s *InitialPreparer) ownPodRequest(ctx context.Context) (context.Context, func(), error) {
	s.requestMu.Lock()
	if s.requestClosed || s.requestContext == nil || ctx == nil || ctx.Err() != nil {
		s.requestMu.Unlock()
		return nil, nil, cfg.ErrUnavailable
	}
	s.requestJoin.Add(1)
	owner := s.requestContext
	s.requestMu.Unlock()
	request, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(owner, cancel)
	return request, func() { stop(); cancel(); s.requestJoin.Done() }, nil
}

func validPreparationPodRequests(p contracts.InitialPreparationPod) bool {
	if p.Requests == nil || len(p.Requests) > contracts.InitialPreparationPodRequests {
		return false
	}
	seen := map[string]bool{p.OperationID: true}
	for _, r := range p.Requests {
		if !authorization.UUID(r.ID) || !authorization.UUID(r.OwnerID) || seen[r.ID] || r.StartedAt.Location() != time.UTC || r.Until.Location() != time.UTC || !r.StartedAt.Equal(r.StartedAt.Truncate(time.Microsecond)) || !r.Until.Equal(r.Until.Truncate(time.Microsecond)) || r.StartedAt.Year() < 2020 || !r.StartedAt.Before(r.Until) || r.Until.Sub(r.StartedAt) > 5*time.Second {
			return false
		}
		seen[r.ID] = true
		if c := r.Completion; c != nil {
			if c.Outcome != "created" && c.Outcome != "alreadyExists" || c.CompletedAt.Location() != time.UTC || !c.CompletedAt.Equal(c.CompletedAt.Truncate(time.Microsecond)) || c.CompletedAt.Before(r.StartedAt) || !c.CompletedAt.Before(r.Until) {
				return false
			}
		}
	}
	return p.Receipt == nil || len(p.Requests) > 0
}

// createGatedPod claims one immutable request before sending it. A competing
// receipt closes further claims through the same root resource-version CAS.
// Completed receipts are retained privately until their exact SQL-free journal
// acknowledgement; another process cannot manufacture completion via a GET.
func (s *InitialPreparer) createGatedPod(ctx context.Context, want core.Pod, until time.Time) error {
	ctx, joined, e := s.ownPodRequest(ctx)
	if e != nil {
		return e
	}
	defer joined()
	cm, w, e := s.read(ctx)
	if e != nil || w.Activation == nil || w.Activation.Pod == nil {
		return cfg.ErrChanged
	}
	p := w.Activation.Pod
	if p.Receipt != nil {
		return nil
	}
	if len(p.Requests) >= contracts.InitialPreparationPodRequests {
		return ErrInitialPreparationRequestsUnresolved
	}
	id, e := prepUUID()
	if e != nil {
		return e
	}
	now := s.protection.observer.now().UTC().Truncate(time.Microsecond)
	deadline := until.UTC().Truncate(time.Microsecond)
	if !now.Before(deadline) || deadline.Sub(now) > 5*time.Second {
		return cfg.ErrUnavailable
	}
	r := contracts.InitialPreparationPodRequest{ID: id, OwnerID: s.requestOwner, StartedAt: now, Until: deadline}
	p.Requests = append(p.Requests, r)
	if e = s.write(ctx, cm, w, until); e != nil {
		return e
	} // only acknowledged claimant sends
	if e = s.finish(ctx, until); e != nil {
		return e
	}
	s.creator.stamp(&want.ObjectMeta)
	want.Annotations[initialPreparationOperationAnnotation] = p.OperationID
	body, e := json.Marshal(want)
	if e != nil {
		return cfg.ErrInvalid
	}
	result := s.creator.api.Post().AbsPath("/api/v1/namespaces/"+s.plan.Workload.Namespace+"/pods").Param("fieldValidation", "Strict").MaxRetries(0).Body(body).Do(ctx)
	code := 0
	result.StatusCode(&code)
	raw, sendErr := result.Raw()
	if sendErr == nil {
		sendErr = result.Error()
	}
	outcome := ""
	if code == http.StatusCreated && sendErr == nil {
		if _, _, check := s.verifiedGatedPod(raw, *p); check == nil {
			outcome = "created"
		}
	} else if code == http.StatusConflict && apierrors.IsAlreadyExists(sendErr) {
		outcome = "alreadyExists"
	}
	completed := s.protection.observer.now().UTC().Truncate(time.Microsecond)
	if outcome != "" && ctx.Err() == nil && completed.Before(r.Until) {
		proof := contracts.InitialPreparationPodRequestCompletion{Outcome: outcome, CompletedAt: completed}
		s.requestMu.Lock()
		if s.requestProofs == nil {
			s.requestProofs = map[string]contracts.InitialPreparationPodRequestCompletion{}
		}
		s.requestProofs[id] = proof
		s.requestMu.Unlock()
		// This write may fail after the request completed. The same joined local
		// owner can later persist its retained proof under fresh current checks.
		_ = s.persistPodRequestCompletions(ctx, until)
	}
	if apierrors.IsForbidden(sendErr) || apierrors.IsUnauthorized(sendErr) {
		return cfg.ErrDenied
	}
	if sendErr != nil {
		return cfg.ErrUnavailable
	}
	return nil
}

func (s *InitialPreparer) persistPodRequestCompletions(ctx context.Context, until time.Time) error {
	s.requestMu.Lock()
	proofs := make(map[string]contracts.InitialPreparationPodRequestCompletion, len(s.requestProofs))
	for k, v := range s.requestProofs {
		proofs[k] = v
	}
	s.requestMu.Unlock()
	if len(proofs) == 0 {
		return nil
	}
	cm, w, e := s.read(ctx)
	if e != nil || w.Activation == nil || w.Activation.Pod == nil {
		return cfg.ErrChanged
	}
	changed := false
	for i := range w.Activation.Pod.Requests {
		r := &w.Activation.Pod.Requests[i]
		proof, ok := proofs[r.ID]
		if !ok {
			continue
		}
		if r.OwnerID != s.requestOwner || proof.CompletedAt.Before(r.StartedAt) || !proof.CompletedAt.Before(r.Until) {
			return cfg.ErrChanged
		}
		if r.Completion != nil {
			if *r.Completion != proof {
				return cfg.ErrChanged
			}
		} else {
			p := proof
			r.Completion = &p
			changed = true
		}
	}
	if changed {
		return s.write(ctx, cm, w, until)
	}
	return s.finish(ctx, until)
}

// DrainPodCreateRequests permanently closes this local owner, then acknowledges
// only its own joined positive responses. It proves all recorded CREATEs closed
// only if each has such a completion. It grants no DELETE, launch or activation
// authority and does not resolve an older owner's missing response.
func (s *InitialPreparer) DrainPodCreateRequests(ctx context.Context) error {
	if !s.ActivationPreparationEnabled() || ctx == nil {
		return cfg.ErrInvalid
	}
	s.Close()
	until, e := s.current(ctx)
	if e != nil {
		return e
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	if s.HandoverEnabled() {
		if e = s.persistSecretCompletions(ctx, until); e != nil {
			return e
		}
	}
	if e = s.persistPodRequestCompletions(ctx, until); e != nil {
		return e
	}
	_, w, e := s.read(ctx)
	if e != nil || w.Activation == nil || w.Activation.Pod == nil || w.Activation.Pod.Receipt == nil {
		return ErrInitialPreparationRequestsUnresolved
	}
	for _, r := range w.Activation.Pod.Requests {
		if r.Completion == nil {
			return ErrInitialPreparationRequestsUnresolved
		}
	}
	return s.finish(ctx, until)
}
