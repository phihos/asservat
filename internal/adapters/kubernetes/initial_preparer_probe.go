package kubernetes

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"asservat.local/asservat/internal/contracts"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	auth "k8s.io/api/authentication/v1"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
)

// A private response owned by the caller, never a persisted public authority.
// Token bytes must be cleared when the caller closes its temporary probe client.
type InitialPreparationProbeObservation struct {
	Token                 []byte
	ExpiresAt, ValidUntil time.Time
}

func (InitialPreparationProbeObservation) String() string {
	return "protected initial probe observation"
}
func (InitialPreparationProbeObservation) GoString() string {
	return "protected initial probe observation"
}
func (s *InitialPreparer) probeAnchorName() string { return s.plan.Workload.Credentials + "-probe" }
func (s *InitialPreparer) probeAnchorPath() string {
	return "/api/v1/namespaces/" + s.plan.Workload.Namespace + "/secrets/" + s.probeAnchorName()
}
func (s *InitialPreparer) originalPrivateScope(ctx context.Context) (contracts.InitialPreparationRoot, contracts.WorkerObjectReference, error) {
	var zero contracts.InitialPreparationRoot
	_, root, e := s.read(ctx)
	if e != nil || root.Phase != "declared" || root.Activation == nil || root.Activation.Pod == nil || root.Activation.Pod.Receipt == nil {
		return zero, contracts.WorkerObjectReference{}, cfg.ErrChanged
	}
	raw, e := s.creator.raw(ctx, "/api/v1/namespaces/"+s.plan.Workload.Namespace+"/pods/"+s.plan.Workload.Name, nil)
	if e != nil {
		return zero, contracts.WorkerObjectReference{}, cfg.ErrUnavailable
	}
	if _, _, e = s.verifiedGatedPod(raw, *root.Activation.Pod); e != nil {
		return zero, contracts.WorkerObjectReference{}, e
	}
	account, e := preparationRootRef(root, "ServiceAccount", s.plan.Workload.ProbeAccount)
	if e != nil {
		return zero, account, e
	}
	raw, e = s.creator.raw(ctx, "/api/v1/namespaces/"+s.plan.Workload.Namespace+"/serviceaccounts/"+account.Name, nil)
	var live core.ServiceAccount
	if e != nil || strictGuardJSON(raw, &live) != nil || !ownerMetadata(live.ObjectMeta, s.plan.Workload.Namespace, account.Name, account.UID) || live.AutomountServiceAccountToken == nil || *live.AutomountServiceAccountToken {
		return zero, account, cfg.ErrChanged
	}
	return root, account, nil
}
func (s *InitialPreparer) readProbeAnchor(ctx context.Context, p contracts.InitialPreparationProbe) (contracts.InitialPreparationReceipt, error) {
	var zero contracts.InitialPreparationReceipt
	raw, e := s.creator.raw(ctx, s.probeAnchorPath(), nil)
	if e != nil {
		return zero, cfg.ErrUnavailable
	}
	defer clear(raw)
	var v core.Secret
	if strictGuardJSON(raw, &v) != nil {
		return zero, cfg.ErrChanged
	}
	for _, b := range v.Data {
		defer clear(b)
	}
	if v.APIVersion != "v1" || v.Kind != "Secret" || v.Type != core.SecretTypeOpaque || !s.creator.owns(v.ObjectMeta, s.probeAnchorName()) || v.Namespace != s.plan.Workload.Namespace || v.Immutable == nil || !*v.Immutable || len(v.Data) != 0 || len(v.StringData) != 0 || len(v.Annotations) != 3 || len(v.Labels) != 0 || len(v.Finalizers) != 0 || v.Annotations[initialPreparationOperationAnnotation] != p.AnchorOperationID {
		return zero, cfg.ErrChanged
	}
	if p.Anchor != nil && p.Anchor.UID != string(v.UID) {
		return zero, cfg.ErrChanged
	}
	return contracts.InitialPreparationReceipt{UID: string(v.UID), ResourceVersion: v.ResourceVersion}, nil
}
func (s *InitialPreparer) prepareProbeAnchor(ctx context.Context) (err error) {
	phase := "open-private-state"
	defer func() {
		if err != nil {
			err = fmt.Errorf("initial probe anchor %s: %w", phase, err)
		}
	}()
	if _, _, e := s.OpenPrivateState(ctx); e != nil {
		return e
	}
	phase = "current-guard"
	until, e := s.current(ctx)
	if e != nil {
		return e
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	phase = "original-scope"
	root, _, e := s.originalPrivateScope(ctx)
	if e != nil {
		return e
	}
	phase = "read-private-state"
	secret, state, e := s.readPrivate(ctx)
	if e != nil || state.RootUID != root.RootUID {
		return cfg.ErrChanged
	}
	fresh := false
	if state.Probe == nil {
		id, e := prepUUID()
		if e != nil {
			return e
		}
		next := state
		next.Probe = &contracts.InitialPreparationProbe{AnchorOperationID: id}
		phase = "persist-anchor-intent"
		if e = s.writePrivate(ctx, secret, state, next, until); e != nil {
			return e
		}
		state = next
		fresh = true
		secret, state, e = s.readPrivate(ctx)
		if e != nil {
			return e
		}
	}
	if fresh {
		if e = s.finish(ctx, until); e != nil {
			return e
		}
		anchor := core.Secret{TypeMeta: meta.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: meta.ObjectMeta{Name: s.probeAnchorName(), Namespace: s.plan.Workload.Namespace}, Type: core.SecretTypeOpaque, Immutable: ptr.To(true)}
		s.creator.stamp(&anchor.ObjectMeta)
		anchor.Annotations[initialPreparationOperationAnnotation] = state.Probe.AnchorOperationID
		phase = "create-anchor"
		raw, e := s.postPreparationSecret(ctx, "/api/v1/namespaces/"+s.plan.Workload.Namespace+"/secrets", &anchor)
		if e == nil {
			s.keepSecretCreateResponse(state.Probe.AnchorOperationID, raw, &anchor, until)
		}
		clear(raw)
		if e == cfg.ErrDenied {
			return e
		}
	}
	phase = "read-anchor"
	receipt, e := s.readProbeAnchor(ctx, *state.Probe)
	if e != nil {
		return e
	}
	if state.Probe.Anchor == nil {
		next := state
		p := *state.Probe
		p.Anchor = &receipt
		p.CreateClosed = s.secretCreateClosed(p.AnchorOperationID, contracts.WorkerObjectReference{Name: s.probeAnchorName(), UID: receipt.UID})
		next.Probe = &p
		phase = "persist-anchor-receipt"
		if e = s.writePrivate(ctx, secret, state, next, until); e != nil {
			return e
		}
	}
	phase = "final-current-guard"
	return s.finish(ctx, until)
}

func (s *InitialPreparer) reviewProbeToken(ctx context.Context, account contracts.WorkerObjectReference, p contracts.InitialPreparationProbe, r contracts.InitialPreparationProbeResponse) (err error) {
	phase := "input"
	defer func() {
		if err != nil {
			err = fmt.Errorf("probe review %s: %w", phase, err)
		}
	}()
	i := p.Issue
	if i == nil || p.Anchor == nil || i.Audience != s.plan.ProbeAudience || !contracts.ValidWorkerToken([]byte(r.Token)) || len(r.Token) > 8192 {
		return cfg.ErrChanged
	}
	token := []byte(r.Token)
	defer clear(token)
	body, e := json.Marshal(auth.TokenReview{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenReview"}, Spec: auth.TokenReviewSpec{Token: r.Token, Audiences: []string{i.Audience}}})
	if e != nil {
		return cfg.ErrInvalid
	}
	defer clear(body)
	phase = "online-authentication"
	raw, e := s.protection.observer.api.Post().AbsPath("/apis/authentication.k8s.io/v1/tokenreviews").MaxRetries(0).Body(body).DoRaw(ctx)
	defer clear(raw)
	var review auth.TokenReview
	if e != nil || strictGuardJSON(raw, &review) != nil || review.APIVersion != "authentication.k8s.io/v1" || review.Kind != "TokenReview" || !review.Status.Authenticated || review.Status.Error != "" || len(review.Status.Audiences) != 1 || review.Status.Audiences[0] != i.Audience || review.Status.User.Username != "system:serviceaccount:"+s.plan.Workload.Namespace+":"+account.Name || review.Status.User.UID != account.UID {
		return cfg.ErrUnavailable
	}
	// Only after online signature/audience authentication, inspect the immutable
	// private bound-Secret claims. TokenReview omits those from UserInfo.Extra.
	phase = "claim-syntax"
	parts := strings.Split(r.Token, ".")
	if len(parts) != 3 {
		return cfg.ErrChanged
	}
	payload, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	defer clear(payload)
	if e != nil || len(payload) > 8192 || base64.RawURLEncoding.EncodeToString(payload) != parts[1] || permissionJSON(payload, 8192, 256) != nil {
		return cfg.ErrChanged
	}
	var claims struct {
		Audience   []string `json:"aud"`
		Kubernetes struct {
			Namespace      string
			ServiceAccount contracts.WorkerObjectReference `json:"serviceaccount"`
			Secret         *contracts.WorkerObjectReference
			Pod, Node      any
		} `json:"kubernetes.io"`
	}
	// Standard JWT names differ from Go field names; use explicit finite fields.
	var standard struct {
		Exp int64 `json:"exp"`
		Iat int64 `json:"iat"`
	}
	phase = "bound-claims"
	if json.Unmarshal(payload, &claims) != nil || json.Unmarshal(payload, &standard) != nil || len(claims.Audience) != 1 || claims.Audience[0] != i.Audience || claims.Kubernetes.Namespace != s.plan.Workload.Namespace || claims.Kubernetes.ServiceAccount != account || claims.Kubernetes.Secret == nil || claims.Kubernetes.Secret.Name != s.probeAnchorName() || claims.Kubernetes.Secret.UID != p.Anchor.UID || claims.Kubernetes.Pod != nil || claims.Kubernetes.Node != nil {
		return cfg.ErrChanged
	}
	phase = "original-interval"
	issued, expiry := time.Unix(standard.Iat, 0).UTC(), time.Unix(standard.Exp, 0).UTC()
	if issued.Before(i.StartedAt.Truncate(time.Second)) || issued.After(i.Until) || !expiry.Equal(r.ExpiresAt) || !expiry.After(i.Until) || expiry.After(i.ExpiresBefore) || !s.protection.observer.now().Before(expiry) {
		return cfg.ErrChanged
	}
	phase = "live-anchor"
	if _, e = s.readProbeAnchor(ctx, p); e != nil {
		return e
	}
	return nil
}

func (s *InitialPreparer) retainedProbeResponse(id string) (contracts.InitialPreparationProbeResponse, bool) {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	r, ok := s.probeResponses[id]
	return r, ok
}
func (s *InitialPreparer) rememberProbeResponse(id string, r contracts.InitialPreparationProbeResponse) {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	if !s.requestClosed {
		if s.probeResponses == nil {
			s.probeResponses = map[string]contracts.InitialPreparationProbeResponse{}
		}
		s.probeResponses[id] = r
	}
}

// PrepareProbe submits at most one TokenRequest for the original claim. A later
// process can use the persisted verified response, never another issuance. The
// live owner may persist its retained positive response after a lost CAS reply.
func (s *InitialPreparer) PrepareProbe(ctx context.Context) (observation InitialPreparationProbeObservation, err error) {
	phase := "validate"
	defer func() {
		if err != nil {
			err = fmt.Errorf("initial probe %s: %w", phase, err)
		}
	}()
	var zero InitialPreparationProbeObservation
	if s == nil || s.plan.PrivateState == nil || ctx == nil {
		return zero, cfg.ErrInvalid
	}
	ctx, joined, e := s.ownPodRequest(ctx)
	if e != nil {
		return zero, e
	}
	defer joined()
	phase = "prepare-anchor"
	if e = s.prepareProbeAnchor(ctx); e != nil {
		return zero, e
	}
	phase = "current-guard"
	until, e := s.current(ctx)
	if e != nil {
		return zero, e
	}
	ctx, end := context.WithDeadline(ctx, until)
	defer end()
	phase = "original-scope"
	root, account, e := s.originalPrivateScope(ctx)
	if e != nil {
		return zero, e
	}
	phase = "read-private-state"
	secret, state, e := s.readPrivate(ctx)
	if e != nil || state.RootUID != root.RootUID || state.Probe == nil || state.Probe.Anchor == nil {
		return zero, cfg.ErrChanged
	}
	phase = "read-anchor"
	if _, e = s.readProbeAnchor(ctx, *state.Probe); e != nil {
		return zero, e
	}
	fresh := false
	if state.Probe.Issue == nil {
		id, e := prepUUID()
		if e != nil {
			return zero, e
		}
		now := s.protection.observer.now().UTC().Truncate(time.Microsecond)
		next := state
		p := *state.Probe
		p.Issue = &contracts.InitialPreparationProbeIssue{ID: id, Audience: s.plan.ProbeAudience, StartedAt: now, Until: until.UTC().Truncate(time.Microsecond), ExpiresBefore: now.Add(605 * time.Second)}
		next.Probe = &p
		phase = "persist-claim"
		if e = s.writePrivate(ctx, secret, state, next, until); e != nil {
			return zero, e
		}
		state = next
		fresh = true
		secret, state, e = s.readPrivate(ctx)
		if e != nil {
			return zero, e
		}
	}
	issue := state.Probe.Issue
	response, retained := s.retainedProbeResponse(issue.ID)
	if fresh {
		operation, stop := context.WithDeadline(ctx, issue.Until)
		request := auth.TokenRequest{TypeMeta: meta.TypeMeta{APIVersion: "authentication.k8s.io/v1", Kind: "TokenRequest"}, Spec: auth.TokenRequestSpec{Audiences: []string{issue.Audience}, ExpirationSeconds: ptr.To(int64(600)), BoundObjectRef: &auth.BoundObjectReference{APIVersion: "v1", Kind: "Secret", Name: s.probeAnchorName(), UID: types.UID(state.Probe.Anchor.UID)}}}
		phase = "token-request"
		raw, e := s.creator.post(operation, "/api/v1/namespaces/"+s.plan.Workload.Namespace+"/serviceaccounts/"+account.Name+"/token", &request)
		var result auth.TokenRequest
		if e != nil || strictGuardJSON(raw, &result) != nil || result.APIVersion != "authentication.k8s.io/v1" || result.Kind != "TokenRequest" {
			clear(raw)
			stop()
			return zero, cfg.ErrUnavailable
		}
		clear(raw)
		response = contracts.InitialPreparationProbeResponse{Token: result.Status.Token, ExpiresAt: result.Status.ExpirationTimestamp.Time.UTC()}
		phase = "initial-token-review"
		e = s.reviewProbeToken(operation, account, *state.Probe, response)
		if e != nil {
			stop()
			return zero, e
		}
		if operation.Err() != nil || !s.protection.observer.now().Before(issue.Until) {
			stop()
			return zero, cfg.ErrUnavailable
		}
		s.rememberProbeResponse(issue.ID, response)
		retained = true
		stop()
	}
	if issue.Response == nil {
		phase = "recover-response"
		if !retained {
			return zero, cfg.ErrUnavailable
		}
		phase = "retained-token-review"
		if e = s.reviewProbeToken(ctx, account, *state.Probe, response); e != nil {
			return zero, e
		}
		next := state
		p := *state.Probe
		i := *p.Issue
		phase = "persist-response"
		i.Response = &response
		p.Issue = &i
		next.Probe = &p
		if e = s.writePrivate(ctx, secret, state, next, until); e != nil {
			return zero, e
		}
		state = next
	}
	phase = "final-token-review"
	response = *state.Probe.Issue.Response
	if e = s.reviewProbeToken(ctx, account, *state.Probe, response); e != nil {
		return zero, e
	}
	until = identity.Earlier(until, response.ExpiresAt)
	phase = "final-current-guard"
	if e = s.finish(ctx, until); e != nil {
		return zero, e
	}
	return InitialPreparationProbeObservation{Token: []byte(response.Token), ExpiresAt: response.ExpiresAt, ValidUntil: until}, nil
}
