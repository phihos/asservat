package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// ADR-249: approval of sensitive acquisition plans. request_capture opens a
// review request (ApprovalRequired with the approval page); get_grant reads
// it for its eligible requester, current reviewer or pinned policy manager; list_reviews,
// decide_review and revoke_grant are the browser approval inbox, with
// step-up verified from the IdP's signed claims.

// ResultAccessInput is the canonical investigation-access request.
type ResultAccessInput struct {
	ActionIDs     []string  `json:"actionIds"`
	Operations    []string  `json:"operations"`
	ClientIDs     []string  `json:"clientIDs"`
	MaxArtifacts  int       `json:"maxArtifacts"`
	MaxBytes      int64     `json:"maxBytes"`
	MaxOperations int64     `json:"maxOperations"`
	NotAfter      time.Time `json:"notAfter"`
}

func (in *ResultAccessInput) access() *authorization.ResultAccess {
	if in == nil {
		return nil
	}
	return &authorization.ResultAccess{ActionIDs: slices.Clone(in.ActionIDs), Operations: slices.Clone(in.Operations), ClientIDs: slices.Clone(in.ClientIDs), MaxArtifacts: in.MaxArtifacts, MaxBytes: in.MaxBytes, MaxOperations: in.MaxOperations, NotAfter: in.NotAfter.UTC()}
}

// ContextResultAccessRequest submits a reviewed recorder preview with a
// result-access instruction; the concrete ContextInvestigation implements it.
type ContextResultAccessRequest interface {
	RequestWithResultAccess(context.Context, identities.CurrentIdentity, string, string, *authorization.ResultAccess) (value.Accepted, error)
}

// ApprovalFailure is the request_capture error of a plan awaiting review: it
// names the approval page and the responsible role.
type ApprovalFailure struct {
	Code            string `json:"code"`
	Message         string `json:"message"`
	Retryable       bool   `json:"retryable"`
	NavigationURI   string `json:"navigation_uri,omitempty"`
	ResponsibleRole string `json:"responsible_role,omitempty"`
}

func approvalFailure(err error, origin string) (ApprovalFailure, bool) {
	var pending authorization.ApprovalPendingError
	switch {
	case errors.As(err, &pending):
		return ApprovalFailure{"ApprovalRequired", "This plan needs an independent approval before anything is recorded. Approval request " + pending.GrantID + " is waiting for an approver of this workload (not you); after approval, submit the same preview again. Nothing was started or reserved.", true, origin + "/approvals/" + pending.GrantID, "approver"}, true
	case errors.Is(err, authorization.ErrApprovalRequired):
		return ApprovalFailure{"ApprovalRequired", "This plan needs an independent approval, which this service cannot record now. Nothing was started or reserved.", true, "", "administrator"}, true
	case errors.Is(err, authorization.ErrGrantDenied):
		return ApprovalFailure{"ApprovalDenied", "An approver denied this plan. Nothing was started. Review a new preview to ask again.", false, "", "approver"}, true
	case errors.Is(err, authorization.ErrGrantRevoked):
		return ApprovalFailure{"ApprovalRevoked", "The approval of this plan was revoked. Nothing was started. Review a new preview to ask again.", false, "", "approver"}, true
	case errors.Is(err, authorization.ErrGrantExpired):
		return ApprovalFailure{"ApprovalExpired", "The approval of this plan (or its review window) has ended. Review a new preview to ask again.", false, "", "approver"}, true
	case errors.Is(err, authorization.ErrGrantScope), errors.Is(err, authorization.ErrGrantPrincipal), errors.Is(err, authapp.ErrGrantConflict):
		return ApprovalFailure{"ReviewChanged", "The approval does not cover this exact plan, requester or result access. Review a new preview.", false, "", "maintainer"}, true
	case errors.Is(err, authorization.ErrGrantInvalid):
		return ApprovalFailure{"InvalidApprovalRequest", "The result access must select actions of this plan, download_artifact, one to four of your client IDs, finite counts and an end within eight hours.", false, "", "maintainer"}, true
	}
	return ApprovalFailure{}, false
}

// ApprovalRequiredBlocker is the preview blocker of a plan that needs an
// individual approval before any observation.
func approvalRequiredBlocker(a *recorderApprovalView) OperationBlocker {
	return OperationBlocker{Code: "ApprovalRequired", Message: "This plan needs an independent approval before anything is recorded (" + strings.Join(a.reasons, ", ") + "). Submitting it opens a review request for an approver of this workload; you cannot approve your own request.", ResponsibleRole: "approver", Retryable: true}
}

type recorderApprovalView struct{ reasons []string }

// GrantUseCase is the C-03 grant service.
type GrantUseCase interface {
	Get(context.Context, identities.CurrentIdentity, string) (authapp.GrantView, time.Time, error)
	List(context.Context, identities.CurrentIdentity, string, int) ([]authapp.GrantView, time.Time, error)
	Decide(context.Context, identities.CurrentIdentity, string, bool, string, string) (authorization.Grant, bool, error)
	Revoke(context.Context, identities.CurrentIdentity, string, int64, string) (authorization.Grant, bool, error)
}

// GrantOperations serves get_grant (browser and MCP) and the browser-only
// list_reviews, decide_review and revoke_grant through the audited path.
type GrantOperations struct {
	origin    string
	now       func() time.Time
	newID     func() string
	grants    GrantUseCase
	contracts *contracts.InvestigationContracts
}

func NewGrantOperations(origin string, now func() time.Time, newID func() string, grants GrantUseCase) (*GrantOperations, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || grants == nil || now == nil || newID == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &GrantOperations{origin: origin, now: now, newID: newID, grants: grants, contracts: wire}, nil
}

func (s *GrantOperations) PublicOrigin() string {
	if s == nil {
		return ""
	}
	return s.origin
}

func (s *GrantOperations) ToolNames() []string {
	return []string{"request_policy_grant", "get_grant", "list_reviews", "decide_review", "revoke_grant"}
}

func (s *GrantOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil || !slices.Contains(s.ToolNames(), name) {
		return contracts.InvestigationTool{}, false
	}
	return s.contracts.Tool(name)
}

// GrantOperationInput is the closed union of the four inputs.
type policyGrantRequestLimits struct {
	MaxExecutions     int64 `json:"max_executions"`
	MaxCollectedBytes int64 `json:"max_collected_bytes"`
	MaxObservedBytes  int64 `json:"max_observed_bytes"`
}
type policyGrantObservationInput struct {
	MaxSessionSeconds     int64 `json:"max_session_seconds"`
	MaxObservedBytes      int64 `json:"max_observed_bytes"`
	MaxBytesPerSecond     int64 `json:"max_bytes_per_second"`
	MaxConcurrentSessions int64 `json:"max_concurrent_sessions"`
	MaxObservedEvents     int64 `json:"max_observed_events,omitempty"`
}
type GrantOperationInput struct {
	PolicyName       string                       `json:"policy_name,omitempty"`
	PolicyUID        string                       `json:"policy_uid,omitempty"`
	LifetimeSeconds  int64                        `json:"lifetime_seconds,omitempty"`
	Limits           *policyGrantRequestLimits    `json:"limits,omitempty"`
	Observation      *policyGrantObservationInput `json:"observation_limits,omitempty"`
	GrantID          string                       `json:"grant_id,omitempty"`
	View             string                       `json:"view,omitempty"`
	Limit            int                          `json:"limit,omitempty"`
	Decision         string                       `json:"decision,omitempty"`
	Reason           string                       `json:"reason,omitempty"`
	ExpectedRevision int64                        `json:"expected_revision,omitempty"`
	IdempotencyKey   string                       `json:"idempotency_key,omitempty"`
}

type grantPrincipal struct {
	Issuer   string `json:"issuer"`
	Subject  string `json:"subject"`
	ClientID string `json:"client_id"`
}

func principalView(p identity.Principal) *grantPrincipal {
	return &grantPrincipal{p.Issuer, p.Subject, p.ClientID}
}

type grantTarget struct {
	ClusterID    string `json:"cluster_id"`
	Namespace    string `json:"namespace"`
	WorkloadKind string `json:"workload_kind"`
	WorkloadName string `json:"workload_name"`
	PodName      string `json:"pod_name,omitempty"`
	NamespaceUID string `json:"namespace_uid,omitempty"`
	WorkloadUID  string `json:"workload_uid,omitempty"`
}

type grantReason struct {
	ActionID string `json:"action_id"`
	Code     string `json:"code"`
}

type grantAction struct {
	ActionID           string   `json:"action_id"`
	Kind               string   `json:"kind"`
	ExecutionMode      string   `json:"execution_mode"`
	Before             string   `json:"before"`
	After              string   `json:"after"`
	Filter             string   `json:"filter,omitempty"`
	FilterDigest       string   `json:"filter_digest,omitempty"`
	FilterInstructions int      `json:"filter_instructions,omitempty"`
	MaxBytes           int64    `json:"max_bytes"`
	RingMaxBytes       int64    `json:"ring_max_bytes"`
	RingMaxAge         string   `json:"ring_max_age"`
	Sensitive          []string `json:"sensitive"`
}

type grantLimits struct {
	MaxSessionSeconds     int64 `json:"max_session_seconds"`
	MaxObservedBytes      int64 `json:"max_observed_bytes"`
	MaxBytesPerSecond     int64 `json:"max_bytes_per_second"`
	MaxConcurrentSessions int64 `json:"max_concurrent_sessions"`
}

type grantAuthentication struct {
	ACR             string    `json:"acr"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
}

type grantDecision struct {
	Decision       string               `json:"decision"`
	DecidedBy      *grantPrincipal      `json:"decided_by"`
	DecidedAt      time.Time            `json:"decided_at"`
	Reason         string               `json:"reason"`
	Authentication *grantAuthentication `json:"authentication_context,omitempty"`
}

type grantResultAccess struct {
	ActionIDs      []string  `json:"action_ids"`
	Operations     []string  `json:"operations"`
	ClientIDs      []string  `json:"client_ids"`
	MaxArtifacts   int       `json:"max_artifacts"`
	MaxBytes       int64     `json:"max_bytes"`
	MaxOperations  int64     `json:"max_operations"`
	NotAfter       time.Time `json:"not_after"`
	ArtifactsUsed  int       `json:"artifacts_used"`
	BytesUsed      int64     `json:"bytes_used"`
	OperationsUsed int64     `json:"operations_used"`
}

type grantPolicyData struct {
	UID                string          `json:"uid"`
	Executor           *grantPrincipal `json:"executor"`
	AuthorityIssuedAt  time.Time       `json:"authority_issued_at"`
	AuthorityNotAfter  time.Time       `json:"authority_not_after"`
	MaxExecutions      int64           `json:"max_executions"`
	MaxCollectedBytes  int64           `json:"max_collected_bytes"`
	MaxObservedBytes   int64           `json:"max_observed_bytes"`
	ExecutionsUsed     int64           `json:"executions_used"`
	CollectedBytesUsed int64           `json:"collected_bytes_used"`
	ObservedBytesUsed  int64           `json:"observed_bytes_used"`
}

// grantData is get_grant's reply; list rows omit actions and result access.
type grantData struct {
	GrantID                      string             `json:"grant_id"`
	Phase                        string             `json:"phase"`
	Revision                     int64              `json:"revision"`
	Kind                         string             `json:"kind"`
	Policy                       *grantPolicyData   `json:"policy,omitempty"`
	CaptureID                    string             `json:"capture_id,omitempty"`
	PreviewID                    string             `json:"preview_id,omitempty"`
	ExecutionDigest              string             `json:"execution_digest"`
	ReviewDigest                 string             `json:"review_digest"`
	Target                       grantTarget        `json:"target"`
	DataClass                    string             `json:"data_class"`
	Reasons                      []grantReason      `json:"reasons"`
	Actions                      []grantAction      `json:"actions,omitempty"`
	ObservationLimits            *grantLimits       `json:"observation_limits,omitempty"`
	RequestedBy                  *grantPrincipal    `json:"requested_by"`
	RequestedAt                  time.Time          `json:"requested_at"`
	ReviewUntil                  time.Time          `json:"review_until"`
	PreviewDeadline              *time.Time         `json:"preview_deadline,omitempty"`
	CaptureDeadlineRule          string             `json:"capture_deadline_rule"`
	CaptureWindowSeconds         int64              `json:"capture_window_seconds,omitempty"`
	LifetimeSeconds              int64              `json:"lifetime_seconds"`
	Decision                     *grantDecision     `json:"decision,omitempty"`
	NotAfter                     *time.Time         `json:"not_after,omitempty"`
	RevokedAt                    *time.Time         `json:"revoked_at,omitempty"`
	RevokedBy                    *grantPrincipal    `json:"revoked_by,omitempty"`
	ResultAccess                 *grantResultAccess `json:"result_access,omitempty"`
	RemainingBytes               *int64             `json:"remaining_bytes,omitempty"`
	CanResume                    *bool              `json:"can_resume,omitempty"`
	CanResolve                   *bool              `json:"can_resolve,omitempty"`
	ResumeRequiresOriginalClient *bool              `json:"resume_requires_original_client,omitempty"`
	CanDecide                    bool               `json:"can_decide"`
	CanRevoke                    bool               `json:"can_revoke"`
	NavigationURI                string             `json:"approval_navigation_uri"`
}

func digestText(d artifact.Digest) string { return hash(d) }

func (s *GrantOperations) view(v authapp.GrantView, caller identity.Principal, full bool, now time.Time) grantData {
	g, r := v.Grant, v.Review
	requester := g.Requester.Issuer == caller.Issuer && g.Requester.Subject == caller.Subject
	d := grantData{GrantID: g.ID, Phase: string(v.Phase), Revision: g.Revision, Kind: g.Kind, CaptureID: g.CaptureID, PreviewID: g.PreviewID, ExecutionDigest: digestText(g.ExecutionDigest), ReviewDigest: digestText(g.ReviewDigest),
		Target: grantTarget{ClusterID: g.Target.ClusterID, Namespace: r.Namespace, WorkloadKind: r.WorkloadKind, WorkloadName: r.WorkloadName, PodName: r.PodName}, DataClass: g.DataClass, Reasons: []grantReason{}, RequestedBy: principalView(g.Requester),
		RequestedAt: g.RequestedAt.UTC(), ReviewUntil: g.ReviewUntil.UTC(), CaptureDeadlineRule: "previewDeadline", LifetimeSeconds: int64(g.Lifetime / time.Second),
		CanDecide: v.Approver && v.Phase == authorization.GrantPending, CanRevoke: g.RevokedAt.IsZero() && (requester || v.Approver), NavigationURI: s.origin + "/approvals/" + g.ID}
	if g.Kind == authorization.GrantPolicy && g.Policy != nil {
		p := g.Policy
		d.Target.ClusterID, d.Target.NamespaceUID, d.Target.WorkloadUID, d.Target.PodName = p.Authority.ClusterID, p.Authority.NamespaceUID, p.Authority.WorkloadUID, ""
		d.Policy = &grantPolicyData{UID: p.Authority.PolicyUID, Executor: principalView(p.Authority.Executor), AuthorityIssuedAt: p.Authority.IssuedAt.UTC(), AuthorityNotAfter: p.Authority.NotAfter.UTC(), MaxExecutions: p.Limits.MaxExecutions, MaxCollectedBytes: p.Limits.MaxBytes, MaxObservedBytes: p.Limits.MaxObservedBytes, ExecutionsUsed: g.PolicySpend.Executions, CollectedBytesUsed: g.PolicySpend.CollectedBytes, ObservedBytesUsed: g.PolicySpend.ObservedBytes}
		end := g.PolicyNotAfter.UTC()
		d.NotAfter = &end
		d.CaptureDeadlineRule = "policyAuthority"
		d.CanRevoke = v.CanRevoke
	} else {
		deadline := r.Deadline.UTC()
		d.PreviewDeadline = &deadline
	}
	var timing struct {
		Timing string `json:"timing"`
	}
	if g.Kind == authorization.GrantAdHocCapture && json.Unmarshal(g.Scope, &timing) == nil && timing.Timing == "approvedAcceptance/v1" {
		d.CaptureDeadlineRule, d.CaptureWindowSeconds = "acceptanceWithinGrant", 300
	}
	for _, x := range g.Reasons {
		d.Reasons = append(d.Reasons, grantReason{x.ActionID, x.Code})
	}
	if l := r.ObservationLimits; l != nil {
		d.ObservationLimits = &grantLimits{l.MaxSessionSeconds, l.MaxObservedBytes, l.MaxBytesPerSecond, l.MaxConcurrentSessions}
	}
	if x := g.Decision; x != nil {
		decision := "denied"
		if x.Approved {
			decision = "approved"
		}
		d.Decision = &grantDecision{Decision: decision, DecidedBy: principalView(x.Approver), DecidedAt: x.DecidedAt.UTC(), Reason: x.Reason}
		if x.Approved {
			d.Decision.Authentication = &grantAuthentication{x.ACR, x.AuthenticatedAt.UTC()}
			end := g.ExpiresAt.UTC()
			d.NotAfter = &end
		}
	}
	if !g.RevokedAt.IsZero() {
		at := g.RevokedAt.UTC()
		d.RevokedAt, d.RevokedBy = &at, principalView(g.Revoker)
	}
	if !full {
		return d
	}
	d.CanResume, d.CanResolve, d.ResumeRequiresOriginalClient = &v.CanResume, &v.CanResolve, &v.ResumeRequiresOriginalClient
	for _, a := range r.Actions {
		x := grantAction{ActionID: a.ActionID, Kind: a.Kind, ExecutionMode: a.ExecutionMode, Before: a.Before, After: a.After, Filter: a.Filter, FilterInstructions: a.FilterInstructions, MaxBytes: a.MaxBytes, RingMaxBytes: a.RingMaxBytes, RingMaxAge: a.RingMaxAge, Sensitive: slices.Clone(a.Sensitive)}
		if x.Sensitive == nil {
			x.Sensitive = []string{}
		}
		if a.FilterDigest != (artifact.Digest{}) {
			x.FilterDigest = digestText(a.FilterDigest)
		}
		d.Actions = append(d.Actions, x)
	}
	if a := g.ResultAccess; a != nil {
		d.ResultAccess = &grantResultAccess{slices.Clone(a.ActionIDs), slices.Clone(a.Operations), slices.Clone(a.ClientIDs), a.MaxArtifacts, a.MaxBytes, a.MaxOperations, a.NotAfter.UTC(), g.Spent.Artifacts, g.Spent.Bytes, g.Spent.Operations}
		remaining := a.MaxBytes - g.Spent.Bytes
		d.RemainingBytes = &remaining
	}
	return d
}

type grantListData struct {
	Approvals []grantData `json:"approvals"`
}

type grantDecisionData struct {
	GrantID  string     `json:"grant_id"`
	Phase    string     `json:"phase"`
	Revision int64      `json:"revision"`
	NotAfter *time.Time `json:"not_after,omitempty"`
}

func publicGrantFailure(err error) OperationFailure {
	switch {
	case errors.Is(err, authorization.ErrGrantInvalid), errors.Is(err, authorization.ErrGrantScope):
		return OperationFailure{"InvalidApprovalRequest", "The selected approval period or limits do not fit this policy. Check its current limits and try again.", false}
	case errors.Is(err, authorization.ErrSelfApproval):
		return OperationFailure{"SelfApprovalRefused", "You requested this plan, so you cannot decide it, from any client. Another approver of this workload must review it.", false}
	case errors.Is(err, authorization.ErrStepUpRequired):
		return OperationFailure{"StepUpRequired", "Approving needs a recent step-up sign-in (for example multi-factor authentication) at your identity provider. Sign in again with step-up, then approve within the allowed time.", true}
	case errors.Is(err, authorization.ErrGrantNotPending):
		return OperationFailure{"ApprovalNotPending", "This request was already decided, withdrawn or its review window ended. Read it again for its current state.", false}
	case errors.Is(err, authorization.ErrGrantExpired):
		return OperationFailure{"ApprovalExpired", "This request or approval has ended.", false}
	case errors.Is(err, authorization.ErrGrantRevoked):
		return OperationFailure{"ApprovalRevoked", "This approval was already revoked.", false}
	case errors.Is(err, authapp.ErrGrantConflict):
		return OperationFailure{"Conflict", "The approval changed or this idempotency key was used for another request. Read it again and retry with its current revision or a new key.", false}
	case errors.Is(err, authorization.ErrGrantInvalid):
		return OperationFailure{"InvalidRequest", "The request is malformed.", false}
	case errors.Is(err, authorization.ErrNotApprover), errors.Is(err, authapp.ErrGrantNotFound), errors.Is(err, identity.ErrDenied), errors.Is(err, value.ErrDenied):
		// No existence disclosure: an unknown grant and one the caller may
		// not see are the same reply.
		return OperationFailure{"NotAvailable", "This approval is not available with your current access. Deciding needs the action-approver role for the workload; reading needs that role or being its requester.", false}
	}
	return OperationFailure{"NotAvailable", "The operation is unavailable. Check your access or retry when the service is available.", true}
}

func (s *GrantOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil {
		return OperationReply{}, ErrOperationsConfiguration
	}
	return s.CallWithContext(ctx, current, OperationCall{requestID: s.newID()}, name, raw)
}

func (s *GrantOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil || ctx == nil || current == nil {
		return OperationReply{}, value.ErrUnavailable
	}
	if err := s.contracts.ValidateInput(name, raw); err != nil {
		return OperationReply{}, err
	}
	var in GrantOperationInput
	if json.Unmarshal(raw, &in) != nil {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.now()) || !slices.Contains(i.Scopes, "evidence:read") {
		return OperationReply{}, identity.ErrDenied
	}
	if !authorization.UUID(call.requestID) {
		return OperationReply{}, value.ErrUnavailable
	}
	out := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: call.requestID, DataClass: "metadata", Status: "ok", Warnings: []string{}, Provenance: []any{}}
	until := i.ValidUntil
	var operationErr error
	switch name {
	case "request_policy_grant":
		requester, ok := s.grants.(interface {
			RequestPolicy(context.Context, identities.CurrentIdentity, authapp.PolicyGrantRequestInput) (authorization.Grant, bool, error)
		})
		if !ok || in.Limits == nil || !slices.Contains(i.Scopes, "evidence:capture") {
			operationErr = authapp.ErrGrantUnavailable
			break
		}
		request := authapp.PolicyGrantRequestInput{PolicyUID: in.PolicyUID, PolicyName: in.PolicyName, IdempotencyKey: in.IdempotencyKey, Lifetime: time.Duration(in.LifetimeSeconds) * time.Second, Limits: authorization.AutomationLimits{MaxExecutions: in.Limits.MaxExecutions, MaxBytes: in.Limits.MaxCollectedBytes, MaxObservedBytes: in.Limits.MaxObservedBytes}}
		if in.Observation != nil {
			o := in.Observation
			request.Observation = &authorization.ObservationLimits{MaxSessionSeconds: o.MaxSessionSeconds, MaxObservedBytes: o.MaxObservedBytes, MaxBytesPerSecond: o.MaxBytesPerSecond, MaxConcurrentSessions: o.MaxConcurrentSessions, MaxObservedEvents: o.MaxObservedEvents}
		}
		var g authorization.Grant
		if g, _, operationErr = requester.RequestPolicy(ctx, current, request); operationErr == nil {
			var v authapp.GrantView
			var valid time.Time
			if v, valid, operationErr = s.grants.Get(ctx, current, g.ID); operationErr == nil {
				until = identity.Earlier(until, valid)
				out.Data = s.view(v, i.Principal, true, s.now())
			}
		}
	case "get_grant":
		var v authapp.GrantView
		var valid time.Time
		if v, valid, operationErr = s.grants.Get(ctx, current, in.GrantID); operationErr == nil {
			until = identity.Earlier(until, valid)
			out.Data = s.view(v, i.Principal, true, s.now())
		}
	case "list_reviews":
		limit := in.Limit
		if limit == 0 {
			limit = 20
		}
		var views []authapp.GrantView
		var valid time.Time
		if views, valid, operationErr = s.grants.List(ctx, current, in.View, limit); operationErr == nil {
			until = identity.Earlier(until, valid)
			data := grantListData{Approvals: []grantData{}}
			for _, v := range views {
				data.Approvals = append(data.Approvals, s.view(v, i.Principal, false, s.now()))
			}
			out.Data = data
		}
	case "decide_review":
		var g authorization.Grant
		if g, _, operationErr = s.grants.Decide(ctx, current, in.GrantID, in.Decision == "approve", in.Reason, in.IdempotencyKey); operationErr == nil {
			d := grantDecisionData{GrantID: g.ID, Phase: string(g.Phase(s.now())), Revision: g.Revision}
			if !g.ExpiresAt.IsZero() {
				end := g.ExpiresAt.UTC()
				d.NotAfter = &end
			}
			out.Data = d
		}
	case "revoke_grant":
		var g authorization.Grant
		if g, _, operationErr = s.grants.Revoke(ctx, current, in.GrantID, in.ExpectedRevision, in.IdempotencyKey); operationErr == nil {
			out.Data = grantDecisionData{GrantID: g.ID, Phase: string(authorization.GrantRevoked), Revision: g.Revision}
		}
	default:
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	if operationErr != nil {
		out.Status, out.Data = "error", publicGrantFailure(operationErr)
	}
	final, err := current.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil || !final.Valid(s.now()) || final.Principal != i.Principal {
		return OperationReply{}, identity.ErrDenied
	}
	until = identity.Earlier(until, final.ValidUntil)
	b, err := json.Marshal(out)
	if err != nil || s.contracts.ValidateOutput(name, b) != nil {
		return OperationReply{}, value.ErrUnavailable
	}
	if !s.now().Before(until) || ctx.Err() != nil {
		clear(b)
		return OperationReply{}, value.ErrUnavailable
	}
	// Self-approval cannot have an accepted prior attempt: the immutable
	// requester is forbidden to decide through every client. This definite
	// refusal differs from an unavailable/withdrawn-rights retry whose earlier
	// logical mutation may already have committed.
	noDispatch := name == "decide_review" && errors.Is(operationErr, authorization.ErrSelfApproval)
	return OperationReply{Body: b, ValidUntil: until, auditDecision: grantAuditDecision(operationErr), auditNoDispatch: noDispatch}, nil
}

func grantAuditDecision(err error) operationAuditDecision {
	switch {
	case errors.Is(err, authorization.ErrSelfApproval), errors.Is(err, authorization.ErrStepUpRequired), errors.Is(err, authorization.ErrNotApprover), errors.Is(err, identity.ErrDenied), errors.Is(err, value.ErrDenied):
		return operationAuditDenied
	case errors.Is(err, authorization.ErrGrantInvalid):
		return operationAuditInvalid
	}
	return operationAuditUnspecified
}
