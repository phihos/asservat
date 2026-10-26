package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"time"

	app "asservat.local/asservat/internal/application/capture"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// PolicyActivationUseCase and PolicyStatusUseCase are the ADR-228 services.
type PolicyActivationUseCase interface {
	Activate(context.Context, identities.CurrentIdentity, string, string) (app.PolicyActivationResult, error)
}
type PolicyStatusUseCase interface {
	Get(context.Context, identities.CurrentIdentity, string) (value.PolicyStatus, time.Time, error)
}
type PolicyDeactivationUseCase interface {
	Deactivate(context.Context, identities.CurrentIdentity, string) (app.PolicyDeactivationResult, error)
}

// PolicyOperations serves activate_policy, get_policy_status and
// deactivate_policy to MCP and the browser through the same audited
// operation path.
type PolicyOperations struct {
	origin     string
	now        func() time.Time
	newID      func() string
	activation PolicyActivationUseCase
	status     PolicyStatusUseCase
	stop       PolicyDeactivationUseCase
	contracts  *contracts.InvestigationContracts
}

func NewPolicyOperations(origin string, now func() time.Time, newID func() string, activation PolicyActivationUseCase, status PolicyStatusUseCase, stop PolicyDeactivationUseCase) (*PolicyOperations, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || activation == nil || status == nil || stop == nil || now == nil || newID == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &PolicyOperations{origin: origin, now: now, newID: newID, activation: activation, status: status, stop: stop, contracts: wire}, nil
}

func (s *PolicyOperations) PublicOrigin() string {
	if s == nil {
		return ""
	}
	return s.origin
}
func (s *PolicyOperations) ToolNames() []string {
	return []string{"activate_policy", "deactivate_policy", "get_policy_status"}
}
func (s *PolicyOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil || !slices.Contains(s.ToolNames(), name) {
		return contracts.InvestigationTool{}, false
	}
	return s.contracts.Tool(name)
}

// PolicyOperationInput is the closed input of the policy operations.
type PolicyOperationInput struct {
	PolicyName     string `json:"policy_name"`
	IdempotencyKey string `json:"idempotency_key,omitempty"`
}

type policyActivationData struct {
	PolicyUID     string    `json:"policy_uid"`
	AcceptanceID  string    `json:"acceptance_id"`
	State         string    `json:"state"`
	ExpiresAt     time.Time `json:"expires_at"`
	MaxExecutions int64     `json:"max_executions"`
	Replay        bool      `json:"replay"`
}
type policyDeactivationData struct {
	PolicyUID    string `json:"policy_uid"`
	AcceptanceID string `json:"acceptance_id"`
	State        string `json:"state"`
	Replay       bool   `json:"replay"`
}
type policyExecutor struct {
	Kind      string `json:"kind"`
	PolicyUID string `json:"policy_uid"`
}

// policyOccurrenceData is one recent occurrence: an exit occurrence's restart
// count, or a probe occurrence's newest failure time (ADR-230) or an alert
// occurrence's newest alert start (ADR-231), both as failed_at.
type policyOccurrenceData struct {
	OccurrenceID string     `json:"occurrence_id"`
	CaptureID    string     `json:"capture_id,omitempty"`
	Outcome      string     `json:"outcome"`
	Detector     string     `json:"detector"`
	Restarts     int64      `json:"restarts,omitempty"`
	FailedAt     *time.Time `json:"failed_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}
type policyDetectorData struct {
	Kind            string   `json:"kind"`
	Reasons         []string `json:"reasons,omitempty"`
	ExitCodes       []int32  `json:"exit_codes,omitempty"`
	ProbeType       string   `json:"probe_type,omitempty"`
	MinimumFailures int      `json:"minimum_failures,omitempty"`
	WindowSeconds   int64    `json:"window_seconds,omitempty"`
}
type policySuppressionData struct {
	Reason  string    `json:"reason"`
	Count   int64     `json:"count"`
	FirstAt time.Time `json:"first_at"`
	LastAt  time.Time `json:"last_at"`
}
type policyStatusData struct {
	PolicyUID       string                  `json:"policy_uid"`
	AcceptanceID    string                  `json:"acceptance_id"`
	State           string                  `json:"state"`
	Generation      int64                   `json:"generation"`
	ExpiresAt       time.Time               `json:"expires_at"`
	Executor        policyExecutor          `json:"executor"`
	ExecutionsSpent int64                   `json:"executions_spent"`
	MaxExecutions   int64                   `json:"max_executions"`
	WatchedPods     int64                   `json:"watched_pods"`
	Occurrences     int64                   `json:"occurrences"`
	Captured        int64                   `json:"captured"`
	Recent          []policyOccurrenceData  `json:"recent"`
	Suppressions    []policySuppressionData `json:"suppressions"`
	Detector        *policyDetectorData     `json:"detector,omitempty"`
}

func publicPolicyFailure(err error) OperationFailure {
	var field value.PolicyFieldError
	switch {
	case errors.As(err, &field):
		// Fixed reviewed reasons with a field path; never a user-authored value.
		return OperationFailure{"PolicyRejected", "This release cannot activate the policy: " + field.Error() + ".", false}
	case errors.Is(err, app.ErrPolicyDeactivated):
		return OperationFailure{"PolicyDeactivated", "This policy revision was deactivated and cannot be activated again, so its spend and expiry are never reset. Change the DebugPolicy to activate a new revision.", false}
	case errors.Is(err, app.ErrPolicyDelegation):
		return OperationFailure{"DelegationRequired", "No sole automation AccessBinding covers this workload for one of your groups, or its envelope does not allow pod-status snapshots. Ask a permission administrator to add spec.automation to the team's AccessBinding.", false}
	case errors.Is(err, value.ErrCapacity):
		return OperationFailure{"CapacityUnavailable", "The workload cluster already has the maximum number of active policies.", false}
	case errors.Is(err, value.ErrConflict):
		return OperationFailure{"Conflict", "This request conflicts with a newer activation of the policy. Check its status and retry.", false}
	case errors.Is(err, value.ErrChanged):
		return OperationFailure{"PolicySuspended", "The policy is suspended or being deleted and cannot be activated.", false}
	case errors.Is(err, value.ErrDenied), errors.Is(err, identity.ErrDenied):
		return OperationFailure{"NotAvailable", "This operation is not available with your current access.", false}
	case errors.Is(err, value.ErrInvalid):
		return OperationFailure{"UnsupportedRequest", "The named policy is not a valid restart-, probe- or alert-trigger DebugPolicy.", false}
	case errors.Is(err, targets.ErrUnsupported):
		return OperationFailure{"DetectorUnavailable", "The workload cluster's connector cannot observe this detector. An alert policy needs the cluster's Alertmanager address (Helm value cluster.alertmanager).", false}
	}
	return OperationFailure{"NotAvailable", "The operation is unavailable. Check your access or retry when the service is available.", true}
}

func (s *PolicyOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil {
		return OperationReply{}, ErrOperationsConfiguration
	}
	return s.CallWithContext(ctx, current, OperationCall{requestID: s.newID()}, name, raw)
}

func (s *PolicyOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil || ctx == nil || current == nil {
		return OperationReply{}, value.ErrUnavailable
	}
	if err := s.contracts.ValidateInput(name, raw); err != nil {
		return OperationReply{}, err
	}
	var in PolicyOperationInput
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
	noDispatch := false
	switch name {
	case "activate_policy":
		if !slices.Contains(i.Scopes, "evidence:capture") {
			noDispatch, operationErr = true, value.ErrDenied
			break
		}
		var r app.PolicyActivationResult
		r, operationErr = s.activation.Activate(ctx, current, in.PolicyName, in.IdempotencyKey)
		if operationErr == nil {
			state := "active"
			if !r.Audited {
				state = "pendingAudit"
			}
			out.Data = policyActivationData{PolicyUID: r.PolicyUID, AcceptanceID: r.AcceptanceID, State: state, ExpiresAt: r.NotAfter.UTC(), MaxExecutions: r.MaxExecutions, Replay: r.Replay}
		}
	case "deactivate_policy":
		if !slices.Contains(i.Scopes, "evidence:capture") {
			noDispatch, operationErr = true, value.ErrDenied
			break
		}
		var r app.PolicyDeactivationResult
		r, operationErr = s.stop.Deactivate(ctx, current, in.PolicyName)
		if operationErr == nil {
			out.Data = policyDeactivationData{PolicyUID: r.PolicyUID, AcceptanceID: r.AcceptanceID, State: "deactivated", Replay: r.Replay}
		}
	case "get_policy_status":
		var st value.PolicyStatus
		var valid time.Time
		st, valid, operationErr = s.status.Get(ctx, current, in.PolicyName)
		if operationErr == nil {
			until = identity.Earlier(until, valid)
			acceptance := st.ActiveID
			if acceptance == "" {
				acceptance = st.DeactivatedID
			}
			data := policyStatusData{PolicyUID: st.PolicyUID, AcceptanceID: acceptance, State: policyState(st, s.now()), Generation: st.Generation, ExpiresAt: st.NotAfter.UTC(), Executor: policyExecutor{"policy", st.PolicyUID}, ExecutionsSpent: st.ExecutionsSpent, MaxExecutions: st.MaxExecutions, WatchedPods: st.WatchedPods, Occurrences: st.Occurrences, Captured: st.Captured, Recent: []policyOccurrenceData{}, Suppressions: []policySuppressionData{}}
			for _, o := range st.Recent {
				outcome := o.Outcome
				if outcome == "" {
					outcome = "pending"
				}
				item := policyOccurrenceData{OccurrenceID: o.ID, CaptureID: o.CaptureID, Outcome: outcome, Detector: o.Detector, Restarts: o.Restarts, CreatedAt: o.CreatedAt.UTC()}
				if o.Detector == value.DetectorProbe || o.Detector == value.DetectorAlert {
					failed := time.Unix(o.Restarts, 0).UTC()
					item.Restarts, item.FailedAt = 0, &failed
				}
				data.Recent = append(data.Recent, item)
			}
			if d := st.Detector; d != nil {
				data.Detector = &policyDetectorData{Kind: d.Kind, Reasons: d.Reasons, ExitCodes: d.ExitCodes, ProbeType: d.ProbeType, MinimumFailures: d.MinimumFailures, WindowSeconds: d.WindowSeconds}
			}
			for _, x := range st.Suppressions {
				data.Suppressions = append(data.Suppressions, policySuppressionData{Reason: x.Reason, Count: x.Count, FirstAt: x.FirstAt.UTC(), LastAt: x.LastAt.UTC()})
			}
			out.Data = data
		}
	default:
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	if operationErr != nil {
		out.Status, out.Data = "error", publicPolicyFailure(operationErr)
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
	return OperationReply{Body: b, ValidUntil: until, auditDecision: captureAuditDecision(operationErr), auditNoDispatch: noDispatch}, nil
}

func policyState(st value.PolicyStatus, now time.Time) string {
	switch {
	case st.Deleted:
		return "deleted"
	case st.ActiveID == "" && st.Generation != st.AcceptedGeneration:
		// Deactivated, but the DebugPolicy has a new revision to activate.
		return "changed"
	case st.ActiveID == "":
		return "deactivated"
	case st.Suspended:
		return "suspended"
	case st.AcceptedIntentVersion != st.IntentVersion:
		return "changed"
	case !now.Before(st.NotAfter):
		return "expired"
	}
	return "active"
}
