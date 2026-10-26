package presentation

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// AccessExplanationUseCase is the ADR-234 caller-only explanation service.
type AccessExplanationUseCase interface {
	Explain(context.Context, identities.CurrentIdentity, targets.WorkloadRequest, authorization.Operation) (authorization.Explanation, time.Time, error)
}

// AccessOperations serves explain_access to MCP and the browser through the
// same audited operation path as every other investigation operation.
type AccessOperations struct {
	origin    string
	now       func() time.Time
	newID     func() string
	explain   AccessExplanationUseCase
	contracts *contracts.InvestigationContracts
}

func NewAccessOperations(origin string, now func() time.Time, newID func() string, explain AccessExplanationUseCase) (*AccessOperations, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || explain == nil || now == nil || newID == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &AccessOperations{origin: origin, now: now, newID: newID, explain: explain, contracts: wire}, nil
}

func (s *AccessOperations) PublicOrigin() string {
	if s == nil {
		return ""
	}
	return s.origin
}
func (s *AccessOperations) ToolNames() []string { return []string{"explain_access"} }
func (s *AccessOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil || name != "explain_access" {
		return contracts.InvestigationTool{}, false
	}
	return s.contracts.Tool(name)
}

// AccessOperationInput is the closed explain_access input.
type AccessOperationInput struct {
	TargetRef struct {
		ClusterID string `json:"cluster_id"`
		Namespace string `json:"namespace"`
		Kind      string `json:"kind"`
		Name      string `json:"name"`
	} `json:"target_ref"`
	Operation string `json:"operation"`
}

var accessOperations = map[string]authorization.Operation{"capture": authorization.CollectContext, "read": authorization.ReadApproved, "download": authorization.DownloadApproved}

type accessTargetData struct {
	ClusterID    string `json:"cluster_id"`
	NamespaceUID string `json:"namespace_uid"`
	WorkloadUID  string `json:"workload_uid"`
	PodUID       string `json:"pod_uid"`
}
type accessAssignmentData struct {
	Effect       string `json:"effect"`
	AssignmentID string `json:"assignment_id"`
	Role         string `json:"role"`
	SubjectKind  string `json:"subject_kind"`
	BasisKind    string `json:"basis_kind"`
	BasisUID     string `json:"basis_uid"`
	Revision     string `json:"revision"`
}
type accessExplanationData struct {
	Decision         string                 `json:"decision"`
	Operation        string                 `json:"operation"`
	Unmet            string                 `json:"unmet,omitempty"`
	MissingScope     string                 `json:"missing_scope,omitempty"`
	RequiredRoles    []string               `json:"required_roles"`
	Message          string                 `json:"message"`
	Target           *accessTargetData      `json:"target,omitempty"`
	Assignments      []accessAssignmentData `json:"assignments"`
	AssignmentsTotal int                    `json:"assignments_total"`
	ValidUntil       *time.Time             `json:"valid_until,omitempty"`
}

// accessMessage is fixed reviewed text per condition; it never includes a
// caller-supplied or Kubernetes-supplied value.
func accessMessage(e authorization.Explanation) string {
	switch e.Unmet {
	case "":
		return "You currently have this access through the listed assignments. It is re-evaluated on every request."
	case authorization.UnmetExplicitDeny:
		return "A deny assignment that names you (directly or through one of your groups) blocks this operation. Ask a permission administrator to review the listed deny."
	case authorization.UnmetClientScope:
		return "Your client was not granted the listed scope. Sign in again with a client that requests it, or ask an administrator to allow it for this client."
	case authorization.UnmetPermissionStale:
		return "Permission data for this workload is not current, so the result cannot be decided now. Retry shortly; if it persists, ask an administrator to check permission observation."
	case authorization.UnmetIdentity:
		return "Your identity could not be confirmed as current. Sign in again and retry."
	case authorization.UnmetAudienceOverflow:
		return "More than 32 assignments would form the audience for this operation. Ask a permission administrator to narrow the bindings for this workload."
	case authorization.UnmetServiceUnavailable:
		return "The service cannot evaluate access right now. Retry shortly."
	}
	if e.Disclosed {
		return "None of your assignments on this workload grants this operation. It needs one of the listed roles."
	}
	return "No current assignment of yours grants this operation on this workload, or the workload does not exist or cannot be observed now. It needs one of the listed roles."
}

func (s *AccessOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil {
		return OperationReply{}, ErrOperationsConfiguration
	}
	return s.CallWithContext(ctx, current, OperationCall{requestID: s.newID()}, name, raw)
}

func (s *AccessOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil || ctx == nil || current == nil {
		return OperationReply{}, value.ErrUnavailable
	}
	if name != "explain_access" {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	if err := s.contracts.ValidateInput(name, raw); err != nil {
		return OperationReply{}, err
	}
	var in AccessOperationInput
	if json.Unmarshal(raw, &in) != nil {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	op, ok := accessOperations[in.Operation]
	if !ok || !authorization.UUID(call.requestID) {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	// No scope is required: explaining a missing scope is part of the answer,
	// and the explanation covers only the caller's own assignments.
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.now()) {
		return OperationReply{}, identity.ErrDenied
	}
	ref := targets.WorkloadRequest{ClusterID: in.TargetRef.ClusterID, Namespace: in.TargetRef.Namespace, Kind: in.TargetRef.Kind, Name: in.TargetRef.Name}
	e, until, err := s.explain.Explain(ctx, current, ref, op)
	if errors.Is(err, authorization.ErrExplainInvalid) {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	if err != nil {
		return OperationReply{}, identity.ErrDenied
	}
	data := accessExplanationData{Decision: string(e.Decision), Operation: in.Operation, Unmet: e.Unmet, MissingScope: e.MissingScope, RequiredRoles: authorization.RequiredRoles(op), Message: accessMessage(e), Assignments: []accessAssignmentData{}, AssignmentsTotal: len(e.Assignments)}
	if e.Disclosed {
		data.Target = &accessTargetData{ClusterID: e.Target.ClusterID, NamespaceUID: e.Target.NamespaceUID, WorkloadUID: e.Target.WorkloadUID, PodUID: e.Target.PodUID}
	}
	for _, a := range e.Assignments {
		if len(data.Assignments) == 32 {
			break
		}
		x := a.Assignment
		data.Assignments = append(data.Assignments, accessAssignmentData{Effect: a.Effect, AssignmentID: x.AssignmentID, Role: x.Role, SubjectKind: x.Kind, BasisKind: x.BasisKind, BasisUID: x.BasisUID, Revision: hex.EncodeToString(x.BasisDigest[:])})
	}
	if e.Decision == authorization.Allow {
		v := e.ValidUntil.UTC()
		data.ValidUntil = &v
		until = identity.Earlier(until, e.ValidUntil)
	}
	out := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: call.requestID, DataClass: "metadata", Status: "ok", Data: data, Warnings: []string{}, Provenance: []any{}}
	final, err := current.ResolveIdentity(ctx)
	if err != nil || ctx.Err() != nil || !final.Valid(s.now()) || final.Principal != i.Principal {
		return OperationReply{}, identity.ErrDenied
	}
	until = identity.Earlier(identity.Earlier(until, i.ValidUntil), final.ValidUntil)
	b, err := json.Marshal(out)
	if err != nil || s.contracts.ValidateOutput(name, b) != nil {
		return OperationReply{}, value.ErrUnavailable
	}
	if !s.now().Before(until) || ctx.Err() != nil {
		clear(b)
		return OperationReply{}, value.ErrUnavailable
	}
	return OperationReply{Body: b, ValidUntil: until, auditDecision: captureAuditDecision(nil)}, nil
}
