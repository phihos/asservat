package presentation

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/sharing"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// ShareUseCase is the ADR-232 share service.
type ShareUseCase interface {
	Create(context.Context, identities.CurrentIdentity, sharing.CreateInput) (authorization.Share, bool, error)
	List(context.Context, identities.CurrentIdentity, string, int) ([]sharing.View, time.Time, error)
	Revoke(context.Context, identities.CurrentIdentity, string, int64, string) (authorization.Share, bool, error)
}

// ShareOperations serves create_share, list_shares and revoke_share to MCP
// (and the browser operation route) through the same audited path.
type ShareOperations struct {
	origin    string
	now       func() time.Time
	newID     func() string
	shares    ShareUseCase
	contracts *contracts.InvestigationContracts
}

func NewShareOperations(origin string, now func() time.Time, newID func() string, shares ShareUseCase) (*ShareOperations, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || shares == nil || now == nil || newID == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &ShareOperations{origin: origin, now: now, newID: newID, shares: shares, contracts: wire}, nil
}

func (s *ShareOperations) PublicOrigin() string {
	if s == nil {
		return ""
	}
	return s.origin
}
func (s *ShareOperations) ToolNames() []string {
	return []string{"create_share", "list_shares", "revoke_share"}
}
func (s *ShareOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil || !slices.Contains(s.ToolNames(), name) {
		return contracts.InvestigationTool{}, false
	}
	return s.contracts.Tool(name)
}

type shareRecipientInput struct {
	Kind   string `json:"kind"`
	Issuer string `json:"issuer"`
	ID     string `json:"id"`
}
type shareArtifactInput struct {
	ArtifactID string `json:"artifactID"`
	Digest     string `json:"digest"`
}

// ShareOperationInput is the closed union of the three implemented inputs;
// each tool's schema admits only its own fields.
type ShareOperationInput struct {
	CaseID           string                `json:"case_id,omitempty"`
	Artifacts        []shareArtifactInput  `json:"artifacts,omitempty"`
	Recipients       []shareRecipientInput `json:"recipients,omitempty"`
	DataClasses      []string              `json:"data_classes,omitempty"`
	Operations       []string              `json:"operations,omitempty"`
	ExpiresAt        *time.Time            `json:"expires_at,omitempty"`
	Reason           string                `json:"reason,omitempty"`
	View             string                `json:"view,omitempty"`
	Limit            int                   `json:"limit,omitempty"`
	ShareID          string                `json:"share_id,omitempty"`
	ExpectedRevision int64                 `json:"expected_revision,omitempty"`
	IdempotencyKey   string                `json:"idempotency_key,omitempty"`
}

type shareCreateData struct {
	ShareID string `json:"share_id"`
	Phase   string `json:"phase"`
}
type shareListItem struct {
	ShareID   string    `json:"share_id"`
	CaseID    string    `json:"case_id"`
	Phase     string    `json:"phase"`
	ExpiresAt time.Time `json:"expires_at"`
}
type shareListData struct {
	Shares []shareListItem `json:"shares"`
}
type shareRevokeData struct {
	ShareID  string `json:"share_id"`
	Phase    string `json:"phase"`
	Revision int64  `json:"revision"`
}

func publicShareFailure(err error) OperationFailure {
	switch {
	case errors.Is(err, value.ErrInvalid):
		return OperationFailure{"InvalidShare", "Recipients must be stable user or group IDs of your identity provider (at most eight), and the expiry must be in the future and at most seven days away.", false}
	case errors.Is(err, value.ErrChanged):
		return OperationFailure{"ArtifactChanged", "The artifact digest does not match the current verified artifact. Read the case again and share the version you reviewed.", false}
	case errors.Is(err, value.ErrCapacity):
		return OperationFailure{"ShareLimit", "This artifact already has the maximum number of active shares (32). Revoke one first.", false}
	case errors.Is(err, value.ErrConflict):
		return OperationFailure{"Conflict", "The share changed or this idempotency key was used for another request. List your shares and retry with the current revision or a new key.", false}
	case errors.Is(err, value.ErrDenied), errors.Is(err, identity.ErrDenied):
		return OperationFailure{"NotAvailable", "This operation is not available with your current access. Sharing needs the evidence-owner role on the workload and the evidence:share scope.", false}
	}
	return OperationFailure{"NotAvailable", "The operation is unavailable. Check your access or retry when the service is available.", true}
}

func (s *ShareOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil {
		return OperationReply{}, ErrOperationsConfiguration
	}
	return s.CallWithContext(ctx, current, OperationCall{requestID: s.newID()}, name, raw)
}

func (s *ShareOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil || ctx == nil || current == nil {
		return OperationReply{}, value.ErrUnavailable
	}
	if err := s.contracts.ValidateInput(name, raw); err != nil {
		return OperationReply{}, err
	}
	var in ShareOperationInput
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
	// Creating and revoking need the evidence:share scope before dispatch;
	// listing received shares needs only evidence:read.
	if (name == "create_share" || name == "revoke_share" || name == "list_shares" && in.View == "owned") && !slices.Contains(i.Scopes, authorization.ShareScope) {
		noDispatch, operationErr = true, value.ErrDenied
	} else {
		switch name {
		case "create_share":
			var version artifact.Digest
			b, e := hex.DecodeString(in.Artifacts[0].Digest)
			if e != nil || len(b) != len(version) {
				return OperationReply{}, contracts.ErrInvestigationWire
			}
			copy(version[:], b)
			input := sharing.CreateInput{CaseID: in.CaseID, ArtifactID: in.Artifacts[0].ArtifactID, Version: version, Reason: in.Reason, IdempotencyKey: in.IdempotencyKey}
			if in.ExpiresAt != nil {
				input.ExpiresAt = in.ExpiresAt.UTC()
			}
			for _, r := range in.Recipients {
				input.Recipients = append(input.Recipients, authorization.ShareRecipient{Kind: r.Kind, Issuer: r.Issuer, ID: r.ID})
			}
			var share authorization.Share
			share, _, operationErr = s.shares.Create(ctx, current, input)
			if operationErr == nil {
				out.Data = shareCreateData{ShareID: share.ID, Phase: string(authorization.ShareActive)}
			}
		case "list_shares":
			limit := in.Limit
			if limit == 0 {
				limit = 20
			}
			var views []sharing.View
			var valid time.Time
			views, valid, operationErr = s.shares.List(ctx, current, in.View, limit)
			if operationErr == nil {
				until = identity.Earlier(until, valid)
				data := shareListData{Shares: []shareListItem{}}
				for _, v := range views {
					data.Shares = append(data.Shares, shareListItem{ShareID: v.Share.ID, CaseID: v.Share.CaseID, Phase: string(v.Phase), ExpiresAt: v.Share.ExpiresAt.UTC()})
				}
				out.Data = data
			}
		case "revoke_share":
			var share authorization.Share
			share, _, operationErr = s.shares.Revoke(ctx, current, in.ShareID, in.ExpectedRevision, in.IdempotencyKey)
			if operationErr == nil {
				out.Data = shareRevokeData{ShareID: share.ID, Phase: string(authorization.ShareRevoked), Revision: share.Revision}
			}
		default:
			return OperationReply{}, contracts.ErrInvestigationWire
		}
	}
	if operationErr != nil {
		out.Status, out.Data = "error", publicShareFailure(operationErr)
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
