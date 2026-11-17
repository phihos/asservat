package presentation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
)

// RetentionPreviewUseCase is the ADR-240 retention impact preview.
type RetentionPreviewUseCase interface {
	Preview(context.Context, privacyapp.PreviewIdentity, []privacyapp.ProposedRetentionChange) (privacy.RetentionPreview, time.Time, error)
}

// RetentionPreviewOperations serves preview_retention_change through the same
// audited operation path as every other operation. Its contract restricts it
// to the browser: MCP neither lists nor accepts it.
type RetentionPreviewOperations struct {
	origin    string
	now       func() time.Time
	newID     func() string
	preview   RetentionPreviewUseCase
	contracts *contracts.InvestigationContracts
}

func NewRetentionPreviewOperations(origin string, now func() time.Time, newID func() string, preview RetentionPreviewUseCase) (*RetentionPreviewOperations, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || preview == nil || now == nil || newID == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &RetentionPreviewOperations{origin: origin, now: now, newID: newID, preview: preview, contracts: wire}, nil
}

func (s *RetentionPreviewOperations) PublicOrigin() string {
	if s == nil {
		return ""
	}
	return s.origin
}
func (s *RetentionPreviewOperations) ToolNames() []string {
	return []string{"preview_retention_change"}
}
func (s *RetentionPreviewOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil || name != "preview_retention_change" {
		return contracts.InvestigationTool{}, false
	}
	return s.contracts.Tool(name)
}

type retentionPreviewChange struct {
	Action          string          `json:"action"`
	SourceClusterID string          `json:"source_cluster_id,omitempty"`
	UID             string          `json:"uid,omitempty"`
	Spec            json.RawMessage `json:"spec,omitempty"`
}

// RetentionPreviewInput is the closed preview_retention_change input. Spec
// stays the raw EvidenceRetentionPolicy spec; the application decodes it with
// the observed schema.
type RetentionPreviewInput struct {
	Changes []retentionPreviewChange `json:"changes"`
	Cursor  string                   `json:"cursor,omitempty"`
}

type retentionGroupData struct {
	ClusterID         string     `json:"cluster_id"`
	PrivacyClass      string     `json:"privacy_class"`
	EvidenceType      string     `json:"evidence_type"`
	Scanned           int        `json:"scanned"`
	Affected          int        `json:"affected"`
	ReadClosed        int        `json:"read_closed"`
	DeletionDue       int        `json:"deletion_due"`
	Unknown           int        `json:"unknown"`
	EarliestExpiresAt *time.Time `json:"earliest_expires_at,omitempty"`
	EarliestDeleteBy  *time.Time `json:"earliest_delete_by,omitempty"`
}
type retentionIncompleteData struct {
	ClusterID string `json:"cluster_id"`
	Reason    string `json:"reason"`
}
type retentionNotEvaluatedData struct {
	Action          string `json:"action"`
	SourceClusterID string `json:"source_cluster_id,omitempty"`
	UID             string `json:"uid,omitempty"`
	Reason          string `json:"reason"`
}
type retentionPreviewData struct {
	Complete          bool                        `json:"complete"`
	Message           string                      `json:"message"`
	ObservedAt        time.Time                   `json:"observed_at"`
	ArtifactsScanned  int                         `json:"artifacts_scanned"`
	ScanLimited       bool                        `json:"scan_limited"`
	AffectedTotal     int                         `json:"affected_total"`
	ReadClosedTotal   int                         `json:"read_closed_total"`
	DeletionDueTotal  int                         `json:"deletion_due_total"`
	UnknownTotal      int                         `json:"unknown_total"`
	EarliestExpiresAt *time.Time                  `json:"earliest_expires_at,omitempty"`
	EarliestDeleteBy  *time.Time                  `json:"earliest_delete_by,omitempty"`
	BaselineChanged   bool                        `json:"baseline_changed"`
	Groups            []retentionGroupData        `json:"groups"`
	GroupsTotal       int                         `json:"groups_total"`
	Incomplete        []retentionIncompleteData   `json:"incomplete_clusters"`
	IncompleteTotal   int                         `json:"incomplete_total"`
	NotEvaluated      []retentionNotEvaluatedData `json:"not_evaluated"`
}

// A page lists at most 32 group and incomplete-cluster rows: a group row
// is at most about 400 bytes, so a page stays inside the 24 KiB reply size
// target (REQ-MCP-002). The totals count every row.
const retentionPreviewPageRows = 32

func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	v := t.UTC()
	return &v
}

func retentionPreviewMessage(p privacy.RetentionPreview) string {
	const tail = " Nothing was changed: apply the reviewed policy with kubectl or GitOps."
	switch {
	case len(p.NotEvaluated) > 0:
		return "Some changes name a policy or source that is not currently accepted and were not evaluated; the counts cover the other changes only." + tail
	case len(p.Incomplete) > 0:
		return "The policy source of some clusters is not current: their counts may change once it is, and the listed clusters are incomplete." + tail
	case p.Unknown > 0:
		return "Unknown artifacts would need historical labels that are not recorded for a newly selected label selector; their deadlines after the change are not assumed." + tail
	case p.Affected == 0:
		return "No retained artifact's access end or deletion date would become earlier. A longer limit applies only to new collections." + tail
	}
	return "The listed artifacts would have their access end or deletion moved earlier once the change is applied; dates already bound are never extended." + tail
}

func retentionPreviewFailure(err error) OperationFailure {
	switch {
	case errors.Is(err, privacy.ErrInvalid):
		return OperationFailure{"InvalidProposal", "A proposed object is not a valid change. Create and update need a complete EvidenceRetentionPolicy spec, update and delete the existing policy's UID, and each policy may appear once.", false}
	case errors.Is(err, identity.ErrDenied):
		return OperationFailure{"AdministratorRequired", "Previewing retention changes needs a current fleet operator signed in with an operator client.", false}
	}
	return OperationFailure{"NotAvailable", "The preview is unavailable right now. Retry shortly.", true}
}

// retentionPreviewReply lists the page of groups, then incomplete clusters,
// that starts at offset.
func retentionPreviewReply(p privacy.RetentionPreview, offset int) retentionPreviewData {
	out := retentionPreviewData{Complete: p.Complete(), Message: retentionPreviewMessage(p), ObservedAt: p.ObservedAt.UTC(), ArtifactsScanned: p.Scanned,
		AffectedTotal: p.Affected, ReadClosedTotal: p.ReadClosed, DeletionDueTotal: p.DeletionDue, UnknownTotal: p.Unknown,
		EarliestExpiresAt: optionalTime(p.EarliestExpiresAt), EarliestDeleteBy: optionalTime(p.EarliestDeleteBy), BaselineChanged: p.BaselineChanged,
		Groups: []retentionGroupData{}, GroupsTotal: len(p.Groups), Incomplete: []retentionIncompleteData{}, IncompleteTotal: len(p.Incomplete), NotEvaluated: []retentionNotEvaluatedData{}}
	end := offset + retentionPreviewPageRows
	for n, g := range p.Groups {
		if n >= offset && n < end {
			out.Groups = append(out.Groups, retentionGroupData{g.ClusterID, g.PrivacyClass, g.EvidenceType, g.Scanned, g.Affected, g.ReadClosed, g.DeletionDue, g.Unknown, optionalTime(g.EarliestExpiresAt), optionalTime(g.EarliestDeleteBy)})
		}
	}
	for n, c := range p.Incomplete {
		if n += len(p.Groups); n >= offset && n < end {
			out.Incomplete = append(out.Incomplete, retentionIncompleteData{c.ClusterID, c.Reason})
		}
	}
	for _, c := range p.NotEvaluated {
		out.NotEvaluated = append(out.NotEvaluated, retentionNotEvaluatedData{c.Action, c.SourceClusterID, c.UID, c.Reason})
	}
	return out
}

func (s *RetentionPreviewOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil {
		return OperationReply{}, ErrOperationsConfiguration
	}
	return s.CallWithContext(ctx, current, OperationCall{requestID: s.newID()}, name, raw)
}

func (s *RetentionPreviewOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil || ctx == nil || current == nil {
		return OperationReply{}, value.ErrUnavailable
	}
	if name != "preview_retention_change" {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	if err := s.contracts.ValidateInput(name, raw); err != nil {
		return OperationReply{}, err
	}
	var in RetentionPreviewInput
	if json.Unmarshal(raw, &in) != nil || !authorization.UUID(call.requestID) {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.now()) {
		return OperationReply{}, identity.ErrDenied
	}
	// The cursor is the next row offset bound to the caller and the exact
	// proposal; the preview itself is recomputed for every page.
	key := sha256.Sum256([]byte(i.Principal.Issuer + "\x00" + i.Principal.Subject + "\x00" + retentionChangesKey(in.Changes)))
	offset := 0
	if in.Cursor != "" {
		head, tail, _ := strings.Cut(in.Cursor, ":")
		n, err := strconv.Atoi(head)
		if err != nil || n < 1 || tail != hex.EncodeToString(key[:16]) {
			return OperationReply{}, contracts.ErrInvestigationWire
		}
		offset = n
	}
	changes := make([]privacyapp.ProposedRetentionChange, len(in.Changes))
	for n, c := range in.Changes {
		changes[n] = privacyapp.ProposedRetentionChange{Action: c.Action, SourceClusterID: c.SourceClusterID, UID: c.UID, Spec: c.Spec}
	}
	out := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: call.requestID, DataClass: "metadata", Status: "ok", Warnings: []string{}, Provenance: []any{}}
	until := i.ValidUntil
	p, valid, operationErr := s.preview.Preview(ctx, current, changes)
	if operationErr != nil {
		out.Status, out.Data = "error", retentionPreviewFailure(operationErr)
	} else {
		until = identity.Earlier(until, valid)
		out.Data = retentionPreviewReply(p, offset)
		if next := offset + retentionPreviewPageRows; next < len(p.Groups)+len(p.Incomplete) {
			cursor := strconv.Itoa(next) + ":" + hex.EncodeToString(key[:16])
			out.NextCursor = &cursor
		}
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
	return OperationReply{Body: b, ValidUntil: until, auditDecision: retentionPreviewAuditDecision(operationErr)}, nil
}

func retentionChangesKey(changes []retentionPreviewChange) string {
	b, _ := json.Marshal(changes)
	return string(b)
}

func retentionPreviewAuditDecision(err error) operationAuditDecision {
	if errors.Is(err, privacy.ErrInvalid) {
		return operationAuditInvalid
	}
	return captureAuditDecision(err)
}
