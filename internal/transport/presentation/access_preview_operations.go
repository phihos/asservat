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

	authapp "asservat.local/asservat/internal/application/authorization"
	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
)

// AccessPreviewUseCase is the ADR-237 administrator impact preview.
type AccessPreviewUseCase interface {
	Preview(context.Context, identities.CurrentIdentity, []authapp.ProposedChange) (cfg.AccessPreview, time.Time, error)
}

// AccessPreviewOperations serves preview_access_change through the same
// audited operation path as every other operation. Its contract restricts it
// to the browser: MCP neither lists nor accepts it.
type AccessPreviewOperations struct {
	origin    string
	now       func() time.Time
	newID     func() string
	preview   AccessPreviewUseCase
	contracts *contracts.InvestigationContracts
}

func NewAccessPreviewOperations(origin string, now func() time.Time, newID func() string, preview AccessPreviewUseCase) (*AccessPreviewOperations, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || preview == nil || now == nil || newID == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, err := contracts.NewInvestigationContracts()
	if err != nil {
		return nil, err
	}
	return &AccessPreviewOperations{origin: origin, now: now, newID: newID, preview: preview, contracts: wire}, nil
}

func (s *AccessPreviewOperations) PublicOrigin() string {
	if s == nil {
		return ""
	}
	return s.origin
}
func (s *AccessPreviewOperations) ToolNames() []string { return []string{"preview_access_change"} }
func (s *AccessPreviewOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil || name != "preview_access_change" {
		return contracts.InvestigationTool{}, false
	}
	return s.contracts.Tool(name)
}

type accessPreviewChange struct {
	Action string          `json:"action"`
	Kind   string          `json:"kind"`
	UID    string          `json:"uid,omitempty"`
	Spec   json.RawMessage `json:"spec,omitempty"`
}

// AccessPreviewInput is the closed preview_access_change input. Spec stays the
// raw AccessBinding or PermissionSource spec; the application decodes it with
// the observed schemas. Cursor continues a paged result.
type AccessPreviewInput struct {
	Changes []accessPreviewChange `json:"changes"`
	Cursor  string                `json:"cursor,omitempty"`
}

type previewCellData struct {
	ClusterID      string `json:"cluster_id"`
	NamespaceUID   string `json:"namespace_uid"`
	WorkloadUID    string `json:"workload_uid"`
	OtherWorkloads bool   `json:"other_workloads"`
}
type previewSubjectData struct {
	Kind   string `json:"kind"`
	Issuer string `json:"issuer"`
	ID     string `json:"id"`
}
type previewBasisData struct {
	Effect      string `json:"effect"`
	Role        string `json:"role"`
	SubjectKind string `json:"subject_kind"`
	BasisKind   string `json:"basis_kind"`
	BasisUID    string `json:"basis_uid"`
	Revision    string `json:"revision"`
	Proposed    bool   `json:"proposed"`
}
type previewDeltaData struct {
	previewCellData
	Subject         previewSubjectData `json:"subject"`
	Operation       string             `json:"operation"`
	Before          string             `json:"before"`
	After           string             `json:"after"`
	BeforeUnmet     string             `json:"before_unmet,omitempty"`
	AfterUnmet      string             `json:"after_unmet,omitempty"`
	BeforeBasis     []previewBasisData `json:"before_basis"`
	AfterBasis      []previewBasisData `json:"after_basis"`
	AfterValidUntil *time.Time         `json:"after_valid_until,omitempty"`
}
type previewUnavailableData struct {
	previewCellData
	Decision string `json:"decision"`
	Unmet    string `json:"unmet"`
}
type previewObjectData struct {
	Kind string `json:"kind"`
	UID  string `json:"uid"`
}
type previewSourceData struct {
	Action   string `json:"action"`
	Kind     string `json:"kind"`
	UID      string `json:"uid,omitempty"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}
type accessPreviewData struct {
	Complete         bool                     `json:"complete"`
	Message          string                   `json:"message"`
	TargetsEvaluated int                      `json:"targets_evaluated"`
	FreshUntil       *time.Time               `json:"fresh_until,omitempty"`
	DeltasTotal      int                      `json:"deltas_total"`
	UnavailableTotal int                      `json:"unavailable_total"`
	ListedRows       int                      `json:"listed_rows"`
	PageOffset       int                      `json:"page_offset"`
	Unavailable      []previewUnavailableData `json:"unavailable"`
	Deltas           []previewDeltaData       `json:"deltas"`
	NotEvaluated     []previewSourceData      `json:"not_evaluated"`
	Unmatched        []previewObjectData      `json:"unmatched"`
}

var previewOperationNames = map[authorization.Operation]string{authorization.CollectContext: "capture", authorization.ReadApproved: "read", authorization.DownloadApproved: "download"}

// The whole listed result (every page's rows) stays within REQ-PER-002's
// 256 KiB result bound; each page stays inside the shared operation reply
// limit with room for the envelope and the summary fields.
const (
	previewResultBudget = 256<<10 - 8<<10
	previewPageBudget   = contracts.InvestigationOutputLimit - 6<<10
)

func previewCell(t authorization.Target) previewCellData {
	return previewCellData{ClusterID: t.ClusterID, NamespaceUID: t.NamespaceUID, WorkloadUID: t.WorkloadUID, OtherWorkloads: t.WorkloadUID == cfg.OtherWorkloads}
}

func previewBasis(rows []cfg.PreviewAssignment) []previewBasisData {
	out := []previewBasisData{}
	for _, r := range rows {
		if len(out) == 8 {
			break
		}
		a := r.Assignment
		out = append(out, previewBasisData{r.Effect, a.Role, a.Kind, a.BasisKind, a.BasisUID, hex.EncodeToString(a.BasisDigest[:]), r.Proposed})
	}
	return out
}

func previewMessage(p cfg.AccessPreview, listed int) string {
	switch {
	case len(p.NotEvaluated) > 0:
		return "Some PermissionSource creations or edits are Indeterminate: the accepted namespace observation is unavailable (MetadataUnavailable) or does not record the source's selector or mapping keys yet (MetadataNotObserved; apply the source with enabled: false first, then preview enabling it), or the source is a kubernetesExec/kubernetesAccessReview source that is reviewed per user and Pod at request time (DecisionTimeSource; use explain_access after applying it). An edited source's current assignments stay in effect in the after state of every listed decision. Nothing was changed: apply the reviewed objects with kubectl or GitOps."
	case !p.Complete():
		return "Some targets could not be evaluated and are listed as Indeterminate; their access after the change is unknown. Nothing was changed: apply the reviewed objects with kubectl or GitOps."
	case p.DeltasTotal == 0:
		return "No listed subject's Allow, Deny or Indeterminate decision would change on these targets. Nothing was changed: apply the reviewed objects with kubectl or GitOps."
	case p.DeltasTotal+len(p.Unavailable) > listed:
		return "The result is limited to 256 KiB: only the first listed_rows rows are listed, and deltas_total counts every change. Preview fewer objects to see all of them. Nothing was changed: apply the reviewed objects with kubectl or GitOps."
	}
	return "The listed decisions would change once the proposed objects are applied and accepted. Nothing was changed: apply the reviewed objects with kubectl or GitOps."
}

func previewFailure(err error) OperationFailure {
	switch {
	case errors.Is(err, errPreviewChanged):
		return OperationFailure{"PreviewChanged", "The permission data or the proposal changed since the first page. Preview again from the start.", true}
	case errors.Is(err, cfg.ErrLimit):
		return OperationFailure{"PreviewTooLarge", "The proposal exceeds the preview bounds: at most 16 objects and 1,000 workload targets. Preview fewer objects or narrower scopes.", false}
	case errors.Is(err, cfg.ErrInvalid):
		return OperationFailure{"InvalidProposal", "A proposed object is not a valid change. Create and update need a complete AccessBinding or PermissionSource spec, update and delete the existing object's UID, and each object may appear once.", false}
	case errors.Is(err, cfg.ErrDenied):
		return OperationFailure{"DelegationExceeded", "A proposed or changed object lies outside the delegation envelope that lets you preview permission changes (cluster, namespace, workloads, roles, issuers; no automation or PermissionSource changes).", false}
	case errors.Is(err, identity.ErrDenied):
		return OperationFailure{"AdministratorRequired", "Previewing permission changes needs a current fleet operator signed in with an operator client, or a configured delegation previewer.", false}
	}
	return OperationFailure{"NotAvailable", "The preview is unavailable right now. Retry shortly.", true}
}

var errPreviewChanged = errors.New("access preview changed")

// previewCursorKey binds a page cursor to the caller, the exact proposal and
// the permission stream revision that produced the result.
func previewCursorKey(i identity.Identity, in AccessPreviewInput, p cfg.AccessPreview) (string, error) {
	changes, err := json.Marshal(in.Changes)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte("asservat-access-preview-cursor/v1\x00" + i.Principal.Issuer + "\x00" + i.Principal.Subject + "\x00" + p.Revision.UID + "\x00" + strconv.FormatInt(p.Revision.Generation, 10) + "\x00"))
	h.Write(p.Revision.Digest[:])
	h.Write(changes)
	return hex.EncodeToString(h.Sum(nil)[:16]), nil
}

func (s *AccessPreviewOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil {
		return OperationReply{}, ErrOperationsConfiguration
	}
	return s.CallWithContext(ctx, current, OperationCall{requestID: s.newID()}, name, raw)
}

func (s *AccessPreviewOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil || ctx == nil || current == nil {
		return OperationReply{}, value.ErrUnavailable
	}
	if name != "preview_access_change" {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	if err := s.contracts.ValidateInput(name, raw); err != nil {
		return OperationReply{}, err
	}
	var in AccessPreviewInput
	if json.Unmarshal(raw, &in) != nil || !authorization.UUID(call.requestID) {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	offset, wantKey := 0, ""
	if in.Cursor != "" {
		head, key, _ := strings.Cut(in.Cursor, ":")
		n, err := strconv.Atoi(head)
		if err != nil || n < 1 {
			return OperationReply{}, contracts.ErrInvestigationWire
		}
		offset, wantKey = n, key
	}
	i, err := current.ResolveIdentity(ctx)
	if err != nil || !i.Valid(s.now()) {
		return OperationReply{}, identity.ErrDenied
	}
	changes := make([]authapp.ProposedChange, len(in.Changes))
	for n, c := range in.Changes {
		changes[n] = authapp.ProposedChange{Action: c.Action, Kind: c.Kind, UID: c.UID, Spec: c.Spec}
	}
	out := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: call.requestID, DataClass: "metadata", Status: "ok", Warnings: []string{}, Provenance: []any{}}
	until := i.ValidUntil
	p, valid, operationErr := s.preview.Preview(ctx, current, changes)
	var data accessPreviewData
	if operationErr == nil {
		until = identity.Earlier(until, valid)
		data, out.NextCursor, operationErr = previewPage(i, in, p, offset, wantKey)
	}
	if operationErr != nil {
		out.Status, out.Data = "error", previewFailure(operationErr)
	} else {
		out.Data = data
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
	return OperationReply{Body: b, ValidUntil: until, auditDecision: captureAuditDecision(operationErr)}, nil
}

// previewPage lists the result's rows (Indeterminate targets first, then
// decision changes) up to the 256 KiB result bound and returns the page that
// starts at offset, with the cursor of the next page.
func previewPage(i identity.Identity, in AccessPreviewInput, p cfg.AccessPreview, offset int, wantKey string) (accessPreviewData, *string, error) {
	key, err := previewCursorKey(i, in, p)
	if err != nil {
		return accessPreviewData{}, nil, value.ErrUnavailable
	}
	if offset > 0 && key != wantKey {
		return accessPreviewData{}, nil, errPreviewChanged
	}
	var rows []any
	for _, c := range p.Unavailable {
		rows = append(rows, previewUnavailableData{previewCell(c.Target), string(authorization.Indeterminate), c.Unavailable})
	}
	for _, d := range p.Deltas {
		row := previewDeltaData{previewCellData: previewCell(d.Target), Subject: previewSubjectData{d.Subject.Kind, d.Subject.Issuer, d.Subject.ID},
			Operation: previewOperationNames[d.Operation], Before: string(d.Before), After: string(d.After), BeforeUnmet: d.BeforeUnmet, AfterUnmet: d.AfterUnmet,
			BeforeBasis: previewBasis(d.BeforeBasis), AfterBasis: previewBasis(d.AfterBasis)}
		if d.After == authorization.Allow && !d.AfterValidUntil.IsZero() {
			v := d.AfterValidUntil.UTC()
			row.AfterValidUntil = &v
		}
		rows = append(rows, row)
	}
	sizes := make([]int, 0, len(rows))
	total := 0
	for _, r := range rows {
		b, err := json.Marshal(r)
		if err != nil {
			return accessPreviewData{}, nil, value.ErrUnavailable
		}
		if total+len(b)+1 > previewResultBudget {
			break
		}
		total += len(b) + 1
		sizes = append(sizes, len(b)+1)
	}
	listed := len(sizes)
	if offset > listed || offset > 0 && offset == listed {
		return accessPreviewData{}, nil, errPreviewChanged
	}
	data := accessPreviewData{Complete: p.Complete(), Message: previewMessage(p, listed), TargetsEvaluated: p.Targets, DeltasTotal: p.DeltasTotal, UnavailableTotal: len(p.Unavailable),
		ListedRows: listed, PageOffset: offset, Unavailable: []previewUnavailableData{}, Deltas: []previewDeltaData{}, NotEvaluated: []previewSourceData{}, Unmatched: []previewObjectData{}}
	if !p.FreshUntil.IsZero() {
		v := p.FreshUntil.UTC()
		data.FreshUntil = &v
	}
	for _, c := range p.NotEvaluated {
		data.NotEvaluated = append(data.NotEvaluated, previewSourceData{c.Action, c.Kind, c.UID, string(authorization.Indeterminate), c.Unevaluated})
	}
	for _, b := range p.Unmatched {
		data.Unmatched = append(data.Unmatched, previewObjectData{b.Kind, b.UID})
	}
	used, end := 0, offset
	for end < listed && (end == offset || used+sizes[end] <= previewPageBudget) {
		used += sizes[end]
		switch r := rows[end].(type) {
		case previewUnavailableData:
			data.Unavailable = append(data.Unavailable, r)
		case previewDeltaData:
			data.Deltas = append(data.Deltas, r)
		}
		end++
	}
	var next *string
	if end < listed {
		cursor := strconv.Itoa(end) + ":" + key
		next = &cursor
	}
	return data, next, nil
}
