package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	app "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
)

// LiveOperations contains no collection or saved-evidence operation. The same
// audited operation set serves browser JSON and MCP; registration is explicit.
type LiveService interface {
	List(context.Context, identities.CurrentIdentity, targets.WorkloadRequest, string, int) (v.SourcePage, string, error)
	Open(context.Context, identities.CurrentIdentity, v.Open) (v.Watch, error)
	Read(context.Context, identities.CurrentIdentity, v.Read) (v.Batch, error)
	Update(context.Context, identities.CurrentIdentity, v.Update, bool) (v.Watch, error)
}

type LiveOperations struct {
	origin  string
	service LiveService
	wire    *contracts.InvestigationContracts
	now     func() time.Time
}

func NewLiveOperations(origin string, service LiveService, now func() time.Time) (*LiveOperations, error) {
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || service == nil || now == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, e := contracts.NewInvestigationContracts()
	if e != nil {
		return nil, e
	}
	return &LiveOperations{origin, service, wire, now}, nil
}
func NewInvestigationLiveOperations(base *InvestigationOperations, live *LiveOperations) (*InvestigationOperations, error) {
	if live == nil {
		return nil, ErrOperationsConfiguration
	}
	return withOperations(base, live)
}
func (s *LiveOperations) PublicOrigin() string { return s.origin }
func (s *LiveOperations) ToolNames() []string {
	return []string{"list_live_sources", "open_live_watch", "read_live_watch", "update_live_watch", "close_live_watch"}
}
func (s *LiveOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil || !slices.Contains(s.ToolNames(), name) {
		return contracts.InvestigationTool{}, false
	}
	return s.wire.Tool(name)
}
func (s *LiveOperations) Call(context.Context, identities.CurrentIdentity, string, json.RawMessage) (OperationReply, error) {
	return OperationReply{}, ErrOperationDelivery
}
func (s *LiveOperations) CallWithContext(ctx context.Context, current identities.CurrentIdentity, call OperationCall, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil || current == nil || !authorization.UUID(call.requestID) {
		return OperationReply{}, ErrOperationDelivery
	}
	if _, ok := s.Tool(name); !ok {
		return OperationReply{}, contracts.ErrInvestigationWire
	}
	if e := s.wire.ValidateInput(name, raw); e != nil {
		return OperationReply{}, e
	}
	i, e := current.ResolveIdentity(ctx)
	if e != nil || !i.Valid(s.now()) || !slices.Contains(i.Scopes, "evidence:read") {
		return OperationReply{}, identity.ErrDenied
	}
	until := identity.Earlier(s.now().Add(5*time.Second), i.ValidUntil)
	if end, ok := ctx.Deadline(); ok {
		until = identity.Earlier(until, end)
	}
	bounded, cancel := context.WithDeadline(ctx, until)
	transferred := false
	var delivery app.CommandDelivery
	defer func() {
		if !transferred && delivery != nil {
			_ = delivery.Close(context.WithoutCancel(ctx))
		}
	}()
	defer func() {
		if !transferred {
			cancel()
		}
	}()
	out := OperationEnvelope{SchemaVersion: "mcp-result/v1", RequestID: call.requestID, DataClass: "metadata", Status: "ok", Warnings: []string{"Live rows are transient and untrusted; save separately before raw inspection. External copies cannot be recalled."}, Provenance: []any{}}
	var err error
	switch name {
	case "list_live_sources":
		var in struct {
			Target WorkloadReference `json:"target_ref"`
			Cursor string            `json:"cursor"`
			Limit  int               `json:"limit"`
		}
		if json.Unmarshal(raw, &in) != nil {
			return OperationReply{}, contracts.ErrInvestigationWire
		}
		var next string
		out.Data, next, err = s.service.List(bounded, current, in.Target.target(), in.Cursor, in.Limit)
		if next != "" {
			out.NextCursor = &next
		}
	case "open_live_watch":
		var in v.Open
		if json.Unmarshal(raw, &in) != nil {
			return OperationReply{}, contracts.ErrInvestigationWire
		}
		if owner, ok := s.service.(app.OwnedCommands); ok {
			delivery, err = owner.BeginLiveCommand(bounded, current, app.Command{Open: &in})
			if err == nil {
				if delivery == nil {
					return OperationReply{}, ErrOperationDelivery
				}
				result := delivery.Result()
				if result.Watch == nil || result.Batch != nil {
					return OperationReply{}, ErrOperationDelivery
				}
				out.Data = *result.Watch
			}
		} else {
			out.Data, err = s.service.Open(bounded, current, in)
		}
	case "read_live_watch":
		var in v.Read
		if json.Unmarshal(raw, &in) != nil {
			return OperationReply{}, contracts.ErrInvestigationWire
		}
		var batch v.Batch
		if owner, ok := s.service.(app.OwnedCommands); ok {
			delivery, err = owner.BeginLiveCommand(bounded, current, app.Command{Read: &in})
			if err == nil {
				if delivery == nil {
					return OperationReply{}, ErrOperationDelivery
				}
				result := delivery.Result()
				if result.Batch == nil || result.Watch != nil || result.Batch.WatchID != in.ID {
					return OperationReply{}, ErrOperationDelivery
				}
				batch = *result.Batch
			}
		} else {
			batch, err = s.service.Read(bounded, current, in)
		}
		out.Data = batch
		if err == nil {
			if batch.DisclosureUntil.IsZero() {
				return OperationReply{}, ErrOperationDelivery
			}
			until = identity.Earlier(until, batch.DisclosureUntil)
		}
		out.DataClass = "extract"
		if batch.Cursor != "" && !v.Terminal(batch.State) {
			out.NextCursor = &batch.Cursor
		}
		for _, row := range batch.Rows {
			until = identity.Earlier(until, row.ExpiresAt)
		}
	case "update_live_watch", "close_live_watch":
		var in v.Update
		if json.Unmarshal(raw, &in) != nil {
			return OperationReply{}, contracts.ErrInvestigationWire
		}
		if owner, ok := s.service.(app.OwnedCommands); ok {
			delivery, err = owner.BeginLiveCommand(bounded, current, app.Command{Update: &in, Close: name == "close_live_watch"})
			if err == nil {
				if delivery == nil {
					return OperationReply{}, ErrOperationDelivery
				}
				result := delivery.Result()
				if result.Watch == nil || result.Batch != nil || result.Watch.ID != in.ID {
					return OperationReply{}, ErrOperationDelivery
				}
				out.Data = *result.Watch
			}
		} else {
			out.Data, err = s.service.Update(bounded, current, in, name == "close_live_watch")
		}
	}
	if err != nil {
		failure := OperationFailure{Code: "LiveUnavailable", Message: "Live observation is unavailable for this source or current access. Saved evidence and separately reviewed collection remain available.", Retryable: false}
		if errors.Is(err, v.ErrCapacity) {
			failure.Code = "CapacityUnavailable"
			failure.Message = "Live-view capacity is unavailable. Close another view or try again later."
		}
		if errors.Is(err, v.ErrConflict) {
			failure.Code = "Conflict"
			failure.Message = "This live view changed or its cursor expired. Refresh the view state before continuing."
		}
		out.Status = "error"
		out.Data = failure
		out.DataClass = "metadata"
		out.NextCursor = nil
	}
	final, e := current.ResolveIdentity(bounded)
	if e != nil || !final.Valid(s.now()) || final.Principal != i.Principal || final.Policy != i.Policy || bounded.Err() != nil {
		return OperationReply{}, identity.ErrDenied
	}
	until = identity.Earlier(until, final.ValidUntil)
	body, e := json.Marshal(out)
	if e != nil || len(body) > contracts.InvestigationOutputLimit || s.wire.ValidateOutput(name, body) != nil || !s.now().Before(until) {
		clear(body)
		return OperationReply{}, ErrOperationDelivery
	}
	reply := OperationReply{Body: body, ValidUntil: until}
	if (name == "read_live_watch" || delivery != nil) && err == nil {
		guard := &liveReplyGuard{ctx: bounded, cancel: cancel, current: current, initial: i, until: until, now: s.now, delivery: delivery}
		owned, e := ownOperationReply(bounded, reply, guard, until, func(ctx context.Context, out audit.OperationOutcome) error {
			if !out.Valid() || out.Intent.ID != call.requestID || out.Intent.Name != name || out.Status != "success" || out.MetadataUntil.After(until) || ctx.Err() != nil {
				return ErrOperationDelivery
			}
			return nil
		})
		if e != nil {
			clear(body)
			return OperationReply{}, e
		}
		transferred = true
		return owned, nil
	}
	return reply, nil
}

// The public request owns these transient bytes through acknowledged outcome
// audit and joined final write. Checks retain the original bounded observation;
// they never extend it, fetch rows, debit again or renew a source.
type liveReplyGuard struct {
	ctx      context.Context
	cancel   context.CancelFunc
	current  identities.CurrentIdentity
	initial  identity.Identity
	until    time.Time
	now      func() time.Time
	delivery app.CommandDelivery
}

func (g *liveReplyGuard) Done() <-chan struct{} {
	if g.delivery != nil {
		return g.delivery.Done()
	}
	return g.ctx.Done()
}
func (g *liveReplyGuard) Close(ctx context.Context) error {
	defer g.cancel()
	if g.delivery != nil {
		return g.delivery.Close(context.WithoutCancel(ctx))
	}
	return nil
}
func (g *liveReplyGuard) CheckDisclosure(ctx context.Context) error {
	if ctx.Err() != nil || g.ctx.Err() != nil || !g.now().Before(g.until) {
		return ErrOperationDelivery
	}
	if g.delivery != nil {
		if e := g.delivery.CheckDisclosure(ctx); e != nil {
			return e
		}
	}
	i, e := g.current.ResolveIdentity(ctx)
	if e != nil || !sameAuditIdentity(g.initial, i, g.now()) {
		return ErrOperationDelivery
	}
	return nil
}
func liveOperation(name string) bool {
	return slices.Contains([]string{"list_live_sources", "open_live_watch", "read_live_watch", "update_live_watch", "close_live_watch"}, name)
}

// Decode first, then normalize typed public input. No filter/row text enters a
// SQL control record; the existing operation journal retains its keyed digest.
func normalizeLiveInput(name string, raw []byte) ([]byte, error) {
	switch name {
	case "list_live_sources":
		var in struct {
			Target WorkloadReference `json:"target_ref"`
			Cursor string            `json:"cursor,omitempty"`
			Limit  int               `json:"limit,omitempty"`
		}
		if e := json.Unmarshal(raw, &in); e != nil {
			return nil, e
		}
		if in.Limit == 0 {
			in.Limit = 20
		}
		return json.Marshal(in)
	case "open_live_watch":
		var in v.Open
		if e := json.Unmarshal(raw, &in); e != nil {
			return nil, e
		}
		if in.Filter.All == nil {
			in.Filter.All = []v.Predicate{}
		}
		if in.Duration == 0 {
			in.Duration = 600
		}
		if in.Output == 0 {
			in.Output = 16 << 20
		}
		return json.Marshal(in)
	case "read_live_watch":
		var in v.Read
		if e := json.Unmarshal(raw, &in); e != nil {
			return nil, e
		}
		if in.Limit == 0 {
			in.Limit = 20
		}
		return json.Marshal(in)
	default:
		var in v.Update
		if e := json.Unmarshal(raw, &in); e != nil {
			return nil, e
		}
		return json.Marshal(in)
	}
}
