package presentation

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	"asservat.local/asservat/internal/application/capture"
	app "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
	capturevalue "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	v "asservat.local/asservat/internal/domain/live"
	"asservat.local/asservat/internal/domain/targets"
)

// LiveOperations serves list_recordings and watch_live: the passive source
// inventory and viewer state. It contains no collection or saved-evidence
// operation. The same audited operation set serves browser JSON and MCP.
type LiveService interface {
	List(context.Context, identities.CurrentIdentity, targets.WorkloadRequest, string, int) ([]v.Listed, string, error)
	Open(context.Context, identities.CurrentIdentity, v.Open) (v.Watch, error)
	Read(context.Context, identities.CurrentIdentity, v.Read) (v.Batch, error)
	Update(context.Context, identities.CurrentIdentity, v.Update, bool) (v.Watch, error)
}

// RecordingLister supplies save handles and eligibility for policy sources.
type RecordingLister interface {
	List(context.Context, identities.CurrentIdentity, targets.WorkloadRequest, string, string, int) (capture.RecordingPage, error)
	Select(context.Context, identities.CurrentIdentity, targets.WorkloadRequest, []string) (capture.RecordingPage, error)
}

// LiveOperationsConfig: Live is nil when live viewing is not configured;
// list_recordings then lists save rows only and watch_live is unregistered.
type LiveOperationsConfig struct {
	PublicOrigin      string
	Live              LiveService
	Recordings        RecordingLister
	Clusters          ClusterNames
	CollectionEnabled bool
	Now               func() time.Time
	// NewID, when set, lets an unaudited composition call list_recordings.
	NewID func() string
}

type LiveOperations struct {
	config  LiveOperationsConfig
	service LiveService
	wire    *contracts.InvestigationContracts
	now     func() time.Time
	// Diagnose, when set, receives fixed operation, class and location words
	// only; never identifiers, inputs or dependency error text.
	Diagnose func(string)
}

func NewLiveOperations(c LiveOperationsConfig) (*LiveOperations, error) {
	u, e := url.Parse(c.PublicOrigin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || c.Live == nil && c.Recordings == nil || c.Now == nil {
		return nil, ErrOperationsConfiguration
	}
	wire, e := contracts.NewInvestigationContracts()
	if e != nil {
		return nil, e
	}
	return &LiveOperations{config: c, service: c.Live, wire: wire, now: c.Now}, nil
}
func NewInvestigationLiveOperations(base *InvestigationOperations, live *LiveOperations) (*InvestigationOperations, error) {
	if live == nil {
		return nil, ErrOperationsConfiguration
	}
	return withOperations(base, live)
}
func (s *LiveOperations) PublicOrigin() string { return s.config.PublicOrigin }
func (s *LiveOperations) ToolNames() []string {
	if s != nil && s.service == nil {
		return []string{"list_recordings"}
	}
	return []string{"list_recordings", "watch_live"}
}
func (s *LiveOperations) Tool(name string) (contracts.InvestigationTool, bool) {
	if s == nil || !slices.Contains(s.ToolNames(), name) {
		return contracts.InvestigationTool{}, false
	}
	return s.wire.Tool(name)
}
// Call serves only the passive inventory; watch_live needs the audited path.
func (s *LiveOperations) Call(ctx context.Context, current identities.CurrentIdentity, name string, raw json.RawMessage) (OperationReply, error) {
	if s == nil || s.config.NewID == nil || name != "list_recordings" {
		return OperationReply{}, ErrOperationDelivery
	}
	return s.CallWithContext(ctx, current, OperationCall{requestID: s.config.NewID()}, name, raw)
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
	until := identity.Earlier(s.now().Add(audit.OperationRequestWindow(name)), i.ValidUntil)
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
	action := ""
	if name == "watch_live" {
		var in struct {
			Action  string   `json:"action"`
			Handles []string `json:"source_handles"`
		}
		if json.Unmarshal(raw, &in) != nil {
			return OperationReply{}, contracts.ErrInvestigationWire
		}
		action = in.Action
		if action == "open" {
			raw = liveOpenHandles(raw, in.Handles)
		}
	}
	switch {
	case name == "list_recordings":
		out.Warnings = []string{}
		var next string
		out.Data, next, err = s.listRecordings(bounded, current, raw, &until)
		if errors.Is(err, errUnknownCluster) {
			out.Data, err = OperationFailure{Code: "UnknownCluster", Message: "No cluster of this installation has this name. Use local for the hub's own cluster or a configured clusters[].name.", Retryable: false}, nil
			out.Status = "error"
		} else if next != "" {
			out.NextCursor = &next
		}
	case action == "open":
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
	case action == "read":
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
	default:
		var in v.Update
		if json.Unmarshal(raw, &in) != nil {
			return OperationReply{}, contracts.ErrInvestigationWire
		}
		closing := action == "close"
		if owner, ok := s.service.(app.OwnedCommands); ok {
			delivery, err = owner.BeginLiveCommand(bounded, current, app.Command{Update: &in, Close: closing})
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
			out.Data, err = s.service.Update(bounded, current, in, closing)
		}
	}
	if err != nil {
		if s.Diagnose != nil {
			s.Diagnose(name + " " + v.Diagnostic(err))
		}
		failure := OperationFailure{Code: "LiveUnavailable", Message: "Live observation is unavailable for this source or current access. Saved evidence and separately reviewed collection remain available.", Retryable: false}
		if errors.Is(err, v.ErrTransient) {
			failure.Retryable = true
			failure.Message = "Live observation is temporarily unavailable. The view stays open; the next read checks current access again."
		}
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
	if (action == "read" || delivery != nil) && err == nil {
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
func liveOperation(name string) bool { return name == "list_recordings" || name == "watch_live" }

// Decode first, then normalize typed public input. No filter/row text enters a
// SQL control record; the existing operation journal retains its keyed digest.
func normalizeLiveInput(name string, raw []byte) ([]byte, error) {
	if name == "list_recordings" {
		var in listRecordingsInput
		if e := json.Unmarshal(raw, &in); e != nil {
			return nil, e
		}
		if in.Limit == 0 {
			in.Limit = 20
		}
		return json.Marshal(in)
	}
	var in struct {
		Action string `json:"action"`
	}
	if e := json.Unmarshal(raw, &in); e != nil {
		return nil, e
	}
	switch in.Action {
	case "open":
		var open v.Open
		if e := json.Unmarshal(raw, &open); e != nil {
			return nil, e
		}
		if open.Filter.All == nil {
			open.Filter.All = []v.Predicate{}
		}
		return json.Marshal(struct {
			Action string `json:"action"`
			v.Open
		}{in.Action, open})
	case "read":
		var read v.Read
		if e := json.Unmarshal(raw, &read); e != nil {
			return nil, e
		}
		if read.Limit == 0 {
			read.Limit = 20
		}
		return json.Marshal(struct {
			Action string `json:"action"`
			v.Read
		}{in.Action, read})
	default:
		var update v.Update
		if e := json.Unmarshal(raw, &update); e != nil {
			return nil, e
		}
		return json.Marshal(struct {
			Action string `json:"action"`
			v.Update
		}{in.Action, update})
	}
}

// liveOpenHandles keeps the live part of each list_recordings handle; a
// combined handle carries the save part first.
func liveOpenHandles(raw json.RawMessage, handles []string) json.RawMessage {
	var in map[string]json.RawMessage
	if json.Unmarshal(raw, &in) != nil {
		return raw
	}
	live := make([]string, len(handles))
	for n, h := range handles {
		live[n] = h[strings.LastIndex(h, capturevalue.RecordingHandleSeparator)+1:]
	}
	in["source_handles"], _ = json.Marshal(live)
	out, e := json.Marshal(in)
	if e != nil {
		return raw
	}
	return out
}

var errUnknownCluster = errors.New("presentation: unknown cluster name")

type listRecordingsInput struct {
	Target struct {
		Cluster   string `json:"cluster"`
		Namespace string `json:"namespace"`
		Kind      string `json:"kind"`
		Name      string `json:"name"`
	} `json:"target_ref"`
	Policy string `json:"policy,omitempty"`
	Cursor string `json:"cursor,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}

// recordingListRow is one recording-save.schema.json#/$defs/recording row.
type recordingListRow struct {
	Handle         string     `json:"recording_handle"`
	OwnerKind      string     `json:"owner_kind"`
	PolicyName     string     `json:"policy_name,omitempty"`
	CaptureID      string     `json:"capture_id,omitempty"`
	PodName        string     `json:"pod_name"`
	ActionID       string     `json:"action_id"`
	Kind           string     `json:"kind"`
	State          string     `json:"state"`
	History        string     `json:"history"`
	MaximumBefore  string     `json:"maximum_before"`
	Eligible       bool       `json:"save_eligible"`
	SaveVia        string     `json:"save_via"`
	Projections    []string   `json:"live_projections"`
	Blockers       []string   `json:"blockers"`
	IncidentPodCap int        `json:"incident_pod_cap"`
	HardEnd        *time.Time `json:"hard_end,omitempty"`
	PolicyUID      string     `json:"policy_uid,omitempty"`
	PodUID         string     `json:"pod_uid,omitempty"`
}
type recordingListPage struct {
	Kind           string             `json:"kind"`
	Recordings     []recordingListRow `json:"recordings"`
	CaptureEnabled bool               `json:"capture_enabled"`
	ExpiresAt      time.Time          `json:"expires_at"`
}

func (r *recordingListRow) block(code string) {
	if !slices.Contains(r.Blockers, code) {
		r.Blockers = append(r.Blockers, code)
	}
}

// listRecordings pages the live source inventory (policy and manual sources)
// and adds save handles for its policy sources. Without live viewing it pages
// the save inventory alone. The page expires with its save handles.
func (s *LiveOperations) listRecordings(ctx context.Context, current identities.CurrentIdentity, raw json.RawMessage, until *time.Time) (any, string, error) {
	var in listRecordingsInput
	if json.Unmarshal(raw, &in) != nil {
		return nil, "", contracts.ErrInvestigationWire
	}
	cluster, ok := s.config.Clusters.ID(in.Target.Cluster)
	if !ok {
		return nil, "", errUnknownCluster
	}
	target := targets.WorkloadRequest{ClusterID: cluster, Namespace: in.Target.Namespace, Kind: in.Target.Kind, Name: in.Target.Name}
	// A row with maximal names and a combined handle encodes to about 1.3 KiB;
	// sixteen fit the 24 KiB result envelope.
	limit := min(max(in.Limit, 1), 16)
	if in.Limit == 0 {
		limit = 16
	}
	page := recordingListPage{Kind: "recordingPage", Recordings: []recordingListRow{}, CaptureEnabled: s.config.CollectionEnabled, ExpiresAt: (*until).UTC()}
	saves := map[string]capture.RecordingRow{}
	note := func(p capture.RecordingPage) {
		*until = identity.Earlier(*until, p.ValidUntil)
		page.ExpiresAt = p.ExpiresAt.UTC()
		for _, r := range p.Rows {
			saves[r.SourceID] = r
		}
	}
	if s.service == nil {
		if s.config.Recordings == nil {
			return page, "", nil
		}
		p, e := s.config.Recordings.List(ctx, current, target, "", in.Cursor, limit)
		if errors.Is(e, capturevalue.ErrDenied) {
			return page, "", nil
		}
		if e != nil {
			return nil, "", e
		}
		note(p)
		for _, r := range p.Rows {
			if r.Handle == "" || in.Policy != "" && r.PolicyName != in.Policy {
				continue
			}
			row := savedRecordingRow(r)
			row.block("LiveViewDisabled")
			page.Recordings = append(page.Recordings, row)
		}
		return page, p.Cursor, nil
	}
	listed, next, err := s.service.List(ctx, current, target, in.Cursor, limit)
	if err != nil {
		return nil, "", err
	}
	ids := []string{}
	for _, l := range listed {
		if l.Source.Manual == nil && l.Source.SaveVia == "recordingSave" {
			ids = append(ids, l.Source.ID())
		}
	}
	if len(ids) > 0 && s.config.Recordings != nil {
		// A caller without collection rights still sees the live rows.
		if p, e := s.config.Recordings.Select(ctx, current, target, ids); e == nil {
			note(p)
		} else if !errors.Is(e, capturevalue.ErrDenied) {
			return nil, "", e
		}
	}
	for _, l := range listed {
		src := l.Source
		if in.Policy != "" && (src.Manual != nil || src.PolicyName != in.Policy) {
			continue
		}
		hard := src.HardUntil.UTC()
		row := recordingListRow{Handle: l.Handle, OwnerKind: src.OwnerKind, PodName: src.PodName, ActionID: src.Action(), Kind: src.Kind, State: src.State, History: "Unknown", MaximumBefore: artifact.LifecycleDuration(src.Before), SaveVia: src.SaveVia, Projections: []string{}, Blockers: []string{}, IncidentPodCap: max(src.IncidentPodCap, 1), HardEnd: &hard, PodUID: src.Pod()}
		if row.PodName == "" {
			row.PodName = src.Pod()
		}
		if row.Kind == "" {
			row.Kind = "packetCapture"
		}
		if l.Live {
			row.Projections = slices.Clone(src.Projections)
		}
		for _, b := range l.Blockers {
			row.block(b)
		}
		if src.Manual != nil {
			row.CaptureID = src.OwnerID
		} else {
			row.PolicyName, row.PolicyUID = src.PolicyName, src.Binding.PolicyUID
			switch saved, ok := saves[src.ID()]; {
			case src.SaveVia != "recordingSave":
				row.block("NotSaveEnabled")
			case !ok || saved.Handle == "":
				row.block("SaveNotPermitted")
			default:
				row.Handle = saved.Handle + capturevalue.RecordingHandleSeparator + l.Handle
				row.History, row.MaximumBefore = saved.History, artifact.LifecycleDuration(saved.MaximumBefore)
				row.Eligible = saved.Blocker == ""
				if saved.Blocker != "" {
					row.block(saved.Blocker)
				}
			}
		}
		page.Recordings = append(page.Recordings, row)
	}
	return page, next, nil
}

// savedRecordingRow presents a save-inventory row when live viewing is off.
func savedRecordingRow(r capture.RecordingRow) recordingListRow {
	row := recordingListRow{Handle: r.Handle, OwnerKind: "policy", PolicyName: r.PolicyName, PodName: r.PodName, ActionID: r.ActionID, Kind: r.Kind, State: "Ready", History: r.History, MaximumBefore: artifact.LifecycleDuration(r.MaximumBefore), Eligible: r.Blocker == "", SaveVia: "recordingSave", Projections: []string{}, Blockers: []string{}, IncidentPodCap: max(r.IncidentPodCap, 1), PolicyUID: r.PolicyUID, PodUID: r.PodUID}
	if r.Blocker != "" {
		row.block(r.Blocker)
	}
	if r.Blocker == "SourceExpired" {
		row.State = "Stopped"
	}
	return row
}
