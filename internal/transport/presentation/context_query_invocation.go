package presentation

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"sync"
	"time"

	analysisapp "asservat.local/asservat/internal/application/analysis"
	auditapp "asservat.local/asservat/internal/application/audit"
	value "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	"asservat.local/asservat/internal/domain/authorization"
)

// This process-local owner carries the existing C-08 lineage. Construction is
// private and occurs only after Begin succeeds. It is neither another auditor
// nor a serializable grant; query SQL independently verifies the intent writer.
type contextQueryInvocation struct {
	mu                   sync.Mutex
	ctx                  context.Context
	intent               audit.OperationIntent
	call                 value.ContextQueryCall
	mac                  *auditapp.OperationMAC
	now                  func() time.Time
	input                analysisapp.ContextQueryInput
	inputChecked         bool
	delivery             *analysisapp.ContextProjectionDelivery
	association          analysisapp.ContextProjectionAssociation
	refusal              analysisapp.ContextProjectionRefusal
	outputDigest         artifact.Digest
	outputBytes          int64
	metadataUntil        time.Time
	acknowledged, closed bool
}

func queryCall(in audit.OperationIntent) value.ContextQueryCall {
	return value.ContextQueryCall{ID: in.ID, RootID: in.RootID, Tool: in.Name,
		InputFormat: in.InputFormat, MACVersion: in.MACVersion, InputDigest: in.InputDigest,
		PrincipalDigest: in.PrincipalDigest, Principal: in.Actor,
		StartedAt: in.CreatedAt, Until: in.RequestUntil, WriteUntil: in.WriteUntil}
}

func newContextQueryInvocation(ctx context.Context, in audit.OperationIntent, mac *auditapp.OperationMAC, now func() time.Time) *contextQueryInvocation {
	return &contextQueryInvocation{ctx: ctx, intent: in, call: queryCall(in), mac: mac, now: now}
}

func (i *contextQueryInvocation) current(ctx context.Context) bool {
	return i != nil && ctx != nil && ctx.Err() == nil && i.ctx != nil && i.ctx.Err() == nil &&
		!i.closed && i.now != nil && i.call.Valid(i.now())
}

func (i *contextQueryInvocation) Invocation(ctx context.Context) (value.ContextQueryCall, error) {
	if i == nil {
		return value.ContextQueryCall{}, ErrOperationDelivery
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.current(ctx) {
		return value.ContextQueryCall{}, ErrOperationDelivery
	}
	return i.call, nil
}

func (i *contextQueryInvocation) CheckIntent(ctx context.Context, call value.ContextQueryCall) error {
	if i == nil {
		return ErrOperationDelivery
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.current(ctx) || call != i.call {
		return ErrOperationDelivery
	}
	return nil
}

// Compare the consumer's typed selection with the same normalized input MAC
// used by Begin. Defaults, display version, tool and query handle remain bound.
func (i *contextQueryInvocation) CheckInput(ctx context.Context, in analysisapp.ContextQueryInput) error {
	if i == nil {
		return ErrOperationDelivery
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.current(ctx) || i.mac == nil {
		return ErrOperationDelivery
	}
	if i.call.Tool != "get_logs" && in.RawLogs != (value.RawLogQueryRequest{}) {
		return ErrOperationDelivery
	}
	if i.call.Tool != "syscall_query" && in.RawSyscalls != (value.RawSyscallQueryRequest{}) {
		return ErrOperationDelivery
	}
	if i.call.Tool != "pcap_query" && !reflect.DeepEqual(in.PacketQuery, value.PacketQueryRequest{}) {
		return ErrOperationDelivery
	}
	if i.call.Tool != "get_pcap_summary" && in.Packet != (value.PacketSummaryRequest{}) {
		return ErrOperationDelivery
	}
	var raw []byte
	var err error
	switch i.call.Tool {
	case "get_logs":
		if !in.RawLogs.Valid() || in.QueryID != "" || !reflect.DeepEqual(in.PacketQuery, value.PacketQueryRequest{}) || in.RawSyscalls != (value.RawSyscallQueryRequest{}) || in.Packet != (value.PacketSummaryRequest{}) || in.Comparison != (value.ProfileComparisonRequest{}) || in.Selection != (value.ContextExcerptSelection{}) || in.Headers != (value.HTTPHeaderSelection{}) || in.Profile != (value.ProfileSummaryRequest{}) || in.Syscalls != (value.SyscallQueryRequest{}) {
			return ErrOperationDelivery
		}
		raw, err = json.Marshal(rawLogInput(in.RawLogs))
	case "syscall_query":
		if !in.RawSyscalls.Valid() || in.QueryID != "" || !reflect.DeepEqual(in.PacketQuery, value.PacketQueryRequest{}) || in.Packet != (value.PacketSummaryRequest{}) || in.Comparison != (value.ProfileComparisonRequest{}) || in.Selection != (value.ContextExcerptSelection{}) || in.Headers != (value.HTTPHeaderSelection{}) || in.Profile != (value.ProfileSummaryRequest{}) || in.Syscalls != (value.SyscallQueryRequest{}) {
			return ErrOperationDelivery
		}
		raw, err = json.Marshal(rawSyscallInput(in.RawSyscalls))
	case "pcap_query":
		if !in.PacketQuery.Valid() || in.QueryID != "" || in.Packet != (value.PacketSummaryRequest{}) || in.Selection != (value.ContextExcerptSelection{}) || in.Headers != (value.HTTPHeaderSelection{}) || in.Profile != (value.ProfileSummaryRequest{}) || in.Syscalls != (value.SyscallQueryRequest{}) || in.Comparison != (value.ProfileComparisonRequest{}) {
			return ErrOperationDelivery
		}
		raw, err = json.Marshal(packetQueryInput(in.PacketQuery))
	case "get_pcap_summary":
		if !in.Packet.Valid() || in.QueryID != "" || in.Comparison != (value.ProfileComparisonRequest{}) || in.Selection != (value.ContextExcerptSelection{}) || in.Headers != (value.HTTPHeaderSelection{}) || in.Profile != (value.ProfileSummaryRequest{}) || in.Syscalls != (value.SyscallQueryRequest{}) {
			return ErrOperationDelivery
		}
		raw, err = json.Marshal(PacketSummaryOperationInput{CaseID: in.Packet.CaseID, ArtifactID: in.Packet.ArtifactID})
	case "get_file_excerpt":
		if !in.Selection.Valid() || in.QueryID != "" || in.Comparison != (value.ProfileComparisonRequest{}) || in.Headers != (value.HTTPHeaderSelection{}) || in.Profile != (value.ProfileSummaryRequest{}) || in.Syscalls != (value.SyscallQueryRequest{}) {
			return ErrOperationDelivery
		}
		raw, err = json.Marshal(struct {
			CaseID     string `json:"case_id"`
			ArtifactID string `json:"artifact_id"`
			LineStart  int    `json:"line_start"`
			MaxLines   int    `json:"max_lines"`
		}{in.Selection.CaseID, in.Selection.ArtifactID, in.Selection.Selection.LineStart, in.Selection.Selection.MaxLines})
	case "get_http_headers":
		if !in.Headers.Valid() || in.QueryID != "" || in.Comparison != (value.ProfileComparisonRequest{}) || in.Selection != (value.ContextExcerptSelection{}) || in.Profile != (value.ProfileSummaryRequest{}) || in.Syscalls != (value.SyscallQueryRequest{}) {
			return ErrOperationDelivery
		}
		raw, err = json.Marshal(HTTPHeaderOperationInput{CaseID: in.Headers.CaseID, ArtifactID: in.Headers.ArtifactID, Cursor: httpHeaderCursorText(in.Headers), Limit: in.Headers.Limit})
	case "compare_profiles":
		if !in.Comparison.Valid() || in.QueryID != "" || in.Selection != (value.ContextExcerptSelection{}) || in.Headers != (value.HTTPHeaderSelection{}) || in.Profile != (value.ProfileSummaryRequest{}) || in.Syscalls != (value.SyscallQueryRequest{}) {
			return ErrOperationDelivery
		}
		c := in.Comparison
		raw, err = json.Marshal(ProfileComparisonOperationInput{CaseID: c.CaseID, ArtifactID: c.ArtifactID, BaselineCaseID: c.BaselineCaseID, BaselineArtifactID: c.BaselineArtifactID, SampleType: c.Selection.SampleType, Normalization: c.Selection.Normalization, TopN: c.Selection.TopN})

	case "get_profile_summary":
		if !in.Profile.Valid() || in.QueryID != "" || in.Comparison != (value.ProfileComparisonRequest{}) || in.Selection != (value.ContextExcerptSelection{}) || in.Headers != (value.HTTPHeaderSelection{}) || in.Syscalls != (value.SyscallQueryRequest{}) {
			return ErrOperationDelivery
		}
		raw, err = json.Marshal(ProfileSummaryOperationInput{CaseID: in.Profile.CaseID, ArtifactID: in.Profile.ArtifactID, SampleType: in.Profile.Selection.SampleType, TopN: in.Profile.Selection.TopN})
	case "get_syscall_summary", "get_syscall_events":
		if !in.Syscalls.Valid() || in.Syscalls.Selection.View != syscallView(i.call.Tool) || in.QueryID != "" || in.Comparison != (value.ProfileComparisonRequest{}) || in.Selection != (value.ContextExcerptSelection{}) || in.Headers != (value.HTTPHeaderSelection{}) || in.Profile != (value.ProfileSummaryRequest{}) {
			return ErrOperationDelivery
		}
		w := in.Syscalls.Selection
		cursor := ""
		if w.Start != 0 {
			cursor = strconv.Itoa(w.Start) + ":" + w.Binding
		}
		raw, err = json.Marshal(SyscallOperationInput{CaseID: in.Syscalls.CaseID, ArtifactID: in.Syscalls.ArtifactID, Cursor: cursor, Limit: w.Limit, Names: w.Selection(in.Syscalls.CaseID, in.Syscalls.ArtifactID).Names, ErrorsOnly: w.ErrorsOnly})
	case "get_query_result":
		if !authorization.UUID(in.QueryID) || in.Comparison != (value.ProfileComparisonRequest{}) || in.Selection != (value.ContextExcerptSelection{}) || in.Headers != (value.HTTPHeaderSelection{}) || in.Profile != (value.ProfileSummaryRequest{}) || in.Syscalls != (value.SyscallQueryRequest{}) {
			return ErrOperationDelivery
		}
		raw, err = json.Marshal(struct {
			QueryHandle string `json:"query_handle"`
		}{in.QueryID})
	default:
		return ErrOperationDelivery
	}
	defer clear(raw)
	if err != nil {
		return ErrOperationDelivery
	}
	normalized, err := normalizeQueryInput(i.call.Tool, raw)
	defer clear(normalized)
	if err != nil {
		return ErrOperationDelivery
	}
	digest, err := i.mac.Digest(i.call.InputFormat, normalized)
	if err != nil || digest != i.call.InputDigest || !i.current(ctx) || i.inputChecked && !reflect.DeepEqual(i.input, in) {
		return ErrOperationDelivery
	}
	in.PacketQuery = analysisapp.NormalizePacketQueryRequest(in.PacketQuery)
	i.input, i.inputChecked = in, true
	return nil
}

func (i *contextQueryInvocation) bind(ctx context.Context, d *analysisapp.ContextProjectionDelivery, bytes int64) error {
	if i == nil || d == nil {
		return ErrOperationDelivery
	}
	a := d.Association()
	selected := false
	branches := 0
	if a.Selection.Valid() {
		branches++
	}
	if a.Headers.Valid() {
		branches++
	}
	if a.Profile.Valid() {
		branches++
	}
	if a.Comparison.Valid() {
		branches++
	}
	if a.Syscalls.Valid() {
		branches++
	}
	if a.Logs.Valid() {
		branches++
	}
	if a.PacketQuery.Valid() {
		branches++
	}
	if d.Tool() == "get_pcap_summary" {
		branches++
	}
	selected = branches == 1 && (a.Logs.Valid() || a.Logs == (value.LogWindow{})) && (a.Selection.Valid() || a.Selection == (value.LineSelection{})) && (a.Headers.Valid() || a.Headers == (value.HTTPHeaderWindow{})) && (a.Profile.Valid() || a.Profile == (value.ProfileSummarySelection{})) && (a.Syscalls.Valid() || a.Syscalls == (value.SyscallWindow{})) && (a.Comparison.Valid() || a.Comparison == (value.ProfileComparisonSelection{}))

	if !authorization.UUID(a.ID) || !authorization.UUID(a.QueryID) || !selected || !a.PacketQuery.Valid() && a.PacketQuery != (value.PacketQueryWindow{}) {
		return ErrOperationDelivery
	}
	until := d.ValidUntil()
	refusal := d.Refusal()
	baseline, incident, hasComparisonSources := d.ProfileComparisonSources()
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.current(ctx) || !i.inputChecked || i.delivery != nil || !authorization.UUID(a.ID) ||
		!authorization.UUID(a.QueryID) || a.OperationID != i.call.ID ||
		!i.now().Before(until) || until.After(i.call.Until) || bytes <= 0 || bytes > audit.OperationOutputLimit {
		return ErrOperationDelivery
	}
	if i.call.Tool == "compare_profiles" && (!hasComparisonSources || baseline.CaseID != i.input.Comparison.BaselineCaseID || baseline.ArtifactID != i.input.Comparison.BaselineArtifactID || incident.CaseID != i.input.Comparison.CaseID || incident.ArtifactID != i.input.Comparison.ArtifactID) {
		return ErrOperationDelivery
	}
	if i.call.Tool != "compare_profiles" && i.call.Tool != "get_query_result" && a.Comparison != (value.ProfileComparisonSelection{}) ||
		i.call.Tool == "compare_profiles" && (a.Comparison != i.input.Comparison.Selection || a.Selection != (value.LineSelection{}) || a.Headers != (value.HTTPHeaderWindow{}) || a.Profile != (value.ProfileSummarySelection{}) || a.Syscalls != (value.SyscallWindow{})) ||
		i.call.Tool == "get_file_excerpt" && (a.Selection != i.input.Selection.Selection || a.Headers != (value.HTTPHeaderWindow{}) || a.Profile != (value.ProfileSummarySelection{}) || a.Syscalls != (value.SyscallWindow{})) ||
		i.call.Tool == "get_http_headers" && (a.Headers != i.input.Headers.Window() || a.Selection != (value.LineSelection{}) || a.Profile != (value.ProfileSummarySelection{}) || a.Syscalls != (value.SyscallWindow{})) ||
		i.call.Tool == "get_profile_summary" && (a.Profile != i.input.Profile.Selection || a.Selection != (value.LineSelection{}) || a.Headers != (value.HTTPHeaderWindow{}) || a.Syscalls != (value.SyscallWindow{})) ||
		i.call.Tool == "get_pcap_summary" && (a.Selection != (value.LineSelection{}) || a.Headers != (value.HTTPHeaderWindow{}) || a.Profile != (value.ProfileSummarySelection{}) || a.Syscalls != (value.SyscallWindow{})) ||
		syscallQueryOperation(i.call.Tool) && (a.Syscalls != i.input.Syscalls.Selection || a.Selection != (value.LineSelection{}) || a.Headers != (value.HTTPHeaderWindow{}) || a.Profile != (value.ProfileSummarySelection{})) ||
		i.call.Tool == "get_query_result" && a.QueryID != i.input.QueryID {
		return ErrOperationDelivery
	}
	if i.call.Tool == "syscall_query" && (a.Syscalls != i.input.RawSyscalls.Selection || a.Selection != (value.LineSelection{}) || a.Headers != (value.HTTPHeaderWindow{}) || a.Profile != (value.ProfileSummarySelection{}) || a.Comparison != (value.ProfileComparisonSelection{})) {
		return ErrOperationDelivery
	}
	if i.call.Tool != "get_logs" && i.call.Tool != "get_query_result" && a.Logs != (value.LogWindow{}) {
		return ErrOperationDelivery
	}
	if i.call.Tool == "get_logs" && (a.Logs != i.input.RawLogs.Selection || a.Selection != (value.LineSelection{}) || a.Headers != (value.HTTPHeaderWindow{}) || a.Profile != (value.ProfileSummarySelection{}) || a.Syscalls != (value.SyscallWindow{}) || a.PacketQuery != (value.PacketQueryWindow{}) || a.Comparison != (value.ProfileComparisonSelection{})) {
		return ErrOperationDelivery
	}
	if i.call.Tool != "pcap_query" && i.call.Tool != "get_query_result" && a.PacketQuery != (value.PacketQueryWindow{}) {
		return ErrOperationDelivery
	}
	if i.call.Tool == "pcap_query" {
		w, e := i.input.PacketQuery.Selection(a.PacketQuery.Selection().Program).Window()
		if e != nil || w != a.PacketQuery || a.Selection != (value.LineSelection{}) || a.Headers != (value.HTTPHeaderWindow{}) || a.Profile != (value.ProfileSummarySelection{}) || a.Syscalls != (value.SyscallWindow{}) || a.Comparison != (value.ProfileComparisonSelection{}) {
			return ErrOperationDelivery
		}
	}
	if d.Pending() {
		expected := analysisapp.ContextQueryAdmitted
		if i.call.Tool == "get_query_result" {
			expected = analysisapp.ContextQueryPollCharged
		}
		if (i.call.Tool == "get_logs" || i.call.Tool == "pcap_query" || i.call.Tool == "syscall_query") && d.Effect() == analysisapp.ContextQueryReplayed {
			expected = analysisapp.ContextQueryReplayed
		}
		if a.BatchID != "" || a.Generation != 0 || d.Effect() != expected || refusal != analysisapp.ContextProjectionNoRefusal {
			return ErrOperationDelivery
		}
	} else if !authorization.UUID(a.BatchID) || a.Generation < 1 || a.Generation > value.ContextMaxReadBatches || d.Effect() != analysisapp.ContextQueryReadCharged {
		return ErrOperationDelivery
	}
	i.delivery, i.association, i.outputBytes, i.metadataUntil = d, a, bytes, until
	i.refusal = refusal
	return nil
}

// Called only by the private reply owner after the existing Finish has
// acknowledged the exact canonical body. The owner separately checks unchanged
// bytes; this records that existing keyed outcome digest without re-auditing.
func (i *contextQueryInvocation) acknowledge(ctx context.Context, out audit.OperationOutcome) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	status, reason := "success", "prepared"
	switch i.refusal {
	case analysisapp.ContextProjectionNoRefusal:
	case analysisapp.ContextProjectionInvalidCursor:
		status, reason = "invalid", "invalid_input"
	case analysisapp.ContextProjectionRecordTooLarge, analysisapp.ContextProjectionIncompatibleProfiles:
		status, reason = "denied", "not_available"
	default:
		return ErrOperationDelivery
	}
	if !i.current(ctx) || i.delivery == nil || i.acknowledged || !out.Valid() || out.Intent != i.intent ||
		out.Status != status || out.Reason != reason || out.Effect != queryDeliveryAuditEffect(i.delivery) || i.delivery.Refusal() != i.refusal ||
		out.OutputBytes != i.outputBytes || out.MetadataUntil.After(i.metadataUntil) || !i.now().Before(out.MetadataUntil) {
		return ErrOperationDelivery
	}
	i.outputDigest, i.metadataUntil, i.acknowledged = out.OutputDigest, out.MetadataUntil, true
	return nil
}

func (i *contextQueryInvocation) CheckOutcome(ctx context.Context, d *analysisapp.ContextProjectionDelivery) error {
	if i == nil || d == nil {
		return ErrOperationDelivery
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.current(ctx) || !i.acknowledged || i.outputDigest == (artifact.Digest{}) ||
		i.delivery != d || d.Association() != i.association || d.Refusal() != i.refusal || !i.now().Before(i.metadataUntil) {
		return ErrOperationDelivery
	}
	return nil
}

func (i *contextQueryInvocation) close() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.closed = true
	i.delivery = nil
	i.outputDigest = artifact.Digest{}
}

var _ analysisapp.ContextQueryInvocation = (*contextQueryInvocation)(nil)

// httpHeaderCursorText is the public cursor a normalized selection was read
// from: empty on the first page, otherwise the canonical index and binding.
func httpHeaderCursorText(s value.HTTPHeaderSelection) string {
	if s.Start == 0 {
		return ""
	}
	return strconv.Itoa(s.Start) + ":" + s.Binding
}

func queryDeliveryAuditEffect(d *analysisapp.ContextProjectionDelivery) string {
	if d != nil && d.Effect() == analysisapp.ContextQueryReplayed {
		return "none"
	}
	return "accepted"
}
