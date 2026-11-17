package presentation

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
)

// queryOperation reports whether name is a public approved-read tool.
func queryOperation(name string) bool {
	return name == "get_extract" || name == "query_artifact" || name == "compare_profiles" || name == "get_query_result"
}

// projectionOperations maps a public tool and its view or operation to the
// internal query operation the application layer and SQL record. Canonical
// views without an entry are CapabilityUnavailable.
var projectionOperations = map[string]string{
	"get_extract/fileExcerpt":    "get_file_excerpt",
	"get_extract/httpHeaders":    "get_http_headers",
	"get_extract/profileSummary": "get_profile_summary",
	"get_extract/pcapSummary":    "get_pcap_summary",
	"get_extract/syscallSummary": "get_syscall_summary",
	"get_extract/syscallEvents":  "get_syscall_events",
	"get_extract/logs":           "get_logs",
	"query_artifact/packets":     "pcap_query",
	"query_artifact/syscalls":    "syscall_query",
	"compare_profiles/":          "compare_profiles",
	"get_query_result/":          "get_query_result",
}

// publicTool names the public tool of an internal query operation.
func publicTool(operation string) string {
	for k, v := range projectionOperations {
		if v == operation {
			tool, _, _ := strings.Cut(k, "/")
			return tool
		}
	}
	return ""
}

type packetQueryFlagInput struct {
	Mask  uint16 `json:"mask"`
	Value uint16 `json:"value"`
}
type packetQueryPrefixInput struct {
	Offset uint16 `json:"offset"`
	Length uint16 `json:"length"`
}

// projectionInput is the union of the canonical projection tool inputs; the
// schema already admitted exactly one view's or operation's argument set.
type projectionInput struct {
	View               string                   `json:"view,omitempty"`
	Operation          string                   `json:"operation,omitempty"`
	CaseID             string                   `json:"case_id,omitempty"`
	ArtifactID         string                   `json:"artifact_id,omitempty"`
	BaselineCaseID     string                   `json:"baseline_case_id,omitempty"`
	BaselineArtifactID string                   `json:"baseline_artifact_id,omitempty"`
	SampleType         string                   `json:"sample_type,omitempty"`
	Normalization      string                   `json:"normalization,omitempty"`
	Cursor             string                   `json:"cursor,omitempty"`
	Limit              int                      `json:"limit,omitempty"`
	LineStart          int                      `json:"line_start,omitempty"`
	Names              []string                 `json:"syscall_names,omitempty"`
	ErrorsOnly         bool                     `json:"errors_only,omitempty"`
	GrantID            string                   `json:"grant_id,omitempty"`
	IdempotencyKey     string                   `json:"idempotency_key,omitempty"`
	QueryHandle        string                   `json:"query_handle,omitempty"`
	PacketFilter       string                   `json:"packet_filter,omitempty"`
	Fields             []value.PacketQueryField `json:"fields,omitempty"`
	StartTime          *time.Time               `json:"start_time,omitempty"`
	EndTime            *time.Time               `json:"end_time,omitempty"`
	TCPFlags           *packetQueryFlagInput    `json:"tcp_flags,omitempty"`
	FramePrefix        *packetQueryPrefixInput  `json:"frame_prefix,omitempty"`
}

// pageMaximum is each operation's page bound: a page must fit the 24 KiB
// response. A larger requested limit returns that page with next_cursor.
var pageMaximum = map[string]int{
	"get_file_excerpt":    200,
	"get_http_headers":    value.HTTPHeaderPageRecords,
	"get_profile_summary": value.ProfileSummaryMaximumTop,
	"compare_profiles":    value.ProfileSummaryMaximumTop,
	"get_syscall_summary": value.SyscallPageRecords,
	"get_syscall_events":  value.SyscallPageRecords,
	"syscall_query":       value.SyscallPageRecords,
	"get_logs":            value.LogPageRecords,
	"pcap_query":          value.PacketQueryMaxPackets,
}

// decodeProjection returns the internal operation ("" when unsupported) and
// the normalized input of one schema-valid public call.
func decodeProjection(name string, raw []byte) (string, projectionInput, error) {
	var in projectionInput
	if err := json.Unmarshal(raw, &in); err != nil {
		return "", in, err
	}
	op := projectionOperations[name+"/"+in.View+in.Operation]
	if m := pageMaximum[op]; in.Limit > m {
		in.Limit = m
	}
	if op == "pcap_query" && in.Limit == 0 {
		in.Limit = value.PacketQueryMaxPackets
	}
	in.Names = slices.Clone(in.Names)
	slices.Sort(in.Names)
	return op, in, nil
}

// normalizeQueryInput is the audited input: the internal operation and its
// normalized arguments.
func normalizeQueryInput(name string, raw []byte) ([]byte, error) {
	op, in, err := decodeProjection(name, raw)
	if err != nil {
		return nil, err
	}
	if op == "" {
		op = name
	}
	return json.Marshal(struct {
		Tool  string
		Input projectionInput
	}{op, in})
}
