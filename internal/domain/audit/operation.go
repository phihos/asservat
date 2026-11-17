package audit

import (
	"slices"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
)

const OperationCipherLimit = 64 << 10
const OperationOutputLimit = 24 << 10

// OperationResultBound is the MCP result bound (specs/mcp.md) of the
// settings and preview results.
const OperationResultBound = 96 << 10

// Only the authenticated browser settings view has this larger prepared-byte
// maximum. Audit stores the HMAC/count/refs, never the parameter response body.
const OperationCaptureSettingsOutputLimit = 160 << 10

const OperationGrantReviewOutputLimit = 256 << 10

// operationKind classifies one public or internal operation for audit.
type operationKind struct {
	format string        // accepted audit input format
	window time.Duration // maximum request interval
	effect bool          // may record an accepted or unknown effect
	output int64         // prepared output byte maximum
}

const (
	contextInput    = "context-input/v1"
	queryInput      = "context-query-input/v1"
	nativeInput     = "native-content-input/v1"
	processingInput = "processing-input/v1"
	ordinaryWindow  = 5 * time.Second
)

// operations lists every audited operation, one per line. Evidence reads use
// the twenty-second evidence window, capture preview/submission their own;
// every contained authority retains its own bound. A live read holds two
// authority checks around a bounded node wait; measured installed reads take
// four to six seconds.
var operations = map[string]operationKind{
	"cancel_capture":             {contextInput, ordinaryWindow, true, OperationOutputLimit},
	"compare_profiles":           {queryInput, identity.EvidenceReadRequestWindow, true, OperationOutputLimit},
	"create_share":               {contextInput, ordinaryWindow, true, OperationOutputLimit},
	"deactivate_policy":          {contextInput, ordinaryWindow, true, OperationOutputLimit},
	"decide_review":              {contextInput, identity.RecordingSaveRequestWindow, true, OperationOutputLimit},
	"download_artifact":          {contextInput, identity.EvidenceReadRequestWindow, true, OperationOutputLimit},
	"download_artifact_content":  {nativeInput, ordinaryWindow, false, OperationOutputLimit},
	"explain_access":             {contextInput, ordinaryWindow, false, OperationOutputLimit},
	"get_capture":                {contextInput, ordinaryWindow, false, OperationCaptureSettingsOutputLimit},
	"get_capture_profile":        {contextInput, ordinaryWindow, false, OperationOutputLimit},
	"get_case":                   {contextInput, ordinaryWindow, false, OperationOutputLimit},
	"get_extract":                {queryInput, identity.EvidenceReadRequestWindow, true, OperationOutputLimit},
	"get_grant":                  {contextInput, ordinaryWindow, false, OperationGrantReviewOutputLimit},
	"get_policy_status":          {contextInput, ordinaryWindow, false, OperationOutputLimit},
	"get_processing_erasure":     {contextInput, ordinaryWindow, false, OperationOutputLimit},
	"get_processing_report":      {contextInput, ordinaryWindow, false, OperationOutputLimit},
	"get_query_result":           {queryInput, identity.EvidenceReadRequestWindow, true, OperationOutputLimit},
	"initialize_processing":      {processingInput, ordinaryWindow, false, OperationOutputLimit},
	"invalid_operation":          {contextInput, ordinaryWindow, false, OperationOutputLimit},
	"list_capture_history":       {contextInput, ordinaryWindow, false, OperationOutputLimit},
	"list_diagnostics":           {contextInput, ordinaryWindow, false, OperationOutputLimit},
	"list_recordings":            {contextInput, identity.EvidenceReadRequestWindow, false, OperationOutputLimit},
	"list_reviews":               {contextInput, ordinaryWindow, false, OperationOutputLimit},
	"list_shares":                {contextInput, ordinaryWindow, false, OperationOutputLimit},
	"preview_access_change":      {contextInput, ordinaryWindow, false, OperationOutputLimit},
	"preview_capture":            {contextInput, identity.CapturePreviewRequestWindow, false, OperationResultBound},
	"preview_retention_change":   {contextInput, ordinaryWindow, false, OperationOutputLimit},
	"query_artifact":             {queryInput, identity.EvidenceReadRequestWindow, true, OperationOutputLimit},
	"release_processing":         {processingInput, ordinaryWindow, true, OperationOutputLimit},
	"request_capture":            {contextInput, identity.RecordingSaveRequestWindow, true, OperationOutputLimit},
	"request_early_erasure":      {processingInput, ordinaryWindow, true, OperationOutputLimit},
	"request_raw_access":         {contextInput, ordinaryWindow, true, OperationOutputLimit},
	"restrict_processing":        {processingInput, ordinaryWindow, true, OperationOutputLimit},
	"revoke_grant":               {contextInput, ordinaryWindow, true, OperationOutputLimit},
	"revoke_share":               {contextInput, ordinaryWindow, true, OperationOutputLimit},
	"search_processing_evidence": {contextInput, ordinaryWindow, false, OperationOutputLimit},
	"stop_future_sharing":        {contextInput, ordinaryWindow, true, OperationOutputLimit},
	"transfer_share":             {contextInput, ordinaryWindow, true, OperationOutputLimit},
	"watch_live":                 {contextInput, identity.EvidenceReadRequestWindow, true, OperationOutputLimit},
}

// OperationLane is server-selected from the fixed operation, never supplied
// by a caller. release_processing has its own lane.
func OperationLane(name string) string {
	if _, ok := operations[name]; !ok {
		return ""
	}
	if name == "release_processing" {
		return "processing"
	}
	return "normal"
}

// StatusWait is the longest server-side after_revision wait of a status read
// (mcp-tools.json: "or 30 seconds pass").
const StatusWait = 30 * time.Second

// OperationTransportWindow bounds one HTTP request: for the status reads it
// also covers one after_revision wait and the second read.
func OperationTransportWindow(name string) time.Duration {
	switch name {
	case "get_capture", "get_grant", "download_artifact":
		return max(OperationRequestWindow(name), identity.StatusWaitRequestWindow)
	}
	return OperationRequestWindow(name)
}

// OperationRequestWindow is the maximum request interval of an operation.
func OperationRequestWindow(name string) time.Duration {
	if k, ok := operations[name]; ok {
		return k.window
	}
	return ordinaryWindow
}

// OperationIntent contains only bounded audit facts. It is not a permit, and
// persisted identity/deadline fields never become current caller authority.
type OperationIntent struct {
	ID, RootID, TraceID, Name, InputFormat, MACVersion, AccountVersion string
	Actor                                                              identity.Principal `json:",omitzero"`
	PrincipalDigest, InputDigest                                       artifact.Digest
	CreatedAt, RequestUntil, WriteUntil, RetainUntil                   time.Time
}

func (r OperationIntent) Valid() bool {
	for _, t := range []time.Time{r.CreatedAt, r.RequestUntil, r.WriteUntil, r.RetainUntil} {
		if t.IsZero() || t.Nanosecond()%1000 != 0 {
			return false
		}
	}
	return authorization.UUID(r.ID) && authorization.UUID(r.RootID) && authorization.UUID(r.TraceID) && OperationLane(r.Name) != "" &&
		r.Actor.Valid() && humanOperationInputValid(r.Name, r.InputFormat) && identity.Text(r.MACVersion, 64) && identity.Text(r.AccountVersion, 64) &&
		r.PrincipalDigest != (artifact.Digest{}) && r.InputDigest != (artifact.Digest{}) &&
		identity.Fresh(r.CreatedAt, r.RequestUntil, r.CreatedAt, OperationRequestWindow(r.Name)) && r.WriteUntil.After(r.CreatedAt) && !r.WriteUntil.After(r.CreatedAt.Add(30*time.Second)) &&
		!r.RequestUntil.After(r.WriteUntil) && r.RetainUntil.After(r.WriteUntil) && !r.RetainUntil.After(r.CreatedAt.Add(3660*24*time.Hour))
}

// Outcome describes prepared bytes, never client receipt. References may only
// come from an already authorized successful result, never echoed input IDs.
type OperationOutcome struct {
	Intent                                OperationIntent
	Status, Reason, Effect, ClientReceipt string
	CaseIDs, ArtifactIDs, CaptureIDs      []string
	OutputDigest                          artifact.Digest
	OutputBytes                           int64
	MetadataUntil, RecordedAt             time.Time
}

func (r OperationOutcome) Valid() bool {
	if !r.Intent.Valid() || !slices.Contains([]string{"success", "denied", "invalid", "unavailable", "interrupted"}, r.Status) ||
		!slices.Contains([]string{"prepared", "not_available", "invalid_input", "authority_unavailable", "interrupted"}, r.Reason) ||
		!slices.Contains([]string{"none", "accepted", "unknown"}, r.Effect) || r.ClientReceipt != "unknown" || r.OutputBytes < 0 || r.OutputBytes > operations[r.Intent.Name].output ||
		r.OutputDigest == (artifact.Digest{}) || r.RecordedAt.Before(r.Intent.CreatedAt) || !r.RecordedAt.Before(r.Intent.WriteUntil) ||
		r.MetadataUntil.Before(r.Intent.CreatedAt) || r.MetadataUntil.After(r.Intent.RequestUntil) {
		return false
	}
	if r.Effect != "none" && !operations[r.Intent.Name].effect {
		return false
	}
	if r.Status != "success" && (len(r.CaseIDs) > 0 || len(r.ArtifactIDs) > 0 || len(r.CaptureIDs) > 0) {
		return false
	}
	for _, ids := range [][]string{r.CaseIDs, r.ArtifactIDs, r.CaptureIDs} {
		if len(ids) > 100 {
			return false
		}
		seen := map[string]bool{}
		for _, id := range ids {
			if !authorization.UUID(id) || seen[id] {
				return false
			}
			seen[id] = true
		}
	}
	return true
}

// Closed internal classification, separate from public tool discovery. Keeping
// this branch explicit prevents a private peer operation accepting human data.
func humanOperationInputValid(name, format string) bool {
	k, ok := operations[name]
	// The processing reads accept no invalid-input form.
	strict := name == "search_processing_evidence" || name == "get_processing_erasure" || name == "get_processing_report"
	return ok && (format == k.format || k.format == contextInput && !strict && format == "invalid-input/v1")
}
