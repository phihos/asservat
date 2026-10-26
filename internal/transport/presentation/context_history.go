package presentation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"strconv"
	"strings"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	planning "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
)

// CaptureHistoryEntry is one canonical capture-history.schema.json entry.
type CaptureHistoryEntry struct {
	CaptureID       string    `json:"capture_id"`
	Origin          string    `json:"origin"`
	AcceptedAt      time.Time `json:"accepted_at"`
	SummaryExpires  time.Time `json:"summary_expires_at"`
	Phase           string    `json:"phase"`
	ActionKinds     []string  `json:"action_kinds"`
	EvidenceState   string    `json:"evidence_state"`
	RepeatState     string    `json:"repeat_state"`
	SettingsExpires time.Time `json:"settings_expires_at"`
	NavigationURI   string    `json:"navigation_uri"`
	Operation       string    `json:"operation"`
}
type CaptureHistoryPage struct {
	Kind     string                `json:"kind"`
	History  []CaptureHistoryEntry `json:"history"`
	Ordering string                `json:"ordering"`
}
type CaptureSettingsView struct {
	Target             json.RawMessage `json:"target"`
	RecipeSpec         json.RawMessage `json:"recipe_spec"`
	DependencyPins     json.RawMessage `json:"dependency_pins"`
	RequestedRetention string          `json:"requested_retention"`
}
type CaptureSettingsRecord struct {
	Kind            string              `json:"kind"`
	CaptureID       string              `json:"capture_id"`
	ClusterID       string              `json:"cluster_id"`
	NamespaceUID    string              `json:"namespace_uid"`
	AcceptedAt      time.Time           `json:"accepted_at"`
	ExpiresAt       time.Time           `json:"expires_at"`
	SettingsDigest  string              `json:"settings_digest"`
	ExecutionDigest string              `json:"original_execution_digest"`
	Settings        CaptureSettingsView `json:"settings"`
	NavigationURI   string              `json:"navigation_uri"`
}

// historyCursorSelector binds a cursor to its selector and origin filter, so
// it cannot continue another list. It only positions a page: every page
// authorizes every row again, so a cursor needs no caller binding or MAC.
func historyCursorSelector(in ContextOperationInput) string {
	b, _ := json.Marshal([]string{in.Target.ClusterID, in.Target.Namespace, in.Target.Kind, in.Target.Name, historyOrigin(in.Origin)})
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:8])
}
func historyOrigin(origin string) string {
	if origin == "" {
		return "manual"
	}
	return origin
}
func encodeHistoryCursor(in ContextOperationInput, c *value.HistoryCursor) *string {
	if c == nil {
		return nil
	}
	s := base64.RawURLEncoding.EncodeToString([]byte("history/v1|" + historyCursorSelector(in) + "|" + strconv.FormatInt(c.AcceptedAt.UnixMicro(), 10) + "|" + c.CaptureID))
	return &s
}
func decodeHistoryCursor(in ContextOperationInput) (*value.HistoryCursor, error) {
	if in.Cursor == "" {
		return nil, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(in.Cursor)
	parts := strings.Split(string(b), "|")
	if err != nil || len(parts) != 4 || parts[0] != "history/v1" || parts[1] != historyCursorSelector(in) || !authorization.UUID(parts[3]) {
		return nil, value.ErrInvalid
	}
	micros, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || micros <= 0 {
		return nil, value.ErrInvalid
	}
	return &value.HistoryCursor{AcceptedAt: time.UnixMicro(micros).UTC(), CaptureID: parts[3]}, nil
}

// historyCall serves list_capture_history and get_capture_settings.
func (s *ContextOperations) historyCall(ctx context.Context, current identities.CurrentIdentity, name string, in ContextOperationInput) (any, *string, time.Time, error) {
	if name == "get_capture_settings" {
		settings, err := s.history.Settings(ctx, current, in.CaptureID)
		if err != nil {
			return nil, nil, time.Time{}, err
		}
		view := CaptureSettingsView{Target: settings.TargetJSON, RecipeSpec: json.RawMessage(planning.ContextRecipeSpec), DependencyPins: settings.DependencyJSON, RequestedRetention: strconv.FormatInt(settings.RequestedSeconds, 10) + "s"}
		b, err := json.Marshal(view)
		if err != nil {
			return nil, nil, time.Time{}, value.ErrUnavailable
		}
		canonical := jsontext.Value(b)
		if canonical.Canonicalize() != nil || json.Unmarshal(canonical, &view) != nil {
			return nil, nil, time.Time{}, value.ErrUnavailable
		}
		d := sha256.Sum256(canonical)
		return CaptureSettingsRecord{Kind: "captureSettings", CaptureID: settings.CaptureID, ClusterID: settings.ClusterID, NamespaceUID: settings.NamespaceUID, AcceptedAt: settings.AcceptedAt, ExpiresAt: settings.ExpiresAt,
			SettingsDigest: hex.EncodeToString(d[:]), ExecutionDigest: hash(settings.ExecutionDigest), Settings: view, NavigationURI: s.config.PublicOrigin + "/captures/" + settings.CaptureID}, nil, settings.ValidUntil, nil
	}
	origins := []value.HistoryOrigin{value.HistoryManual}
	switch in.Origin {
	case "", "manual":
	case "policy":
		origins = []value.HistoryOrigin{value.HistoryPolicy}
	case "all":
		origins = []value.HistoryOrigin{value.HistoryManual, value.HistoryPolicy}
	default:
		return nil, nil, time.Time{}, value.ErrInvalid
	}
	limit := in.Limit
	if limit == 0 {
		limit = value.DefaultHistoryPage
	}
	after, err := decodeHistoryCursor(in)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	page, err := s.history.List(ctx, current, in.Target.target(), origins, after, limit)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	out := CaptureHistoryPage{Kind: "captureHistoryPage", History: make([]CaptureHistoryEntry, 0, len(page.Entries)), Ordering: "acceptedAtDescCaptureIDDesc"}
	for _, e := range page.Entries {
		out.History = append(out.History, CaptureHistoryEntry{CaptureID: e.CaptureID, Origin: string(e.Origin), AcceptedAt: e.AcceptedAt, SummaryExpires: e.ExpiresAt, Phase: e.Phase, ActionKinds: []string{"kubernetesSnapshot"},
			EvidenceState: e.EvidenceState, RepeatState: "available", SettingsExpires: e.ExpiresAt, NavigationURI: s.config.PublicOrigin + "/captures/" + e.CaptureID, Operation: "collect"})
	}
	return out, encodeHistoryCursor(in, page.Next), page.ValidUntil, nil
}
