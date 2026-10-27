package presentation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"strconv"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	planning "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
)

// CaptureHistoryEntry is one canonical capture-history.schema.json entry.
type CaptureHistoryRequester struct {
	Issuer       string `json:"issuer"`
	SubjectID    string `json:"subject_id"`
	IdentityType string `json:"identity_type"`
}

type CaptureHistoryEntry struct {
	Requester       *CaptureHistoryRequester `json:"requester,omitempty"`
	RepeatedFrom    string                   `json:"repeated_from_capture_id,omitempty"`
	CaptureID       string                   `json:"capture_id"`
	Origin          string                   `json:"origin"`
	AcceptedAt      time.Time                `json:"accepted_at"`
	SummaryExpires  time.Time                `json:"summary_expires_at"`
	Phase           string                   `json:"phase"`
	ActionKinds     []string                 `json:"action_kinds"`
	EvidenceState   string                   `json:"evidence_state"`
	RepeatState     string                   `json:"repeat_state"`
	SettingsExpires time.Time                `json:"settings_expires_at"`
	NavigationURI   string                   `json:"navigation_uri"`
	Operation       string                   `json:"operation"`
}
type CaptureHistoryPage struct {
	Kind     string                `json:"kind"`
	History  []CaptureHistoryEntry `json:"history"`
	Ordering string                `json:"ordering"`
}
type CaptureSettingsView struct {
	Composition                json.RawMessage `json:"profile_composition,omitempty"`
	Target                     json.RawMessage `json:"target"`
	RecipeSpec                 json.RawMessage `json:"recipe_spec"`
	DependencyPins             json.RawMessage `json:"dependency_pins"`
	RequestedRetention         string          `json:"requested_retention,omitempty"`
	OriginalEffectiveRetention string          `json:"original_effective_retention,omitempty"`
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

// historyCall serves list_capture_history and get_capture_settings.
func (s *ContextOperations) historyCall(ctx context.Context, current identities.CurrentIdentity, actor identity.Identity, name string, in ContextOperationInput) (any, *string, time.Time, error) {
	if name == "get_capture_settings" {
		settings, err := s.history.Settings(ctx, current, in.CaptureID)
		if err != nil {
			return nil, nil, time.Time{}, err
		}
		view := CaptureSettingsView{Target: settings.TargetJSON, RecipeSpec: json.RawMessage(planning.ContextRecipeSpec), DependencyPins: settings.DependencyJSON, RequestedRetention: strconv.FormatInt(settings.RequestedSeconds, 10) + "s"}
		if len(settings.RecipeJSON) > 0 {
			view.RecipeSpec = settings.RecipeJSON
		}
		view.Composition = settings.CompositionJSON
		if settings.RequestedSeconds == 0 {
			view.RequestedRetention = ""
		}
		if settings.OriginalEffectiveSeconds > 0 {
			view.OriginalEffectiveRetention = strconv.FormatInt(settings.OriginalEffectiveSeconds, 10) + "s"
		}
		b, err := json.Marshal(view)
		if err != nil {
			return nil, nil, time.Time{}, value.ErrUnavailable
		}
		canonical := jsontext.Value(b)
		// Unmarshal into a fresh projection: RawMessage.UnmarshalJSON can reuse
		// capacity, so filling view again would mutate the caller's snapshot.
		var canonicalView CaptureSettingsView
		if canonical.Canonicalize() != nil || json.Unmarshal(canonical, &canonicalView) != nil {
			return nil, nil, time.Time{}, value.ErrUnavailable
		}
		limit := contracts.InvestigationOutputLimit
		if browserSettingsView(ctx, name) {
			limit = value.MaxHistoryParameters
		}
		if (!browserSettingsView(ctx, name) && len(b) > limit) || len(canonical) > limit {
			return nil, nil, time.Time{}, value.ErrSettingsTooLarge
		}
		d := sha256.Sum256(canonical)
		if settings.SettingsKey != ([32]byte{}) {
			d = settings.SettingsKey
		}
		return CaptureSettingsRecord{Kind: "captureSettings", CaptureID: settings.CaptureID, ClusterID: settings.ClusterID, NamespaceUID: settings.NamespaceUID, AcceptedAt: settings.AcceptedAt, ExpiresAt: settings.ExpiresAt,
			SettingsDigest: hex.EncodeToString(d[:]), ExecutionDigest: hash(settings.ExecutionDigest), Settings: canonicalView, NavigationURI: s.config.PublicOrigin + "/captures/" + settings.CaptureID}, nil, settings.ValidUntil, nil
	}
	origins := []value.HistoryOrigin{value.HistoryManual}
	switch in.Origin {
	case "", "manual":
	case "policy":
		origins = []value.HistoryOrigin{value.HistoryPolicy}
	case "discovery":
		origins = []value.HistoryOrigin{value.HistoryDiscovery}
	case "all":
		origins = []value.HistoryOrigin{value.HistoryManual, value.HistoryPolicy, value.HistoryDiscovery}
	default:
		return nil, nil, time.Time{}, value.ErrInvalid
	}
	limit := in.Limit
	if limit == 0 {
		limit = value.DefaultHistoryPage
	}
	after, err := s.decodeHistoryCursor(in, actor)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	page, err := s.history.List(ctx, current, in.Target.target(), origins, after, limit)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	out := CaptureHistoryPage{Kind: "captureHistoryPage", History: make([]CaptureHistoryEntry, 0, len(page.Entries)), Ordering: "acceptedAtDescCaptureIDDesc"}
	for _, e := range page.Entries {
		if len(e.ActionKinds) == 0 {
			e.ActionKinds = []string{"kubernetesSnapshot"}
		}
		if e.RepeatState == "" {
			e.RepeatState = "available"
		}
		if e.SettingsExpiresAt.IsZero() {
			e.SettingsExpiresAt = e.ExpiresAt
		}
		entry := CaptureHistoryEntry{CaptureID: e.CaptureID, Origin: string(e.Origin), AcceptedAt: e.AcceptedAt, SummaryExpires: e.ExpiresAt, Phase: e.Phase, ActionKinds: e.ActionKinds,
			EvidenceState: e.EvidenceState, RepeatState: e.RepeatState, SettingsExpires: e.SettingsExpiresAt, RepeatedFrom: e.RepeatedFrom, NavigationURI: s.config.PublicOrigin + "/captures/" + e.CaptureID, Operation: "collect"}
		if e.Requester.Valid() {
			entry.Requester = &CaptureHistoryRequester{Issuer: e.Requester.Issuer, SubjectID: e.Requester.Subject, IdentityType: string(e.Requester.Kind)}
		}
		out.History = append(out.History, entry)
	}
	cursor, err := s.encodeHistoryCursor(in, actor, page, after)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	return out, cursor, page.ValidUntil, nil
}
