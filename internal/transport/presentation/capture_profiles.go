package presentation

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// ContextProfiles is the optional catalog read of the C-09 service
// (REQ-CPR-001). A service without it lists no capture profiles.
type ContextProfiles interface {
	CaptureProfiles(context.Context, identities.CurrentIdentity, targets.WorkloadRequest, string) ([]compiler.ProfileDescription, time.Time, error)
	CaptureProfile(context.Context, identities.CurrentIdentity, targets.WorkloadRequest, planning.ProfileRef) (compiler.ProfileDescription, time.Time, error)
}

type ProfileRefData struct {
	Catalog string `json:"catalog"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

func (r ProfileRefData) ref() planning.ProfileRef {
	return planning.ProfileRef{Catalog: r.Catalog, Name: r.Name, Version: r.Version}
}

type ProfileDetailData struct {
	Ref        ProfileRefData  `json:"profile_ref"`
	Digest     string          `json:"definition_digest"`
	Definition json.RawMessage `json:"definition"`
}

// diagnosticPage is the default list_diagnostics page: rows of up to about
// 1 KiB keep a page within the 24 KiB result target (specs/apis.md).
const diagnosticPage = 20

var errInvalidCursor = errors.New("invalid list cursor")

func profileRef(r planning.ProfileRef) ProfileRefData {
	return ProfileRefData{r.Catalog, r.Name, r.Version}
}

// diagnostics lists the pod-status preset and the catalog capture profiles
// usable on one target. approval_required of a profile is the recorder
// plan's ordinary review default; the preview decides it (ADR-249).
// Ranked recommendations (goal) and recipe or discovery rows have no
// runtime yet.
func (s *ContextOperations) diagnostics(ctx context.Context, current identities.CurrentIdentity, in ContextOperationInput) (any, *string, time.Time, error) {
	switch {
	case in.TargetHandle != "":
		return nil, nil, time.Time{}, capabilityError("target_handle")
	case in.Goal != "" || in.DiscoveryCaptureIDs != nil || in.Preferences != nil || in.Focus != nil:
		return nil, nil, time.Time{}, capabilityError("diagnostic recommendations")
	case in.Kind == "recipe" || in.Kind == "discovery":
		return nil, nil, time.Time{}, capabilityError(in.Kind + " diagnostics")
	}
	offset := 0
	if in.Cursor != "" {
		n, err := strconv.Atoi(in.Cursor)
		if err != nil || n < 1 {
			return nil, nil, time.Time{}, errInvalidCursor
		}
		offset = n
	}
	target, err := s.workload(in.Target)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	until, err := s.captures.CheckDiagnostic(ctx, current, target)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	rows := []DiagnosticRow{}
	if in.Catalog == "" && in.Kind != "captureProfile" {
		rows = append(rows, DiagnosticRow{Kind: "preset", Name: "Pod status", Version: "v1", Description: "One whole-pod Kubernetes status snapshot, up to 4096 native bytes. This does not collect logs, processes or network traffic.", Available: s.config.CollectionEnabled, Blockers: collectionBlockers(s.config.CollectionEnabled), ExecutionModes: []string{"onTrigger"}, Preset: &PresetReference{"pod-status", "v1"}})
	}
	if profiles, ok := s.captures.(ContextProfiles); ok && in.Kind != "preset" {
		list, listUntil, err := profiles.CaptureProfiles(ctx, current, target, in.Catalog)
		if err != nil {
			return nil, nil, time.Time{}, err
		}
		until = identity.Earlier(until, listUntil)
		for _, p := range list {
			ref := profileRef(p.Ref)
			description := p.Description
			if description == "" {
				description = p.DisplayName
			}
			row := DiagnosticRow{Kind: "captureProfile", Name: p.Ref.Name, Version: p.Ref.Version, Description: description, DisplayName: p.DisplayName, Available: p.Available, Deprecated: p.Deprecated,
				ApprovalRequired: true, Blockers: []OperationBlocker{}, ExecutionModes: p.ExecutionModes, Profile: &ref}
			if !p.Available {
				row.Blockers = append(row.Blockers, OperationBlocker{Code: "ProfileUnavailable", Message: "This profile version is disabled. Choose another version.", ResponsibleRole: "administrator"})
			}
			rows = append(rows, row)
		}
	}
	limit := in.Limit
	if limit == 0 {
		limit = diagnosticPage
	}
	if offset > len(rows) {
		return nil, nil, time.Time{}, errInvalidCursor
	}
	rows = rows[offset:]
	var next *string
	if len(rows) > limit {
		rows = rows[:limit]
		cursor := strconv.Itoa(offset + limit)
		next = &cursor
	}
	return struct {
		Diagnostics []DiagnosticRow `json:"diagnostics"`
	}{rows}, next, until, nil
}

// profile reads one catalog profile definition.
func (s *ContextOperations) profile(ctx context.Context, current identities.CurrentIdentity, in ContextOperationInput) (any, time.Time, error) {
	profiles, ok := s.captures.(ContextProfiles)
	if !ok {
		return nil, time.Time{}, capabilityError("capture profiles")
	}
	if in.TargetHandle != "" {
		return nil, time.Time{}, capabilityError("target_handle")
	}
	target, err := s.workload(in.Target)
	if err != nil {
		return nil, time.Time{}, err
	}
	p, until, err := profiles.CaptureProfile(ctx, current, target, in.ProfileRef.ref())
	if err != nil {
		return nil, time.Time{}, err
	}
	return ProfileDetailData{profileRef(p.Ref), hex.EncodeToString(p.Digest[:]), p.Definition}, until, nil
}
