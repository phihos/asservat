package presentation

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	identities "asservat.local/asservat/internal/application/identity"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// ContextProfiles is the optional catalog read of the C-09 service
// (REQ-CPR-001). A service without it serves neither profile tool.
type ContextProfiles interface {
	CaptureProfiles(context.Context, identities.CurrentIdentity, targets.WorkloadRequest, string) ([]compiler.ProfileDescription, time.Time, error)
	CaptureProfile(context.Context, identities.CurrentIdentity, targets.WorkloadRequest, planning.ProfileRef) (compiler.ProfileDescription, time.Time, error)
}

type ProfileRefData struct {
	Catalog string `json:"catalog"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (r ProfileRefData) ref() planning.ProfileRef {
	return planning.ProfileRef{Catalog: r.Catalog, Name: r.Name, Version: r.Version}
}

type ProfileRow struct {
	Ref              ProfileRefData     `json:"profile_ref"`
	DisplayName      string             `json:"display_name"`
	Description      string             `json:"description"`
	Available        bool               `json:"available"`
	Deprecated       bool               `json:"deprecated"`
	ApprovalRequired bool               `json:"approval_required"`
	Blockers         []OperationBlocker `json:"blockers"`
	ExecutionModes   []string           `json:"execution_modes"`
}

type ProfileDetailData struct {
	Ref        ProfileRefData  `json:"profile_ref"`
	Digest     string          `json:"definition_digest"`
	Definition json.RawMessage `json:"definition"`
}

// maxProfileRows is the canonical one-page bound; narrow with catalog.
const maxProfileRows = 100

var errProfileListLimit = errors.New("more capture profiles than one page")

func profileRef(r planning.ProfileRef) ProfileRefData {
	return ProfileRefData{r.Catalog, r.Name, r.Version}
}

// profileCall lists or reads catalog profiles. approval_required is the
// recorder plan's ordinary review default; the preview decides it for the
// caller (ADR-249).
func (s *ContextOperations) profileCall(ctx context.Context, current identities.CurrentIdentity, name string, in ContextOperationInput) (any, string, time.Time, error) {
	profiles := s.captures.(ContextProfiles)
	if name == "get_capture_profile" {
		p, until, err := profiles.CaptureProfile(ctx, current, in.Target.target(), in.ProfileRef.ref())
		if err != nil {
			return nil, "", time.Time{}, err
		}
		return ProfileDetailData{profileRef(p.Ref), hex.EncodeToString(p.Digest[:]), p.Definition}, "extract", until, nil
	}
	list, until, err := profiles.CaptureProfiles(ctx, current, in.Target.target(), in.Catalog)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	if len(list) > maxProfileRows {
		return nil, "", time.Time{}, errProfileListLimit
	}
	rows := []ProfileRow{}
	for _, p := range list {
		row := ProfileRow{Ref: profileRef(p.Ref), DisplayName: p.DisplayName, Description: boundedText(p.Description, 512), Available: p.Available, Deprecated: p.Deprecated,
			ApprovalRequired: true, Blockers: []OperationBlocker{}, ExecutionModes: p.ExecutionModes}
		if !p.Available {
			row.Blockers = append(row.Blockers, OperationBlocker{Code: "ProfileUnavailable", Message: "This profile version is disabled. Choose another version.", ResponsibleRole: "administrator"})
		}
		rows = append(rows, row)
	}
	return struct {
		Profiles []ProfileRow `json:"profiles"`
	}{rows}, "metadata", until, nil
}
