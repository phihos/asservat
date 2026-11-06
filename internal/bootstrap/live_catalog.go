package bootstrap

import (
	authapp "asservat.local/asservat/internal/application/authorization"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/live"
	"context"
	"strings"
)

// Both variants retain their real accepted authority. There is no policy
// acceptance alias for a manual session and no source replacement fallback.
type liveCatalog struct {
	ongoing liveSourceCatalog
	manual  liveManualCatalog
}

func (c liveCatalog) LiveSourceTarget(ctx context.Context, id, kind string) (authorization.Target, error) {
	switch kind {
	case "policy":
		return c.ongoing.LiveSourceTarget(ctx, id, kind)
	case "manualSession":
		return c.manual.target(ctx, id)
	}
	return authorization.Target{}, live.ErrInvalid
}
func (c liveCatalog) ReadLiveSource(ctx context.Context, s live.Source) (authapp.LiveSourceRecord, error) {
	return c.ReadLiveSourceID(ctx, s.Target, s.ID(), s.OwnerKind)
}
func (c liveCatalog) ReadLiveSourceID(ctx context.Context, target authorization.Target, id, kind string) (authapp.LiveSourceRecord, error) {
	rows, e := c.ReadLiveSourceRecords(ctx, []live.SourceReference{{Target: target, ID: id, Kind: kind}})
	if e != nil || len(rows) != 1 {
		return authapp.LiveSourceRecord{}, live.ErrUnavailable
	}
	return rows[0], nil
}
func (c liveCatalog) ReadLiveSourceRecords(ctx context.Context, refs []live.SourceReference) ([]authapp.LiveSourceRecord, error) {
	if len(refs) < 1 || len(refs) > 16 {
		return nil, live.ErrInvalid
	}
	var ongoing, manual []live.SourceReference
	seen := map[string]bool{}
	for _, r := range refs {
		if seen[r.ID] {
			return nil, live.ErrInvalid
		}
		seen[r.ID] = true
		switch r.Kind {
		case "policy":
			ongoing = append(ongoing, r)
		case "manualSession":
			manual = append(manual, r)
		default:
			return nil, live.ErrInvalid
		}
	}
	indexed := map[string]authapp.LiveSourceRecord{}
	if len(ongoing) > 0 {
		rows, e := c.ongoing.ReadLiveSourceRecords(ctx, ongoing)
		if e != nil || len(rows) != len(ongoing) {
			return nil, live.ErrUnavailable
		}
		for _, r := range rows {
			indexed[r.Source.ID()] = r
		}
	}
	if len(manual) > 0 {
		rows, e := c.manual.read(ctx, manual)
		if e != nil || len(rows) != len(manual) {
			return nil, live.ErrUnavailable
		}
		for _, r := range rows {
			indexed[r.Source.ID()] = r
		}
	}
	out := make([]authapp.LiveSourceRecord, len(refs))
	for n, r := range refs {
		v, ok := indexed[r.ID]
		if !ok || v.Source.OwnerKind != r.Kind || v.Source.Target != r.Target {
			return nil, live.ErrDenied
		}
		out[n] = v
	}
	return out, nil
}

// Inventory cursors are non-authorizing scan positions. Finite sources come
// first because their original lifetime can be much shorter than ongoing ones.
// A family transition never arms a source or changes an existing selection.
func (c liveCatalog) ListLiveSources(ctx context.Context, target authorization.WorkloadTarget, cursor string, limit int) ([]authapp.LiveSourceRecord, string, error) {
	if cursor != "" && !strings.HasPrefix(cursor, "manual:") && !strings.HasPrefix(cursor, "policy:") {
		return nil, "", live.ErrInvalid
	}
	if cursor == "" || strings.HasPrefix(cursor, "manual:") {
		after := strings.TrimPrefix(cursor, "manual:")
		if after != "" && !authorization.UUID(after) {
			return nil, "", live.ErrInvalid
		}
		rows, next, e := c.manual.list(ctx, target, after, limit)
		if e != nil {
			return nil, "", e
		}
		if next != "" {
			return rows, "manual:" + next, nil
		}
		if len(rows) > 0 {
			return rows, "policy:", nil
		}
		cursor = "policy:"
	}
	after := strings.TrimPrefix(cursor, "policy:")
	rows, next, e := c.ongoing.ListLiveSources(ctx, target, after, limit)
	if next != "" {
		next = "policy:" + next
	}
	return rows, next, e
}
