package privacy

import (
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// ProcessingInventoryQuery pages only the installation's bounded rule ledger.
// Each page is a new current observation; a cursor is neither a snapshot nor authority.
type ProcessingInventoryQuery struct {
	After string
	Limit int
}

func (q ProcessingInventoryQuery) Valid() bool {
	return (q.After == "" || authorization.UUID(q.After)) && q.Limit >= 1 && q.Limit <= 100
}

type ProcessingInventoryRule struct {
	ID                            string
	Revision                      int64
	State                         string
	Scope                         ProcessingScope
	AdministrationUntil, RetireBy time.Time
}

func (r ProcessingInventoryRule) Valid() bool {
	if !authorization.UUID(r.ID) || !r.Scope.Valid() || r.AdministrationUntil.IsZero() || !r.RetireBy.After(r.AdministrationUntil) {
		return false
	}
	return r.State == "reserved" && r.Revision == 0 || r.State == "restricted" && r.Revision > 0 && r.Revision <= MaxProcessingChanges && r.Revision%2 == 1 || r.State == "released" && r.Revision > 0 && r.Revision <= MaxProcessingChanges && r.Revision%2 == 0
}

type ProcessingInventoryPage struct {
	RootID, Epoch          string
	Initialized            bool
	Sequence               int64
	Rules                  []ProcessingInventoryRule
	NextCursor             string
	ObservedAt, ValidUntil time.Time
}

func (p ProcessingInventoryPage) Valid(q ProcessingInventoryQuery, now time.Time) bool {
	window := identity.Check(p.ObservedAt, identity.SQLFenced).Narrow(p.ValidUntil)
	if !q.Valid() || !authorization.UUID(p.RootID) || !authorization.UUID(p.Epoch) || p.Sequence < 1 || p.Sequence > 1<<60 || p.Rules == nil || len(p.Rules) > q.Limit || !window.Valid(now) || !window.Until().Equal(p.ValidUntil) {
		return false
	}
	last := q.After
	for _, r := range p.Rules {
		if !r.Valid() || r.ID <= last {
			return false
		}
		last = r.ID
	}
	return p.NextCursor == "" || len(p.Rules) == q.Limit && p.NextCursor == last
}
