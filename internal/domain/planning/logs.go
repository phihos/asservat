package planning

import "time"

// LogsContext retains the reviewed authored composition. TriggeredAt is set
// only by the policy service from its persisted occurrence, never a public
// request. Manual admission supplies its original preparation anchor instead.
type LogsContext struct {
	Composition     ProfileComposition
	RequireApproval bool      `json:",omitempty"`
	TriggeredAt     time.Time `json:",omitzero"`
}

func (l *LogsContext) Clone() *LogsContext {
	if l == nil {
		return nil
	}
	out := *l
	out.Composition = *l.Composition.Clone()
	return &out
}
