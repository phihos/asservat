package artifact

// ProcessCapture is one immutable finite whole-Pod metadata acquisition. The
// composition is restored and recompiled before dispatch, just like profiles.
type ProcessCapture struct {
	ActionID                      string
	Mode                          string
	MaxNativeBytes, TimeoutMillis int64
	Composition                   []byte
}

func (p *ProcessCapture) Valid() bool {
	return p != nil && recorderActionID(p.ActionID) && (p.Mode == ProcessMain || p.Mode == ProcessAll) && p.MaxNativeBytes > 0 && p.MaxNativeBytes <= ProcessNativeLimit && p.TimeoutMillis > 0 && p.TimeoutMillis <= 5000 && len(p.Composition) > 0 && len(p.Composition) <= 48<<10
}

func (p *ProcessCapture) Clone() *ProcessCapture {
	if p == nil {
		return nil
	}
	out := *p
	out.Composition = append([]byte(nil), p.Composition...)
	return &out
}
