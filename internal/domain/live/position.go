package live

// Position is private per-source sequence/loss state, not a disclosure grant.
// Loss advances cumulatively so each viewer reports newly observed loss once.
type Position struct {
	Sequence, Lost                     uint64
	ClockLost, Unsupported, SensorLost uint64
}

func (p Position) Follows(old Position) bool {
	return p.Valid() && old.Valid() && p.Sequence >= old.Sequence && p.Lost >= old.Lost && p.ClockLost >= old.ClockLost && p.Unsupported >= old.Unsupported && p.SensorLost >= old.SensorLost
}

func (p Position) Valid() bool {
	left := p.Lost
	for _, n := range []uint64{p.ClockLost, p.Unsupported, p.SensorLost} {
		if n > left {
			return false
		}
		left -= n
	}
	return p.Sequence <= 1<<53-1
}
