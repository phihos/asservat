package live

import (
	v "asservat.local/asservat/internal/domain/live"
)

// Coalesce bounded coverage; unknown counts stay unknown rather than becoming
// zero or being summed as independent losses. Overflow never hides a full page.
func appendLiveGap(in []v.Gap, g v.Gap) []v.Gap {
	for n, old := range in {
		same := old.SourceID == nil && g.SourceID == nil || old.SourceID != nil && g.SourceID != nil && *old.SourceID == *g.SourceID
		if old.Reason == g.Reason && same {
			if g.From.Before(in[n].From) {
				in[n].From = g.From
			}
			if g.Until.After(in[n].Until) {
				in[n].Until = g.Until
			}
			if old.Count == nil || g.Count == nil {
				in[n].Count = nil
			} else {
				count := min(1000000000, *old.Count+*g.Count)
				in[n].Count = &count
			}
			return in
		}
	}
	if len(in) < 32 {
		return append(in, g)
	}
	in[31] = v.Gap{Reason: "subscriberOverflow", From: in[31].From, Until: g.Until}
	return in
}
