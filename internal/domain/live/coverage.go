package live

import (
	"asservat.local/asservat/internal/domain/authorization"
	"slices"
	"time"
)

func (g Gap) Valid(now time.Time) bool {
	return slices.Contains([]string{"sensorLoss", "filteredOut", "unsupportedProtocol", "projectionSampled", "subscriberOverflow", "reconnect", "filterChanged", "paused", "sourceEnded", "clockUncertain", "sourceUnavailable", "bufferExpired", "accessLost"}, g.Reason) && (g.SourceID == nil || authorization.UUID(*g.SourceID)) && (g.Count == nil || *g.Count >= 0 && *g.Count <= 1000000000) && !g.From.IsZero() && g.From.Year() >= 1970 && g.From.Year() <= 9999 && !g.Until.Before(g.From) && !g.Until.After(now)
}
func (s SourceStatus) Valid(now time.Time) bool {
	return authorization.UUID(s.ID) && slices.Contains([]string{"Warming", "Ready", "Degraded", "Stopped", "Unavailable"}, s.State) && s.Generation >= 0 && s.Generation <= 1000000000 && slices.Contains([]string{"observed", "partial", "unknown"}, s.Coverage) && (s.LastObserved == nil || !s.LastObserved.IsZero() && !s.LastObserved.After(now))
}
