package postgres

import (
	"time"

	liveapp "asservat.local/asservat/internal/application/live"
	"asservat.local/asservat/internal/domain/authorization"
	v "asservat.local/asservat/internal/domain/live"
)

// LiveWatchLimits comes from the protected runtime composition, never a public
// watch request. These are configured ceilings, not measured parser overhead.
type LiveWatchLimits struct {
	InstallationSlots, PrincipalSlots, WorkloadSlots   int64
	MemoryBytes                                        int64
	InstallationRate, InstallationBurst                int64
	PrincipalRate, PrincipalBurst                      int64
	WorkloadRate, WorkloadBurst                        int64
	WatchBurst, MaxOutputBytes, MaxRate                int64
	MaxDurationSeconds, MaxAccounts, MaxControlRecords int64
}

func (p LiveWatchLimits) Valid() bool {
	if p.InstallationSlots < 1 || p.InstallationSlots > 4096 || p.PrincipalSlots < 1 || p.PrincipalSlots > p.InstallationSlots || p.WorkloadSlots < 1 || p.WorkloadSlots > p.InstallationSlots || p.MemoryBytes < p.InstallationSlots*v.MaxBufferBytes || p.MemoryBytes > 4096*v.MaxBufferBytes || p.MaxOutputBytes < 24<<10 || p.MaxOutputBytes > 64<<20 || p.MaxRate < 1 || p.MaxRate > 256<<10 || p.WatchBurst < 24<<10 || p.WatchBurst > 1<<20 || p.MaxDurationSeconds < 1 || p.MaxDurationSeconds > 3600 || p.MaxAccounts < 3 || p.MaxAccounts > 1048576 || p.MaxControlRecords < p.InstallationSlots || p.MaxControlRecords > 1048576 {
		return false
	}
	for _, b := range [][2]int64{{p.InstallationRate, p.InstallationBurst}, {p.PrincipalRate, p.PrincipalBurst}, {p.WorkloadRate, p.WorkloadBurst}} {
		if b[0] < 1 || b[0] > 256<<20 || b[1] < 24<<10 || b[1] > 1<<30 {
			return false
		}
	}
	return true
}
func liveControlValid(c liveapp.Control) bool {
	return authorization.UUID(c.ID) && authorization.UUID(c.OwnerID) && authorization.UUID(c.Fence) && c.PrincipalKey != [32]byte{} && c.WorkloadKey != [32]byte{} && c.RequestDigest != [32]byte{} && c.Revision >= 1 && c.Revision <= 1000000000 && (c.State == "Active" || c.State == "Paused" || c.State == "Closed" || c.State == "Expired" || c.State == "AccessLost" || c.State == "Exhausted" || c.State == "Disconnected" || c.State == "SourceEnded") && !c.AcceptedAt.IsZero() && c.ExpiresAt.After(c.AcceptedAt) && c.ExpiresAt.Sub(c.AcceptedAt) <= time.Hour && c.IdleUntil.After(c.AcceptedAt) && !c.IdleUntil.After(c.ExpiresAt) && c.OutputLimit >= 1 && c.OutputLimit <= 64<<20 && c.Spent >= 0 && c.Spent <= c.OutputLimit && c.BytesPerSecond >= 1 && c.BytesPerSecond <= 256<<10
}
