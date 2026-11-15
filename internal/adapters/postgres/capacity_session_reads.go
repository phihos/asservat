package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/domain/artifact"
)

// A session reads the live per-workload download rows; there is no
// per-session capacity snapshot.
func effectiveSessionNativeBacking(row custodydb.ReadSessionNativeBackingRow, session artifact.DownloadSession) (custodydb.DownloadNativeBacking, error) {
	b := row.DownloadNativeBacking
	if b.AllocationID != id(session.AllocationID) || b.RootID != id(session.Scope.RootID) || !row.SessionDeadline.Time.Equal(session.Deadline) {
		return custodydb.DownloadNativeBacking{}, artifact.ErrIntegrity
	}
	return b, nil
}

func effectiveSessionControlBacking(row custodydb.ReadDownloadSessionControlRow, session artifact.DownloadSession) (custodydb.DownloadControlAllocation, error) {
	c := row.DownloadControlAllocation
	if c.ID != id(session.AllocationID) || c.RootID != id(session.Scope.RootID) || !row.SessionDeadline.Time.Equal(session.Deadline) {
		return custodydb.DownloadControlAllocation{}, artifact.ErrIntegrity
	}
	return c, nil
}
