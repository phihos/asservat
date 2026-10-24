package analysis

import (
	"asservat.local/asservat/internal/domain/authorization"
	"time"
)

// The query is already admitted and fixes the only possible worker. This value
// adds the accepted shared acquisition profile, not another evidence grant.
type ContextProjectionWorkerIntent struct {
	Query  ContextQuery
	Worker authorization.AcquisitionWorkerIntent
}

func (i ContextProjectionWorkerIntent) Valid() bool {
	q, w := i.Query, i.Worker
	return q.Valid() && w.Valid() && w.ID == q.WorkerID && w.Parent == (authorization.AcquisitionParent{Purpose: authorization.AcquisitionProjection, ID: q.ID}) &&
		w.Profile.InstallationID == q.Plan.InstallationID && w.Profile.ClusterID == q.Plan.Profile.Path.AcquisitionClusterID &&
		w.Profile.Configuration == q.Plan.Profile.Path.WorkerConfiguration && w.CreatedAt.Equal(q.CreatedAt) &&
		w.RunUntil.Equal(q.WorkerUntil) && !w.RunUntil.After(q.CredentialUntil) && w.RunUntil.Sub(w.CreatedAt) >= time.Second
}
