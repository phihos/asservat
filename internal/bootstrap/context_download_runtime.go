package bootstrap

import (
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"context"
	"time"
)

// This constructor is for accepted installed dependencies. It cannot be chosen
// by a public request and supplies no raw reader, unwrap capability or synthetic
// process. Enrollment and native channels use the same actual owning hub.
type ContextNativeDownloadServices struct {
	Runtime  *evidence.ContextNativeRuntime
	Transfer evidence.DownloadResponseTransfer
	Stop     evidence.ContextDownloadStopCoordinator
}

func NewContextNativeDownloadRuntime(owner *OwnerRuntime, workers *postgres.DownloadWorkers, sessions *postgres.FirstContextPreparations, configuration *postgres.WorkerConfigurations, native *postgres.FirstContextNativeOperations, responses *postgres.FirstContextResponses, c evidence.ContextNativeRuntimeConfig, transfer evidence.DownloadResponseTransfer, stop evidence.ContextDownloadStopCoordinator) (ContextNativeDownloadServices, error) {
	var zero ContextNativeDownloadServices
	if owner == nil || owner.native == nil || owner.root == nil || owner.root.Err() != nil || workers == nil || sessions == nil || configuration == nil || native == nil || responses == nil || c.Workers != nil || c.Preparation != nil || c.Serving != nil || c.Configuration != nil || c.Native.Owners != nil || c.Native.Registrar != nil || c.Native.HubPodUID != "" || c.Native.HubProcessEpoch != "" || c.Profile.InstallationID != owner.binding.InstallationID || c.Native.Enrollment != (authorization.WorkerEnrollment{}) || transfer.Sessions != nil || transfer.Responses != nil || transfer.Authority != nil || transfer.Objects == nil || transfer.Audit == nil || stop.Active != nil || stop.Ledger == nil || stop.Acknowledgements == nil || stop.Objects == nil || stop.Now == nil {
		return zero, artifact.ErrInvalid
	}
	c.Workers = workers
	c.Preparation = sessions
	c.Configuration = configuration
	c.Serving = owner
	c.Native.Owners = native
	c.Native.Registrar = owner
	c.Native.HubPodUID = owner.binding.PodUID
	c.Native.HubProcessEpoch = owner.binding.ProcessEpoch
	runtime, e := evidence.NewContextNativeRuntime(c)
	if e != nil {
		return zero, e
	}
	// The Observe and BeginResponse exclusions are deliberately paired here.
	// Supplying an otherwise valid generic ledger cannot omit either lock check.
	transfer.Sessions = sessions
	transfer.Responses = responses
	transfer.Authority = c.Authority
	transfer.Now = c.Now
	transfer.NewID = c.NewID
	stop.Active = runtime
	return ContextNativeDownloadServices{Runtime: runtime, Transfer: transfer, Stop: stop}, nil
}

// An expiring local readiness observation prevents reservation when no native
// process/listener exists. It grants no peer or artifact authority; actual SQL,
// source, route and TLS/Pod checks still surround every operation.
func (r *OwnerRuntime) ContextNativeReady(ctx context.Context) (time.Time, error) {
	if r == nil || ctx == nil || ctx.Err() != nil || r.root == nil || r.root.Err() != nil || r.native == nil || !r.Ready() {
		return time.Time{}, artifact.ErrDownloadUnavailable
	}
	observed := r.ready.Load()
	if observed == nil || !time.Now().Before(observed.until) {
		return time.Time{}, artifact.ErrDownloadUnavailable
	}
	return observed.until, nil
}
