package artifact

import (
	"asservat.local/asservat/internal/domain/identity"
	"time"
)

// DownloadEnvironment is a current, independently accepted deployment/privacy
// decision. It covers recovery, processing restrictions, client disclosure and
// the exact regional store/relay path. It is never read from public request data.
type DownloadEnvironment struct {
	RootID, InstallationID, Region, StoreID, RecoveryEpoch string
	Location                                               Location
	Principal                                              identity.Principal
	Revision, RecoveryRevision                             identity.Revision
	Path                                                   DownloadPath            `json:",omitzero"`
	Processing                                             DownloadProcessingProof `json:",omitzero"`
	ObservedAt, ValidUntil                                 time.Time
}

func (e DownloadEnvironment) Valid(now time.Time) bool {
	return (e.Path == (DownloadPath{}) || e.Path.Valid() && e.Path.TargetClusterID == e.Location.ClusterID && e.Path.StoreID == e.StoreID) && (e.Processing == (DownloadProcessingProof{}) || e.Processing.Valid(now) && e.Processing.RootID == e.RootID && e.Processing.Location == e.Location && !e.ValidUntil.After(e.Processing.ValidUntil)) && uuid(e.RootID) && uuid(e.InstallationID) && e.RecoveryRevision.Valid() && identity.Text(e.Region, 63) && uuid(e.StoreID) && uuid(e.RecoveryEpoch) && e.Location.Validate() == nil && e.Principal.Valid() && e.Revision.Valid() && identity.Fresh(e.ObservedAt, e.ValidUntil, now, 5*time.Second)
}

func (e DownloadEnvironment) Recovery() RecoveryProof {
	return RecoveryProof{InstallationID: e.InstallationID, IssuerEpoch: e.RecoveryEpoch, Revision: e.RecoveryRevision, ObservedAt: e.ObservedAt, FreshUntil: e.ValidUntil}
}

// CurrentValid is mandatory for live effects. Valid deliberately still decodes
// historical records without these later proofs; it cannot authorize new I/O.
func (e DownloadEnvironment) CurrentValid(now time.Time) bool {
	return e.Valid(now) && e.Region == e.Path.AcquisitionRegion && e.Path.Valid() && e.Processing.Valid(now) && e.Path.TargetClusterID == e.Location.ClusterID && e.Path.StoreID == e.StoreID && e.Processing.RootID == e.RootID && e.Processing.Location == e.Location && !e.ValidUntil.After(e.Processing.ValidUntil)
}
