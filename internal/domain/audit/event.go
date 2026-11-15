package audit

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// Event is one append-only audit row (REQ-AUT-005, ADR-330 D6). Kind is
// "call" for the public operation boundary and names the effect otherwise.
// It records digests and references only, never raw arguments or content.
type Event struct {
	ID, OperationID, Kind, Operation string
	Actor                            identity.Principal
	InputDigest                      *artifact.Digest
	Status, Reason, Effect           string
	CaseIDs, ArtifactIDs, CaptureIDs []string
	ShareIDs, GrantIDs               []string
	ReservationID                    string
	OutputBytes                      int64
	OutputDigest                     *artifact.Digest
}

// Valid checks the fields every row needs.
func (e Event) Valid() bool {
	return e.ID != "" && e.OperationID != "" && e.Kind != "" && e.Operation != "" && e.Actor.Valid() && e.Status != "" && e.OutputBytes >= 0
}
