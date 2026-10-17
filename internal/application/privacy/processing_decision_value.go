package privacy

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/privacy"
	"bytes"
	"encoding/json"
)

// The audit describes an authorized, prepared decision. It deliberately keeps
// effect=unknown: independent acknowledgement precedes the SQL CAS and cannot
// truthfully assert its outcome. The SQL receipt separately proves acceptance.
type ProcessingDecision struct {
	Change         value.ProcessingChange
	Intent         audit.OperationIntent
	Outcome        audit.OperationOutcome
	DecisionDigest artifact.Digest
	ReleaseAccount artifact.Digest
}

func (d ProcessingDecision) Valid() bool {
	left, le := json.Marshal(d.Intent)
	right, re := json.Marshal(d.Outcome.Intent)
	capacityValid := d.Change.Action == "initialize_processing" && d.ReleaseAccount == (artifact.Digest{}) || d.Change.Action != "initialize_processing" && d.ReleaseAccount != (artifact.Digest{})
	if d.Change.Action == "release_processing" {
		capacityValid = capacityValid && d.Intent.PrincipalDigest == d.ReleaseAccount
	}
	return capacityValid && le == nil && re == nil && bytes.Equal(left, right) && d.Change.Valid() && d.Intent.ID == d.Change.RequestID && d.Intent.Valid() && d.Intent.Name == d.Change.Action && d.Intent.InputFormat == "processing-input/v1" && d.Outcome.Valid() && d.Outcome.Intent.ID == d.Intent.ID && d.Outcome.Intent.RootID == d.Intent.RootID && d.Outcome.Status == "success" && d.Outcome.Reason == "prepared" && d.Outcome.Effect == "unknown" && d.Outcome.ClientReceipt == "unknown" && len(d.Outcome.CaseIDs) == 0 && len(d.Outcome.ArtifactIDs) == 0 && len(d.Outcome.CaptureIDs) == 0 && d.DecisionDigest != (artifact.Digest{})
}
