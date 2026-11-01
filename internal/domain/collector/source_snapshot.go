package collector

import "asservat.local/asservat/internal/domain/artifact"

// SourceSnapshot consumes a separately admitted capture's snapshot authority.
// Its source binding is unchanged; neither acceptance nor replay can arm or
// renew a source. ExpectationDigest identifies the saved output, distinct from
// Binding.ExpectationDigest which identifies its ongoing source definition.
type SourceSnapshot struct {
	Binding           SourceBinding
	CaptureID         string
	AttemptID         string
	WriterPodUID      string `json:",omitempty"`
	WriterEpoch       string `json:",omitempty"`
	ExpectationDigest [32]byte
	Request           artifact.SourceSnapshotRequest
}

func (s SourceSnapshot) Valid() bool {
	if (s.WriterPodUID != "" || s.WriterEpoch != "") && (!validUUID(s.WriterPodUID) || !validUUID(s.WriterEpoch)) {
		return false
	}
	return validUUID(s.AttemptID) && s.Binding.AudienceDigest != ([32]byte{}) && s.Binding.Valid() && validUUID(s.CaptureID) && s.ExpectationDigest != ([32]byte{}) &&
		s.Request.Valid() && s.Request.SourceID == s.Binding.SourceID && s.Request.Fence == s.Binding.Fence
}

func (s SourceSnapshot) Equal(other SourceSnapshot) bool {
	return s.Binding == other.Binding && s.CaptureID == other.CaptureID && s.AttemptID == other.AttemptID && s.WriterPodUID == other.WriterPodUID && s.WriterEpoch == other.WriterEpoch && s.ExpectationDigest == other.ExpectationDigest && s.Request.Equal(other.Request)
}
