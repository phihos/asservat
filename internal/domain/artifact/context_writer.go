package artifact

import "time"

const ContextWriterProtocol = "closed-small-context/v1"

// ContextWriterCompletion is a positive producer result, not an interpretation
// of a stored label or a canceled request. The concrete one-use producer issues
// it only after four acknowledged writes and joined handle closure. NativeBytes
// and, for Go profiles, Acquisition are the producer's facts that the hub
// stores with the catalog row; every read checks them against the manifest.
type ContextWriterCompletion struct {
	RegistrationDigest, ExpectationDigest Digest
	Copies                                Copies
	StoredAt, ClosedAt                    time.Time
	NativeBytes                           int64
	Acquisition                           *AcquisitionWindow `json:",omitempty"`
}

func (c ContextWriterCompletion) Valid(r Registration) bool {
	return r.Validate() == nil && c.RegistrationDigest != (Digest{}) && c.ExpectationDigest != (Digest{}) && c.Copies.Validate(r) == nil && !c.StoredAt.IsZero() && c.StoredAt.Nanosecond()%1000 == 0 && !c.ClosedAt.IsZero() && c.ClosedAt.Nanosecond()%1000 == 0 && !c.StoredAt.Before(r.AnchorAt) && c.StoredAt.Before(r.WriteUntil) && !c.ClosedAt.Before(c.StoredAt) && c.NativeBytes >= 0 && c.NativeBytes <= r.NativeLimit && (c.Acquisition == nil || c.Acquisition.Valid())
}
