package artifact

import "time"

// Location names one immutable attempt, not an arbitrary bucket prefix.
type Location struct{ ClusterID, ArtifactID, AttemptID string }

func (l Location) Validate() error {
	return (Binding{l.ClusterID, l.ArtifactID, l.AttemptID, "application/octet-stream"}).Validate()
}

func (l Location) Prefix() string {
	return "v1/" + l.ClusterID + "/" + l.ArtifactID + "/" + l.AttemptID + "/"
}

// Registration is a storage obligation, never a collection or disclosure grant.
// Native limits above one frame (ADR-166) are valid only with a StreamingPlan:
// the small Register path rejects them and SQL requires their stream journal.
type Registration struct {
	Location                                  Location
	StoreID, AllocationID                     string
	PoolRevision, AllocationRevision          int64
	NativeLimit                               int64
	AnchorAt, WriteUntil, ExpiresAt, DeleteBy time.Time
}

func (r Registration) Equal(other Registration) bool {
	r.AnchorAt = r.AnchorAt.UTC()
	other.AnchorAt = other.AnchorAt.UTC()
	r.WriteUntil = r.WriteUntil.UTC()
	other.WriteUntil = other.WriteUntil.UTC()
	r.ExpiresAt = r.ExpiresAt.UTC()
	other.ExpiresAt = other.ExpiresAt.UTC()
	r.DeleteBy = r.DeleteBy.UTC()
	other.DeleteBy = other.DeleteBy.UTC()
	return r == other
}

func (r Registration) Validate() error {
	if r.Location.Validate() != nil || !uuid(r.StoreID) || !uuid(r.AllocationID) || r.PoolRevision < 1 || r.AllocationRevision < 1 || r.NativeLimit < 0 || r.NativeLimit > StreamingNativeLimit {
		return ErrInvalid
	}
	for _, t := range []time.Time{r.AnchorAt, r.WriteUntil, r.ExpiresAt, r.DeleteBy} {
		if t.IsZero() || t.Year() < 2020 || t.Year() > 9999 || t.Nanosecond()%1000 != 0 {
			return ErrInvalid
		}
	}
	if !r.AnchorAt.Before(r.WriteUntil) || r.WriteUntil.After(r.ExpiresAt) || !r.ExpiresAt.Before(r.DeleteBy) {
		return ErrInvalid
	}
	return nil
}

func (r Registration) Limits() [4]int64 {
	d, i, _ := WorstCase(r.NativeLimit)
	return [4]int64{d, i, MaxRootBytes + CipherOverhead, 32 << 10}
}

func (r Registration) ReservedBytes() int64 {
	var n int64
	for _, v := range r.Limits() {
		n += v
	}
	return n
}

func Role(index int) string {
	switch index {
	case 0:
		return "data"
	case 1:
		return "index"
	case 2:
		return "manifest"
	case 3:
		return "commit"
	}
	return ""
}

// CopyReceipt pins ciphertext only. Native hashes and keys stay out of SQL.
type CopyReceipt struct {
	VersionID, ETag string
	Bytes           int64
	SHA256          Digest
}
type Copies [4]CopyReceipt

func (c Copies) Validate(r Registration) error {
	for i, v := range c {
		if v.Bytes < 1 || v.Bytes > r.Limits()[i] || len(v.VersionID) > 1024 || len(v.ETag) < 1 || len(v.ETag) > 1024 || v.SHA256 == (Digest{}) {
			return ErrInvalid
		}
		for _, s := range []string{v.VersionID, v.ETag} {
			for _, b := range s {
				if b < 32 || b == 127 {
					return ErrInvalid
				}
			}
		}
	}
	return nil
}

// StoredUnpublished deliberately cannot be interpreted as a readable artifact.
const (
	Reserved          = "reserved"
	StoredUnpublished = "stored_unpublished"
	Deleting          = "deleting"
	Deleted           = "deleted"
)
