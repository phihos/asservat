package authorization

import "time"

// WorkerOwner names one hub process and active control operation. It contains
// no network address, bearer credential or evidence authority. Pod identity and
// a per-process epoch must later be matched by authenticated owner transport.
type WorkerOwnerRequest struct {
	ID, InstallationID, SessionID, WorkerID string
	PodUID, ProcessEpoch                    string
	Until                                   time.Time
}

func (r WorkerOwnerRequest) Valid(now time.Time) bool {
	return UUID(r.ID) && UUID(r.InstallationID) && UUID(r.SessionID) && UUID(r.WorkerID) && UUID(r.PodUID) && UUID(r.ProcessEpoch) && now.Before(r.Until) && !r.Until.After(now.Add(30*time.Second))
}

type WorkerOwnerLease struct {
	Request WorkerOwnerRequest
	Fence   int64
	Started time.Time
}

// Equal compares original instants independently of Go's location/monotonic
// representation, which cannot survive a SQL or JSON round trip.
func (l WorkerOwnerLease) Equal(other WorkerOwnerLease) bool {
	a, b := l.Request, other.Request
	until := a.Until.Equal(b.Until)
	a.Until, b.Until = time.Time{}, time.Time{}
	return a == b && until && l.Fence == other.Fence && l.Started.Equal(other.Started)
}

func (l WorkerOwnerLease) Valid(now time.Time) bool {
	return l.Fence > 0 && l.Fence <= 9007199254740991 && !l.Started.IsZero() && !now.Before(l.Started) && l.Request.Valid(l.Started) && now.Before(l.Request.Until)
}
