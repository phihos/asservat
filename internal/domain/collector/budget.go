package collector

import (
	"math"
	"math/bits"
	"time"
)

// Node budget bounds (ADR-246). The collector-wide ceilings are the local
// administrator's Helm values; a budget policy's node limits can only lower
// them (specs/capacity.md: node limits are intersected, never multiplied).
const (
	MaxNodeRingBytes      int64 = 4 << 30
	MaxNodeFrozenBytes    int64 = 4 << 30
	MaxNodeUploadRate     int64 = 10 << 30
	MaxNodeUploadBurst    int64 = 10 << 30
	DefaultNodeRingBytes  int64 = 256 << 20
	DefaultNodeFrozen     int64 = 256 << 20
	DefaultNodeUploadRate int64 = 32 << 20
	DefaultNodeBurst      int64 = 64 << 20
)

// Ceilings are one node's byte budgets: memory held by armed source rings,
// memory held by frozen snapshot copies awaiting upload, and the upload rate
// with its burst. Zero means nothing of that kind may be reserved.
type Ceilings struct {
	RingBytes            int64
	FrozenBytes          int64
	UploadBytesPerSecond int64
	UploadBurstBytes     int64
}

func (c Ceilings) Valid() bool {
	return c.RingBytes >= 0 && c.RingBytes <= MaxNodeRingBytes &&
		c.FrozenBytes >= 0 && c.FrozenBytes <= MaxNodeFrozenBytes &&
		c.UploadBytesPerSecond >= 0 && c.UploadBytesPerSecond <= MaxNodeUploadRate &&
		c.UploadBurstBytes >= 0 && c.UploadBurstBytes <= MaxNodeUploadBurst &&
		(c.UploadBytesPerSecond == 0) == (c.UploadBurstBytes == 0)
}

// PolicyLimits are the optional node limits of an EvidenceBudgetPolicy; zero
// means the policy sets no limit of that kind.
type PolicyLimits struct {
	RingBytes            int64
	FrozenBytes          int64
	UploadBytesPerSecond int64
	UploadBurstBytes     int64
}

// Intersect returns the tighter of the collector ceiling and each policy limit.
func (c Ceilings) Intersect(p PolicyLimits) Ceilings {
	lower := func(a, b int64) int64 {
		if b > 0 && b < a {
			return b
		}
		return a
	}
	return Ceilings{lower(c.RingBytes, p.RingBytes), lower(c.FrozenBytes, p.FrozenBytes), lower(c.UploadBytesPerSecond, p.UploadBytesPerSecond), lower(c.UploadBurstBytes, p.UploadBurstBytes)}
}

// Budget accounts one node's reservations. Ring and frozen bytes are held
// until released; upload is a token bucket refilled at the configured rate up
// to the burst. A reservation that does not fit fails without partial effect.
// Budget is not safe for concurrent use; its owner serializes access.
type Budget struct {
	ceilings     Ceilings
	ring, frozen int64
	tokens       int64
	refilled     time.Time
}

func NewBudget(c Ceilings, now time.Time) (*Budget, error) {
	if !c.Valid() || now.IsZero() {
		return nil, ErrInvalid
	}
	return &Budget{ceilings: c, tokens: c.UploadBurstBytes, refilled: now}, nil
}

func (b *Budget) Ceilings() Ceilings { return b.ceilings }

func reserve(held *int64, limit, n int64) error {
	if n <= 0 {
		return ErrInvalid
	}
	if n > limit-*held {
		return ErrExceeded
	}
	*held += n
	return nil
}

func release(held *int64, n int64) error {
	if n <= 0 || n > *held {
		return ErrInvalid
	}
	*held -= n
	return nil
}

func (b *Budget) ReserveRing(n int64) error   { return reserve(&b.ring, b.ceilings.RingBytes, n) }
func (b *Budget) ReleaseRing(n int64) error   { return release(&b.ring, n) }
func (b *Budget) ReserveFrozen(n int64) error { return reserve(&b.frozen, b.ceilings.FrozenBytes, n) }
func (b *Budget) ReleaseFrozen(n int64) error { return release(&b.frozen, n) }
func (b *Budget) refill(now time.Time) {
	if !now.After(b.refilled) {
		return
	}
	elapsed := now.Sub(b.refilled)
	b.refilled = now
	room := b.ceilings.UploadBurstBytes - b.tokens
	if room <= 0 {
		return
	}
	hi, lo := bits.Mul64(uint64(b.ceilings.UploadBytesPerSecond), uint64(elapsed))
	if hi >= uint64(time.Second) {
		b.tokens = b.ceilings.UploadBurstBytes
		return
	}
	add, _ := bits.Div64(hi, lo, uint64(time.Second))
	if add >= uint64(room) || add > math.MaxInt64 {
		b.tokens = b.ceilings.UploadBurstBytes
		return
	}
	b.tokens += int64(add)
}

// TakeUpload consumes n upload bytes at now. When the bucket holds fewer, it
// consumes nothing and returns how long to wait before n bytes are available.
// A request larger than the burst can never be satisfied.
func (b *Budget) TakeUpload(now time.Time, n int64) (time.Duration, error) {
	if n <= 0 || now.IsZero() {
		return 0, ErrInvalid
	}
	if n > b.ceilings.UploadBurstBytes {
		return 0, ErrExceeded
	}
	b.refill(now)
	if b.tokens >= n {
		b.tokens -= n
		return 0, nil
	}
	missing := n - b.tokens
	hi, lo := bits.Mul64(uint64(missing), uint64(time.Second))
	wait, rem := bits.Div64(hi, lo, uint64(b.ceilings.UploadBytesPerSecond))
	if rem != 0 {
		wait++
	}
	return time.Duration(wait), nil
}

// Usage is a point-in-time view for status reports.
type Usage struct {
	Ceilings        Ceilings
	RingReserved    int64
	FrozenReserved  int64
	UploadAvailable int64
}

func (b *Budget) Usage(now time.Time) Usage {
	b.refill(now)
	return Usage{Ceilings: b.ceilings, RingReserved: b.ring, FrozenReserved: b.frozen, UploadAvailable: b.tokens}
}
