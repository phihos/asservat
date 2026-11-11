package authorization

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"asservat.local/asservat/internal/domain/privacy"
)

// DownloadPolicyObservations owns one protected policy per installed reader.
// Refresh is synchronous and belongs to its requesting caller; concurrent
// callers may wait for that read but retain their own cancellation. No stale
// observation survives expiry or a failed refresh. An observation is valid for
// its accepted 60-second interval (ADR-311). A cached observation is reused
// while it is valid now and still outlives one check's I/O timeout
// (downloadCheckTimeout), so a new check never straddles policy expiry and is
// refused mid-check. That margin only triggers an earlier refresh; it is not an
// authority bound, and every consumer still ends at the original FreshUntil.
type DownloadPolicyObservations struct {
	reader  DownloadPolicyReader
	now     func() time.Time
	mu      sync.Mutex
	policy  privacy.DownloadPolicy
	lastNow time.Time
	flight  *downloadPolicyRead
}

type downloadPolicyRead struct {
	done   chan struct{}
	policy privacy.DownloadPolicy
	err    error
}

func NewDownloadPolicyObservations(reader DownloadPolicyReader, now func() time.Time) (*DownloadPolicyObservations, error) {
	if reader == nil || now == nil {
		return nil, privacy.ErrInvalid
	}
	return &DownloadPolicyObservations{reader: reader, now: now}, nil
}

func (s *DownloadPolicyObservations) DownloadPolicy(ctx context.Context) (privacy.DownloadPolicy, error) {
	var zero privacy.DownloadPolicy
	if s == nil {
		return zero, privacy.ErrUnavailable
	}
	s.mu.Lock()
	now, err := s.current(ctx)
	if err != nil {
		s.mu.Unlock()
		return zero, err
	}
	if s.policy.DownloadValid(now) && s.policy.FreshUntil.Sub(now) >= downloadCheckTimeout {
		out := cloneDownloadPolicy(s.policy)
		s.mu.Unlock()
		return out, nil
	}
	s.policy = zero
	if read := s.flight; read != nil {
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return zero, errors.Join(privacy.ErrUnavailable, ctx.Err())
		case <-read.done:
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		now, err = s.current(ctx)
		if err != nil {
			return zero, err
		}
		if read.err != nil {
			return zero, read.err
		}
		// A joined read is a new live observation: valid now suffices.
		if !read.policy.DownloadValid(now) {
			return zero, privacy.ErrUnavailable
		}
		return cloneDownloadPolicy(read.policy), nil
	}
	read := &downloadPolicyRead{done: make(chan struct{})}
	s.flight = read
	s.mu.Unlock()

	call, cancel := context.WithTimeout(ctx, downloadCheckTimeout)
	readUntil, _ := call.Deadline()
	p, err := s.reader.DownloadPolicy(call)
	if callErr := downloadPolicyCallError(call); callErr != nil {
		err = callErr
	}
	cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	now, currentErr := s.current(ctx)
	if !time.Now().Before(readUntil) {
		err = errors.Join(privacy.ErrUnavailable, context.DeadlineExceeded)
	}
	if currentErr != nil {
		err = currentErr
	}
	if err == nil && !p.Valid(now) {
		err = privacy.ErrUnavailable
	}
	if err == nil {
		// Only a completed live read (within its I/O timeout) may be retained. The
		// download interval starts at that observation, never at a cache hit.
		p = cloneDownloadPolicy(p)
		p.FreshUntil = p.ObservedAt.Add(privacy.DownloadPolicyObservationInterval)
		s.policy = p
		read.policy = p
	}
	read.err = err
	s.flight = nil
	close(read.done)
	if err != nil {
		return zero, err
	}
	return cloneDownloadPolicy(p), nil
}

// current is called with mu held. Retaining the greatest observed clock value
// prevents a backward clock from reviving or lengthening an observation.
func (s *DownloadPolicyObservations) current(ctx context.Context) (time.Time, error) {
	if err := downloadPolicyCallError(ctx); err != nil {
		return time.Time{}, err
	}
	now := s.now()
	if now.IsZero() || now.Before(s.lastNow) {
		return time.Time{}, privacy.ErrUnavailable
	}
	s.lastNow = now
	return now, nil
}

func downloadPolicyCallError(ctx context.Context) error {
	if ctx == nil {
		return privacy.ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(privacy.ErrUnavailable, err)
	}
	// Context cancellation timers can run after the wall-clock cutoff.
	if until, ok := ctx.Deadline(); ok && !time.Now().Before(until) {
		return errors.Join(privacy.ErrUnavailable, context.DeadlineExceeded)
	}
	return nil
}

func cloneDownloadPolicy(p privacy.DownloadPolicy) privacy.DownloadPolicy {
	p.PermittedRegions = slices.Clone(p.PermittedRegions)
	p.Paths = slices.Clone(p.Paths)
	p.Operators = slices.Clone(p.Operators)
	p.Processors = slices.Clone(p.Processors)
	for i := range p.Processors {
		organization := &p.Processors[i]
		organization.Activities = slices.Clone(organization.Activities)
		organization.Regions = slices.Clone(organization.Regions)
	}
	p.Clients = slices.Clone(p.Clients)
	for i := range p.Clients {
		c := &p.Clients[i]
		c.DataClasses = slices.Clone(c.DataClasses)
		c.PrivacyClasses = slices.Clone(c.PrivacyClasses)
		c.EvidenceTypes = slices.Clone(c.EvidenceTypes)
		c.Purposes = slices.Clone(c.Purposes)
		c.PathIDs = slices.Clone(c.PathIDs)
	}
	return p
}

// downloadCheckTimeout is the I/O timeout of one live delivery-policy read. It
// bounds blocking work, not how long the resulting observation is valid.
const downloadCheckTimeout = 5 * time.Second
