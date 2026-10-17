//go:build ignore

package main

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	cfg "asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Counters see no URL, argument, credential or body. Expected independent guard
// denial is separated from an unexpected transport/status failure. Header time
// does not prove server processing/SQL lock time.
type apiCounters struct {
	requests, denied, errors, headerNanos atomic.Int64
}
type metrics struct{ observer, probe apiCounters }
type apiSnapshot = APISnapshot
type poolSnapshot = PoolSnapshot
type metricsSnapshot = MetricsSnapshot
type measuredTransport struct {
	base   http.RoundTripper
	counts *apiCounters
}

func (t measuredTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	start := time.Now()
	t.counts.requests.Add(1)
	response, err := t.base.RoundTrip(r)
	t.counts.headerNanos.Add(time.Since(start).Nanoseconds())
	if err != nil || response == nil {
		t.counts.errors.Add(1)
	} else if response.StatusCode == http.StatusForbidden {
		t.counts.denied.Add(1)
	} else if response.StatusCode >= 400 {
		t.counts.errors.Add(1)
	}
	return response, err
}
func (c *apiCounters) snapshot() apiSnapshot {
	return apiSnapshot{c.requests.Load(), c.denied.Load(), c.errors.Load(), c.headerNanos.Load()}
}
func (m *metrics) wrap(probe bool) func(http.RoundTripper) http.RoundTripper {
	c := &m.observer
	if probe {
		c = &m.probe
	}
	return func(base http.RoundTripper) http.RoundTripper { return measuredTransport{base, c} }
}
func (m *metrics) snapshot(pools map[string]*pgxpool.Pool) metricsSnapshot {
	out := metricsSnapshot{Observer: m.observer.snapshot(), Probe: m.probe.snapshot(), SQL: map[string]poolSnapshot{}}
	for purpose, pool := range pools {
		s := pool.Stat()
		out.SQL[purpose] = poolSnapshot{s.AcquireCount(), s.AcquireDuration().Nanoseconds(), s.EmptyAcquireCount(), s.CanceledAcquireCount()}
	}
	return out
}
func errorCategory(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, cfg.ErrInvalid) || errors.Is(err, value.ErrInvalid):
		return "invalid"
	case errors.Is(err, cfg.ErrDenied) || errors.Is(err, value.ErrDenied) || errors.Is(err, value.ErrClusterCredentialDenied) || errors.Is(err, value.ErrClusterCredentialFenced):
		return "denied"
	case errors.Is(err, cfg.ErrChanged):
		return "changed"
	default:
		return "unavailable"
	}
}
