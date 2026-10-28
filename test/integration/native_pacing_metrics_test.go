package integration

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// All counters belong to the owned fixture. Runtime authorization never reads
// these snapshots. SQL is background-inclusive and provider dispatch counts end
// at response headers, not body completion or cryptographic success.
type nativeProviderCounters struct {
	Dispatches        int64 `json:"dispatches"`
	Active            int64 `json:"active_roundtrips"`
	Errors            int64 `json:"transport_errors"`
	Status2xx         int64 `json:"status_2xx"`
	Status3xx         int64 `json:"status_3xx"`
	Status4xx         int64 `json:"status_4xx"`
	Status5xx         int64 `json:"status_5xx"`
	StatusOther       int64 `json:"status_other"`
	HeaderNanoseconds int64 `json:"roundtrip_to_headers_nanoseconds"`
}

var nativeProviderCategories = []string{"s3_get", "s3_head", "s3_put", "s3_post", "s3_delete", "s3_other", "kms_encrypt", "kms_decrypt", "kms_sign", "kms_verify", "kms_login", "kms_lookup", "kms_renew", "kms_revoke", "kms_other"}

type nativePacingSnapshot struct {
	StartedAt, FinishedAt time.Time
	SQL                   nativeSQLSnapshot
	Providers             map[string]nativeProviderCounters
}

type nativePacingPhase struct {
	Name          string    `json:"name"`
	StartedAt     time.Time `json:"startedAt"`
	FinishedAt    time.Time `json:"finishedAt"`
	Before, After nativePacingSnapshot
	SQLDelta      map[uint32]nativeSQLCounters
	ProviderDelta map[string]nativeProviderCounters
}

// Optional target-cgroup diagnostics are independent of authority and artifact
// qualification. Missing or discontinuous data is explicit, never a zero delta.
type nativePacingTargetCPU struct {
	Before, After                                   *nativeTrafficCPU
	BeforeAvailable, AfterAvailable, DeltaAvailable bool
	Delta                                           map[string]uint64
}

func nativePacingTargetCPUSamples(before, after *nativeTrafficCPU) nativePacingTargetCPU {
	out := nativePacingTargetCPU{Before: before, After: after, BeforeAvailable: before != nil, AfterAvailable: after != nil}
	if before == nil || after == nil || before.StartedAt.IsZero() || before.FinishedAt.Before(before.StartedAt) || after.StartedAt.Before(before.FinishedAt) || after.FinishedAt.Before(after.StartedAt) {
		return out
	}
	delta, err := nativeTrafficCPUDelta(*before, *after)
	if err == nil {
		out.Delta = delta
		out.DeltaAvailable = true
	}
	return out
}

type nativePacingMeasurement struct {
	traffic                                                  nativeTrafficHelper
	admin                                                    *pgxpool.Pool
	root                                                     string
	providers                                                *initialRuntimeNativeProviders
	Phases                                                   []nativePacingPhase `json:"phases"`
	Traffic                                                  nativeTrafficResult
	TargetCPU                                                nativePacingTargetCPU
	TrafficEndedAtDeadline                                   bool
	TrafficStartedAt, TrafficFinishedAt, ExecutionObservedAt time.Time
	Owner                                                    nativePacingOwnerReport
	Bodies                                                   map[string]nativePacingResult
	NearFullBytes                                            int64
	MeasurementFailure                                       string `json:"measurement_failure,omitempty"`
	Complete                                                 bool
	PCAPInterfaceStatistics                                  string
	FirstPacketAt, LastPacketAt                              time.Time
	PacketsDuringTraffic                                     int64
	// The current native format combines drops in its standard ISB. Separate
	// OutputFull versus engine LostSamples is not exposed to this fixture.
	CollectorDropBreakdownAvailable       bool
	DistinctSessionCount                  int
	RangeSessionReused                    bool
	ObservedSQLDelta                      map[uint32]nativeSQLCounters
	ObservedProviderDelta                 map[string]nativeProviderCounters
	ObservedStartedAt, ObservedFinishedAt time.Time
}

func (m *nativePacingMeasurement) snapshot(ctx context.Context) (nativePacingSnapshot, error) {
	s := nativePacingSnapshot{StartedAt: time.Now().UTC()}
	var err error
	s.SQL, err = nativePacingSQLSnapshot(ctx, m.admin)
	if err != nil {
		return s, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(m.providers.fixture.NativeProviders.S3, "/")+"/__asservat_fixture/counters", nil)
	if err != nil {
		return s, errors.New("provider counter URL unavailable")
	}
	response, err := m.providers.client.Do(req)
	if err != nil {
		return s, errors.New("provider counters unavailable")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil || len(raw) > 16384 || response.StatusCode != http.StatusOK || json.Unmarshal(raw, &s.Providers) != nil || len(s.Providers) != len(nativeProviderCategories) {
		return s, errors.New("provider counter shape unavailable")
	}
	for _, name := range nativeProviderCategories {
		c, ok := s.Providers[name]
		if !ok || !c.valid() {
			return s, errors.New("provider counter category unavailable")
		}
	}
	s.FinishedAt = time.Now().UTC()
	return s, nil
}

func (c nativeProviderCounters) valid() bool {
	return c.Dispatches >= 0 && c.Active >= 0 && c.Errors >= 0 && c.Status2xx >= 0 && c.Status3xx >= 0 && c.Status4xx >= 0 && c.Status5xx >= 0 && c.StatusOther >= 0 && c.HeaderNanoseconds >= 0
}

func nativeProviderDelta(a, b map[string]nativeProviderCounters) (map[string]nativeProviderCounters, error) {
	if len(a) != len(nativeProviderCategories) || len(b) != len(nativeProviderCategories) {
		return nil, errors.New("provider counter categories changed")
	}
	out := make(map[string]nativeProviderCounters, len(b))
	for _, name := range nativeProviderCategories {
		x, okA := a[name]
		y, okB := b[name]
		// Active is a gauge; retain both edge snapshots and report its signed
		// change separately from monotonic dispatch/status/duration counters.
		d := nativeProviderCounters{Dispatches: y.Dispatches - x.Dispatches, Errors: y.Errors - x.Errors, Status2xx: y.Status2xx - x.Status2xx, Status3xx: y.Status3xx - x.Status3xx, Status4xx: y.Status4xx - x.Status4xx, Status5xx: y.Status5xx - x.Status5xx, StatusOther: y.StatusOther - x.StatusOther, HeaderNanoseconds: y.HeaderNanoseconds - x.HeaderNanoseconds}
		if !okA || !okB || !x.valid() || !y.valid() || !d.valid() {
			return nil, errors.New("provider counters reset or moved backwards")
		}
		d.Active = y.Active - x.Active
		out[name] = d
	}
	return out, nil
}

// End snapshots enclose the phase edges. Their own administrative SQL and
// provider-counter reads are excluded by the lower-level fixture counters.
func (m *nativePacingMeasurement) begin(ctx context.Context, name string) (func() error, error) {
	if m == nil || len(m.Phases) >= 24 {
		return nil, errors.New("native phase budget exceeded")
	}
	for _, p := range m.Phases {
		if p.Name == name {
			return nil, errors.New("duplicate native phase")
		}
	}
	before, err := m.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	phase := nativePacingPhase{Name: name, Before: before, StartedAt: time.Now().UTC()}
	ended := false
	return func() error {
		if ended {
			return errors.New("native phase already ended")
		}
		ended = true
		phase.FinishedAt = time.Now().UTC()
		phase.After, err = m.snapshot(ctx)
		if err == nil {
			phase.SQLDelta, err = nativePacingSQLDelta(before.SQL, phase.After.SQL)
		}
		if err == nil {
			phase.ProviderDelta, err = nativeProviderDelta(before.Providers, phase.After.Providers)
		}
		m.Phases = append(m.Phases, phase)
		return err
	}, nil
}

func (m *nativePacingMeasurement) writeReport() error {
	// Persist the bounded edge observations even when coverage was lost. A
	// failed comparison never becomes a complete report or a fabricated zero.
	m.ObservedSQLDelta, m.ObservedProviderDelta = nil, nil
	m.MeasurementFailure = ""
	var measurementErr error
	if len(m.Phases) > 0 {
		first, last := m.Phases[0].Before, m.Phases[len(m.Phases)-1].After
		m.ObservedStartedAt, m.ObservedFinishedAt = first.StartedAt, last.FinishedAt
		m.ObservedSQLDelta, measurementErr = nativePacingSQLDelta(first.SQL, last.SQL)
		if measurementErr == nil {
			m.ObservedProviderDelta, measurementErr = nativeProviderDelta(first.Providers, last.Providers)
		}
	}
	if measurementErr != nil {
		m.Complete = false
		m.MeasurementFailure = measurementErr.Error()
	}
	// Unexported fixture pointers/installation IDs/SQL credentials never leave
	// this object. An incomplete report stays explicitly incomplete.
	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile("../results/native-paced-report.json", append(raw, '\n'), 0600); err != nil {
		return err
	}
	return measurementErr
}
