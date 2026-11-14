package integration

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"time"

	query "asservat.local/asservat/internal/domain/analysis"
	"github.com/google/pprof/profile"
)

const installedProfileComparisonQueries = 2

func installedProfileFocus() bool {
	return installedJourneyFocus() == "manual-profile" || installedJourneyFocus() == "profile-comparison"
}

type installedProfileComparisonSource struct {
	CaseID, ArtifactID, Version string
	Native                      []byte
	Expires                     time.Time
	Retirement                  func()
}

// The live check must run before later normal demand can retire its exact Pod.
// Only the original worker's terminal wait belongs to the two-worker cohort.
type installedProfileComparisonProof struct {
	capture  func(string, string) func() func()
	terminal func() func()
}

func (p *installedProfileComparisonProof) observe(handle, operation string) {
	if p.terminal == nil {
		p.terminal = p.capture(handle, operation)
	}
}

func (p *installedProfileComparisonProof) join(handle, operation string) func() {
	p.observe(handle, operation)
	if p.terminal == nil {
		return nil
	}
	return p.terminal()
}

type installedComparisonReply struct{ installedJourneyEnvelope }

// A separate fixture calculation: parse the downloaded originals, accumulate
// each function once per sample (including inline/recursive stack members),
// compute exact rational rates/deltas, sort all names and truncate only last.
// It calls no production comparison/aggregation implementation.
func independentInstalledProfileComparison(baseline, incident []byte, limit int) ([]query.ProfileComparisonRow, [2]int64, [2]float64, error) {
	var totals [2]int64
	var durations [2]float64
	var profiles [2]*profile.Profile
	counts := [2]map[string]int64{{}, {}}
	for side, native := range [2][]byte{baseline, incident} {
		p, err := profile.ParseData(native)
		if err != nil || p.CheckValid() != nil || p.DurationNanos <= 0 {
			return nil, totals, durations, errors.New("invalid fixture CPU profile")
		}
		profiles[side] = p
		durations[side] = float64(p.DurationNanos) / 1e9
		cpu := -1
		for i, typ := range p.SampleType {
			if typ.Type == "cpu" && typ.Unit == "nanoseconds" {
				cpu = i
			}
		}
		if cpu < 0 {
			return nil, totals, durations, errors.New("fixture lacks CPU nanoseconds")
		}
		for _, sample := range p.Sample {
			if cpu >= len(sample.Value) {
				return nil, totals, durations, errors.New("missing CPU value")
			}
			value := sample.Value[cpu]
			totals[side] += value
			names := map[string]bool{}
			if len(sample.Location) == 0 {
				names[""] = true
			}
			for _, location := range sample.Location {
				if location == nil || len(location.Line) == 0 {
					names[""] = true
					continue
				}
				for _, line := range location.Line {
					name := ""
					if line.Function != nil {
						name = line.Function.Name
					}
					names[name] = true
				}
			}
			for name := range names {
				counts[side][name] += value
			}
		}
	}
	names := map[string]bool{}
	for _, side := range counts {
		for name := range side {
			names[name] = true
		}
	}
	rows := make([]query.ProfileComparisonRow, 0, len(names))
	rate := func(value, duration int64) *big.Rat {
		return new(big.Rat).SetFrac(new(big.Int).Mul(big.NewInt(value), big.NewInt(1e9)), big.NewInt(duration))
	}
	for name := range names {
		b, i := rate(counts[0][name], profiles[0].DurationNanos), rate(counts[1][name], profiles[1].DurationNanos)
		bf, _ := b.Float64()
		inf, _ := i.Float64()
		delta, _ := new(big.Rat).Sub(i, b).Float64()
		row := query.ProfileComparisonRow{Baseline: bf, Incident: inf, Delta: delta}
		if name != "" {
			n := name
			row.Function = &n
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if math.Abs(rows[i].Delta) != math.Abs(rows[j].Delta) {
			return math.Abs(rows[i].Delta) > math.Abs(rows[j].Delta)
		}
		a, b := "", ""
		if rows[i].Function != nil {
			a = *rows[i].Function
		}
		if rows[j].Function != nil {
			b = *rows[j].Function
		}
		return a < b
	})
	if limit < 1 {
		return nil, totals, durations, fmt.Errorf("invalid fixture row limit %d", limit)
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, totals, durations, nil
}
