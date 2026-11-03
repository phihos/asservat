package analysis

import (
	"math"
	"unicode"
	"unicode/utf8"
)

const (
	ProfileSummaryDefaultTop = 20
	ProfileSummaryMaximumTop = 100
	ProfileSummaryBytes      = 24 << 10
	// JSON clients must receive exact integers, including signed heap deltas.
	ProfileSummaryMaximumValue int64 = 1<<53 - 1
)

// ProfileSummarySelection is a bounded display selection, never authority to
// read the raw profile. Its query scope must separately bind the exact artifact.
type ProfileSummarySelection struct {
	SampleType string
	TopN       int
}

func NormalizeProfileSummarySelection(sampleType string, topN int) (ProfileSummarySelection, error) {
	if topN == 0 {
		topN = ProfileSummaryDefaultTop
	}
	s := ProfileSummarySelection{SampleType: sampleType, TopN: topN}
	if !s.Valid() {
		return ProfileSummarySelection{}, ErrInvalid
	}
	return s, nil
}
func (s ProfileSummarySelection) Valid() bool {
	return ProfileSummaryText(s.SampleType, 64) && s.TopN >= 1 && s.TopN <= ProfileSummaryMaximumTop
}

// ProfileSummaryText admits bounded display text, not markup or an executable
// symbol/path. Transport rendering must still treat every name as user data.
func ProfileSummaryText(s string, maximum int) bool {
	if len(s) == 0 || len(s) > maximum || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

type ProfileHotspot struct {
	Function   *string `json:"function"`
	Flat       int64   `json:"flat"`
	Cumulative int64   `json:"cumulative"`
	// Fraction is flat / total only for nonnegative samples and a
	// positive total. Signed deltas and zero totals have no percentage.
	Fraction *float64 `json:"fraction"`
}

// ProfileSummary contains only the approved aggregate fields. It deliberately
// cannot hold raw samples, labels, comments, paths, mappings or addresses.
// This value does not activate the approved projection source registry.
type ProfileSummary struct {
	SampleType      string           `json:"sample_type"`
	Unit            string           `json:"unit"`
	DurationSeconds *float64         `json:"duration_seconds"`
	Total           int64            `json:"total"`
	Top             []ProfileHotspot `json:"top"`
	SymbolStatus    string           `json:"symbol_status"`
}

func ProfileSummaryValue(v int64) bool {
	return v >= -ProfileSummaryMaximumValue && v <= ProfileSummaryMaximumValue
}

func (r ProfileSummary) Valid(s ProfileSummarySelection) bool {
	if !s.Valid() || r.SampleType != s.SampleType || !ProfileSummaryText(r.Unit, 64) || !ProfileSummaryValue(r.Total) || r.Top == nil || len(r.Top) > s.TopN {
		return false
	}
	if r.DurationSeconds != nil && (math.IsNaN(*r.DurationSeconds) || math.IsInf(*r.DurationSeconds, 0) || *r.DurationSeconds <= 0 || *r.DurationSeconds > 86400) {
		return false
	}
	if r.SymbolStatus != "complete" && r.SymbolStatus != "partial" && r.SymbolStatus != "missing" {
		return false
	}
	if len(r.Top) == 0 && (r.Total != 0 || r.SymbolStatus != "missing") {
		return false
	}
	seen := make(map[string]bool, len(r.Top))
	var nullSeen bool
	var flatTotal int64
	for i, h := range r.Top {
		if !ProfileSummaryValue(h.Flat) || !ProfileSummaryValue(h.Cumulative) {
			return false
		}
		if h.Function == nil {
			if r.SymbolStatus == "complete" || nullSeen {
				return false
			}
			nullSeen = true
		} else {
			if r.SymbolStatus == "missing" || !ProfileSummaryText(*h.Function, 512) || seen[*h.Function] {
				return false
			}
			seen[*h.Function] = true
		}
		if i > 0 && (h.Fraction == nil) != (r.Top[0].Fraction == nil) {
			return false
		}
		if h.Fraction != nil {
			flatTotal += h.Flat
			if flatTotal > r.Total {
				return false
			}
			if r.Total <= 0 || h.Flat < 0 || h.Flat > h.Cumulative || h.Cumulative < 0 || h.Cumulative > r.Total || math.IsNaN(*h.Fraction) || math.IsInf(*h.Fraction, 0) || *h.Fraction != float64(h.Flat)/float64(r.Total) {
				return false
			}
		}
	}
	return true
}
