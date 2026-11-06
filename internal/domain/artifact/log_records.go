package artifact

import (
	"encoding/base64"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	LogFormat                 = "asservat-logs/v1"
	LogNativeLimit      int64 = 64 << 20
	LogMaxLine                = 8192
	LogMaxFragmentBytes       = 4096
	LogMaxOrigins             = 128
)

// Log records describe saved raw bytes, never capture or disclosure authority.
// Requested windows and source times are distinct from actual fetch intervals.
type LogHeader struct {
	Record      string    `json:"record"`
	Format      string    `json:"format"`
	PodUID      string    `json:"pod_uid"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	Origins     uint16    `json:"origins"`
}
type LogOrigin struct {
	Record        string  `json:"record"`
	OriginID      uint16  `json:"origin_id"`
	ContainerKind string  `json:"container_kind"`
	ContainerName string  `json:"container_name"`
	Source        string  `json:"source"`
	Stream        string  `json:"stream"`
	RuntimeID     *string `json:"runtime_id"`
	RestartCount  *uint32 `json:"restart_count"`
}
type LogFragment struct {
	Record       string  `json:"record"`
	OriginID     uint16  `json:"origin_id"`
	Line         uint64  `json:"line"`
	Offset       uint64  `json:"offset"`
	LineOffset   uint64  `json:"line_offset"`
	Continuation bool    `json:"continuation"`
	EndLine      bool    `json:"end_line"`
	SourceTime   *string `json:"source_time"`
	Data         string  `json:"data"`
}
type LogCoverage struct {
	Record          string     `json:"record"`
	OriginID        uint16     `json:"origin_id"`
	FetchOutcome    string     `json:"fetch_outcome"`
	FetchStartedAt  *time.Time `json:"fetch_started_at"`
	FetchFinishedAt *time.Time `json:"fetch_finished_at"`
	SourceBytes     uint64     `json:"source_bytes"`
	Fragments       uint64     `json:"fragments"`
	Lines           uint64     `json:"lines"`
	Gaps            []string   `json:"gaps"`
}
type LogFooter struct {
	Record      string `json:"record"`
	Origins     uint16 `json:"origins"`
	SourceBytes uint64 `json:"source_bytes"`
	Fragments   uint64 `json:"fragments"`
	Lines       uint64 `json:"lines"`
}

func logText(v string, max int) bool {
	if len(v) < 1 || len(v) > max || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func logTime(v time.Time) bool { return !v.IsZero() && v.Year() >= 1 && v.Year() <= 9999 }
func (h LogHeader) WellFormed() bool {
	return h.Record == "header" && h.Format == LogFormat && logText(h.PodUID, 128) && logTime(h.WindowStart) && logTime(h.WindowEnd) && !h.WindowEnd.Before(h.WindowStart) && h.Origins > 0 && h.Origins <= LogMaxOrigins
}
func (o LogOrigin) WellFormed() bool {
	if o.Record != "origin" || o.OriginID >= LogMaxOrigins || o.Stream != "combined" || (o.Source != "current" && o.Source != "previous") || (o.ContainerKind != "regular" && o.ContainerKind != "init" && o.ContainerKind != "ephemeral") || len(o.ContainerName) < 1 || len(o.ContainerName) > 63 {
		return false
	}
	for i, c := range o.ContainerName {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' && i > 0 && i < len(o.ContainerName)-1) {
			return false
		}
	}
	return o.RuntimeID == nil || logText(*o.RuntimeID, 256)
}
func (f LogFragment) Bytes() ([]byte, error) {
	if f.Record != "fragment" || f.OriginID >= LogMaxOrigins || f.Line < 1 || f.Line > uint64(LogNativeLimit) || f.Offset > uint64(LogNativeLimit) || f.LineOffset > f.Offset || f.Continuation != (f.LineOffset > 0) || len(f.Data) > base64.StdEncoding.EncodedLen(LogMaxFragmentBytes) {
		return nil, ErrInvalid
	}
	if f.SourceTime != nil {
		if len(*f.SourceTime) > 64 {
			return nil, ErrInvalid
		}
		if t, e := time.Parse(time.RFC3339Nano, *f.SourceTime); e != nil || !logTime(t) {
			return nil, ErrInvalid
		}
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(f.Data)
	if err != nil || len(raw) < 1 || len(raw) > LogMaxFragmentBytes || base64.StdEncoding.EncodeToString(raw) != f.Data {
		clear(raw)
		return nil, ErrInvalid
	}
	if uint64(len(raw)) > uint64(LogNativeLimit)-f.Offset {
		clear(raw)
		return nil, ErrInvalid
	}
	newline := strings.IndexByte(string(raw), '\n')
	if (newline >= 0 && newline != len(raw)-1) || f.EndLine != (newline == len(raw)-1) {
		clear(raw)
		return nil, ErrInvalid
	}
	return raw, nil
}
func (c LogCoverage) WellFormed() bool {
	if c.Record != "coverage" || c.OriginID >= LogMaxOrigins || c.SourceBytes > uint64(LogNativeLimit) || c.Fragments > c.SourceBytes || c.Lines > c.Fragments || c.Gaps == nil || len(c.Gaps) > 7 || (c.FetchStartedAt == nil) != (c.FetchFinishedAt == nil) {
		return false
	}
	if c.FetchStartedAt != nil && (!logTime(*c.FetchStartedAt) || !logTime(*c.FetchFinishedAt) || c.FetchFinishedAt.Before(*c.FetchStartedAt)) {
		return false
	}
	if c.FetchOutcome != "complete" && c.FetchOutcome != "partial" && c.FetchOutcome != "unavailable" {
		return false
	}
	if (c.FetchOutcome == "complete" || c.SourceBytes > 0) && c.FetchStartedAt == nil || c.FetchOutcome == "unavailable" && c.SourceBytes != 0 || c.FetchOutcome != "complete" && len(c.Gaps) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, g := range c.Gaps {
		switch g {
		case "sourceUnavailable", "previousUnavailable", "rotationUnknown", "sourceChanged", "timedOut", "outputFull", "timestampUnknown":
		default:
			return false
		}
		if seen[g] {
			return false
		}
		seen[g] = true
	}
	return true
}
func (f LogFooter) WellFormed() bool {
	return f.Record == "footer" && f.Origins > 0 && f.Origins <= LogMaxOrigins && f.SourceBytes <= uint64(LogNativeLimit) && f.Fragments <= f.SourceBytes && f.Lines <= f.Fragments
}
