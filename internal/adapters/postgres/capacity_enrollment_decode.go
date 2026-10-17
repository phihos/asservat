package postgres

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"io"
	"time"

	app "asservat.local/asservat/internal/application/capacity"
	cfg "asservat.local/asservat/internal/domain/configuration"
)

type capacityEnrollmentRead struct {
	Enrollment *app.Enrollment
	FreshUntil time.Time
}

// An exact null row is different from unavailable/malformed output. Neither is
// evidence that a former SQL request had no effect; the scoped RPC supplies the
// original current deadline only after the shared transaction lock prefix.
func decodeCapacityEnrollment(raw []byte) (capacityEnrollmentRead, error) {
	var out capacityEnrollmentRead
	if len(raw) < 2 || len(raw) > 8192 {
		return out, cfg.ErrUnavailable
	}
	canonical := jsontext.Value(bytes.Clone(raw))
	if canonical.Canonicalize() != nil {
		return out, cfg.ErrUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil {
		return capacityEnrollmentRead{}, cfg.ErrUnavailable
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return capacityEnrollmentRead{}, cfg.ErrUnavailable
	}
	encoded, e := json.Marshal(out)
	if e != nil || !capacitySameJSONFields(raw, encoded) || out.FreshUntil.IsZero() || out.FreshUntil.Nanosecond()%1000 != 0 || out.Enrollment != nil && !out.Enrollment.Valid() {
		return capacityEnrollmentRead{}, cfg.ErrUnavailable
	}
	return out, nil
}

func (v capacityEnrollmentRead) matches(o app.EnrollmentObservation, now time.Time) bool {
	if !o.Valid(now) || !now.Before(v.FreshUntil) || v.FreshUntil.After(o.FreshUntil) {
		return false
	}
	if v.Enrollment == nil {
		return true
	}
	e := v.Enrollment
	return e.Valid() && e.Key == o.Key && e.SourceDigest == o.SourceDigest && e.PlanDigest == o.PlanDigest && e.AccountVersion == o.Plan.AccountVersion()
}
