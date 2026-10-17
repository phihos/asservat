package audit

import (
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
)

func TestDownloadAuditEqualitySurvivesPersistence(t *testing.T) {
	// Equality compares historical records; validity/current authority remain
	// separately enforced by the consumer. Include every nested timestamp so
	// adding processing provenance cannot break a persisted acknowledgement.
	now := time.Now()
	i := DownloadIntent{SessionID: "original-session", Batch: artifact.DownloadBatch{ID: "original-batch", Generation: 1, StartedAt: now, LeaseUntil: now.Add(time.Second)}}
	a := &i.Batch.Authority
	a.CheckedAt, a.ValidUntil, a.AccessUntil, a.DeleteBy = now, now.Add(time.Second), now.Add(time.Hour), now.Add(2*time.Hour)
	a.Retention.ObservedAt, a.Retention.ValidUntil = now, now.Add(time.Second)
	a.Environment.ObservedAt, a.Environment.ValidUntil = now, now.Add(time.Second)
	a.Environment.Processing.ObservedAt, a.Environment.Processing.ValidUntil = now, now.Add(time.Second)
	a.Environment.Processing.Sequence = 3
	r := DownloadOutcome{Intent: i, RecordedAt: now.Add(time.Second), EmittedBytes: 17, Success: true}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var persisted DownloadOutcome
	if err = json.Unmarshal(encoded, &persisted); err != nil {
		t.Fatal(err)
	}
	if !r.Intent.Equal(persisted.Intent) || !r.Equal(persisted) {
		t.Fatal("persistence changed equality of the original audit record")
	}
	persisted.RecordedAt = r.RecordedAt.In(time.FixedZone("other", 7200))
	persisted.Intent.Batch.Authority.Environment.Processing.ObservedAt = now.In(time.FixedZone("another", -18000))
	if !r.Equal(persisted) {
		t.Fatal("timezone representation changed original audit identity")
	}
	for name, mutate := range map[string]func(*DownloadOutcome){
		"session":             func(v *DownloadOutcome) { v.Intent.SessionID += "-different" },
		"generation":          func(v *DownloadOutcome) { v.Intent.Batch.Generation++ },
		"processing sequence": func(v *DownloadOutcome) { v.Intent.Batch.Authority.Environment.Processing.Sequence++ },
		"processing deadline": func(v *DownloadOutcome) {
			v.Intent.Batch.Authority.Environment.Processing.ValidUntil = v.Intent.Batch.Authority.Environment.Processing.ValidUntil.Add(time.Nanosecond)
		},
		"retention deadline": func(v *DownloadOutcome) {
			v.Intent.Batch.Authority.Retention.ValidUntil = v.Intent.Batch.Authority.Retention.ValidUntil.Add(time.Nanosecond)
		},
		"lease":         func(v *DownloadOutcome) { v.Intent.Batch.LeaseUntil = v.Intent.Batch.LeaseUntil.Add(time.Nanosecond) },
		"recorded time": func(v *DownloadOutcome) { v.RecordedAt = v.RecordedAt.Add(time.Nanosecond) },
		"emitted bytes": func(v *DownloadOutcome) { v.EmittedBytes++ },
		"success":       func(v *DownloadOutcome) { v.Success = false },
	} {
		t.Run(name, func(t *testing.T) {
			changed := persisted
			mutate(&changed)
			if r.Equal(changed) {
				t.Fatal("changed audit record compared equal")
			}
		})
	}
}
