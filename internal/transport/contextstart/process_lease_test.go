package contextstart

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
)

// leaseLocal counts process reads.
type leaseLocal struct {
	countingLocal
	process value.APIProcessObservation
	reads   int
}

func (l *leaseLocal) ReadAPIProcess(context.Context) (value.APIProcessObservation, error) {
	l.reads++
	return l.process, nil
}

// ADR-173: one complete process observation serves every operation of one
// verified work until its original deadline, and is never renewed.
func TestRegionalSessionReusesOneProcessObservationPerWork(t *testing.T) {
	w := workFixture().Work
	now := time.Now().UTC().Truncate(time.Microsecond)
	clock := now
	id := func(n string) string { return "00000000-0000-4000-8000-0000000000" + n }
	process := value.APIProcessObservation{Binding: value.APIProcessBinding{InstallationID: id("01"), ClusterID: w.Target.ClusterID, IssuerEpoch: id("03"), NamespaceUID: id("13"), AccountUID: id("14"), PodUID: id("08"), ProcessEpoch: id("15"), StartupDigest: artifact.Digest{2}, ImageDigest: artifact.Digest{3}}, CheckedAt: now, ValidUntil: now.Add(5 * time.Second)}
	op := func(method string, body any) contracts.APIContextOperation {
		b, _ := json.Marshal(body)
		if body == nil {
			b = []byte(`{}`)
		}
		return contracts.APIContextOperation{Format: contracts.APIContextExchangeFormat, Sequence: 1, Method: method, Body: b}
	}
	{
		l := &leaseLocal{process: process}
		local := l.countingLocal.local()
		local.Process, local.Now = l, func() time.Time { return clock }
		clock = now
		s := &regionalSession{local: local, work: w}
		ctx := context.Background()
		for range 3 {
			out, err := s.handle(ctx, op(opReadProcess, nil))
			if err != nil || out.(value.APIProcessObservation) != process {
				t.Fatal("work observation not returned unchanged", err)
			}
		}
		if l.reads != 1 {
			t.Fatalf("process read %d times within one original interval", l.reads)
		}
		// After the original deadline the observation is never renewed: a new
		// complete read replaces it.
		clock = process.ValidUntil
		if _, err := s.handle(ctx, op(opReadProcess, nil)); err != nil || l.reads != 2 {
			t.Fatal("expired observation reused", l.reads, err)
		}
	}
}
