package postgres

import (
	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	"asservat.local/asservat/internal/application/evidence"
	app "asservat.local/asservat/internal/application/execution"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/targets"
	"bytes"
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func argumentObservationRowFixture() custodydb.PolicyObservationSession {
	r := policyObservationRowFixture()
	r.AccountingRule = argumentRuleBytes()
	r.ArgumentDefinitionDigest = bytes.Repeat([]byte{3}, 32)
	r.DurationMillis = 60000
	r.SessionUntil = ts(r.StartedAt.Time.Add(70 * time.Second))
	r.LeaseUntil = r.SessionUntil
	r.StartBy = ts(r.StartedAt.Time.Add(10 * time.Second))
	r.EventCredit = 100
	r.MaxEventsPerSecond = 100
	r.MaxProbeBytes = 512
	r.MaxBytesPerEvent = 128
	r.MaxTrackedThreads = 4096
	r.BindingScope = argumentObservationScope(r)
	return r
}
func TestArgumentObservationPinsDistinctOriginalTuple(t *testing.T) {
	r := argumentObservationRowFixture()
	p, err := argumentObservationPermit(r)
	if err != nil || !p.ValidFinite(r.StartedAt.Time) {
		t.Fatal(p, err)
	}
	if _, err = policyObservationPermit(r); err == nil {
		t.Fatal("argument engine treated as packet cBPF")
	}
	for name, edit := range map[string]func(*custodydb.PolicyObservationSession){
		"definition": func(x *custodydb.PolicyObservationSession) { x.ArgumentDefinitionDigest = bytes.Repeat([]byte{9}, 32) },
		"events":     func(x *custodydb.PolicyObservationSession) { x.EventCredit++ }, "rate": func(x *custodydb.PolicyObservationSession) { x.MaxEventsPerSecond++ },
		"probe": func(x *custodydb.PolicyObservationSession) { x.MaxProbeBytes = 256 }, "event-width": func(x *custodydb.PolicyObservationSession) { x.MaxBytesPerEvent++ },
		"threads": func(x *custodydb.PolicyObservationSession) { x.MaxTrackedThreads++ }, "buffers": func(x *custodydb.PolicyObservationSession) { x.CaptureBuffers = true },
		"node": func(x *custodydb.PolicyObservationSession) { x.NodeUid = "replacement" }, "boot": func(x *custodydb.PolicyObservationSession) { x.BootID = "replacement" },
		"epoch": func(x *custodydb.PolicyObservationSession) { x.CollectorEpoch = "replacement" }, "fence": func(x *custodydb.PolicyObservationSession) { x.Fence = x.ID },
		"attempt": func(x *custodydb.PolicyObservationSession) { x.AttemptID = x.ID }, "lease": func(x *custodydb.PolicyObservationSession) { x.LeaseUntil.Time = x.LeaseUntil.Time.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			x := r
			edit(&x)
			if _, err := argumentObservationPermit(x); err == nil {
				t.Fatal("mutated original tuple accepted")
			}
		})
	}
	legacy := policyObservationRowFixture()
	legacy.EventCredit = 1
	if _, err := policyObservationPermit(legacy); err == nil {
		t.Fatal("new event field hidden behind legacy packet digest")
	}
	r.StartedAt.Time = r.StartedAt.Time.In(time.FixedZone("receiver", 3600))
	if got, err := argumentObservationPermit(r); err != nil || !got.StartedAt.Equal(p.StartedAt) {
		t.Fatal("instant-preserving SQL timezone", err)
	}
}
func TestArgumentHistoricalPublicationSourceDoesNotRenewPermit(t *testing.T) {
	r := argumentObservationRowFixture()
	e := artifact.ContextExpectation{CaptureUID: uid(r.CaptureID), ActionID: r.ActionID, PodUID: r.PodUid, Registration: artifact.Registration{Location: artifact.Location{AttemptID: uid(r.AttemptID)}}, Recording: &artifact.Recording{Kind: "syscallTrace", Profile: "arguments", Composition: []byte("{}"), DurationMillis: r.DurationMillis, MaxBytes: 65536, Syscalls: &artifact.RecordingSyscalls{Names: []string{"openat"}, MaxEvents: 100, MaxEventsPerSecond: r.MaxEventsPerSecond, MaxTrackedThreads: r.MaxTrackedThreads}, Arguments: &artifact.RecordingArguments{MaxProbeBytes: r.MaxProbeBytes, MaxBytesPerEvent: r.MaxBytesPerEvent, MaxBytesPerSecond: r.MaxBytesPerSecond}}}
	copy(e.Recording.Arguments.ProgramDigest[:], r.ProgramDigest)
	copy(e.Recording.Arguments.DefinitionDigest[:], r.ArgumentDefinitionDigest)
	copy(e.Recording.Arguments.AccountingRule[:], r.AccountingRule)
	d := evidence.ContextExpectationDigest(e)
	r.ExpectationDigest = d[:]
	r.BindingScope = argumentObservationScope(r)
	r.EndedAt = pgtype.Timestamptz{Time: r.SessionUntil.Time, Valid: true}
	p, err := argumentSourceProvenance(r, e)
	if err != nil || p.NodeUID != r.NodeUid || p.BootID != r.BootID || p.CollectorEpoch != r.CollectorEpoch || p.SessionID != uid(r.ID) || p.Fence != uid(r.Fence) || !p.Until.Equal(r.SessionUntil.Time) {
		t.Fatal(p, err)
	}
	if _, err = argumentObservationPermit(r); err == nil {
		t.Fatal("ended historical provenance became active permit")
	}
	e.Recording.Arguments.MaxBytesPerEvent++
	if _, err = argumentSourceProvenance(r, e); err == nil {
		t.Fatal("different accepted expected receipt admitted")
	}
}

func TestArgumentCannotUseOrdinaryOrPacketPreparation(t *testing.T) {
	r := &artifact.Recording{Kind: "syscallTrace", Profile: "arguments"}
	if !policyRecordingNeedsGrant(r) {
		t.Fatal("argument observation lost independent grant requirement")
	}
	var c app.APIExecutionCheck
	c.Work.Accepted.Expectation.Recording = r
	s := &APIContextExecutions{}
	if _, first, err := s.PrepareAPIExecution(context.Background(), c); !errors.Is(err, value.ErrDenied) || first {
		t.Fatal("ordinary preparation bypass", first, err)
	}
	if _, first, _, err := s.PreparePolicyRecording(context.Background(), c, targets.PacketSourceObservation{}); !errors.Is(err, value.ErrDenied) || first {
		t.Fatal("packet permit used for arguments", first, err)
	}
	c.Work.Accepted.Expectation.Recording = &artifact.Recording{Kind: "packetCapture", Profile: "rawPackets"}
	if _, first, _, err := s.PrepareArgumentRecording(context.Background(), c, targets.PacketSourceObservation{}); !errors.Is(err, value.ErrDenied) || first {
		t.Fatal("argument permit used for packet", first, err)
	}
}
