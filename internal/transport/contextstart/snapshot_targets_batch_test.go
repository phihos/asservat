package contextstart

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

func maximumSnapshotBatch(t *testing.T, count int) ([]targets.SourceSnapshotTarget, []targets.SourceSnapshotResolution) {
	t.Helper()
	requests, values := maximumOngoingBatch(count)
	originals := make([]targets.SourceSnapshotTarget, count)
	out := make([]targets.SourceSnapshotResolution, count)
	for i, value := range values {
		request := requests[i].Target
		request.Namespace.UID = strings.Repeat("n", 64)
		request.Workload.UID = strings.Repeat("w", 64)
		request.PodUID = strings.Repeat("p", 63) + string(rune('a'+i))
		pin := value.Recorder.Target.Pin
		pin.UID = request.PodUID
		pin.NamespaceUID = request.Namespace.UID
		pin.ControllerUID = strings.Repeat("c", 64)
		pin.NodeName = strings.Repeat("n", 253)
		process := *value.Recorder.Recorder.Source
		process.PodUID = request.PodUID
		original := targets.SourceSnapshotTarget{Request: request, Pin: pin, NodeUID: process.NodeUID, BootID: process.BootID, CollectorPodUID: process.CollectorPodUID, CollectorEpoch: process.CollectorEpoch, SourceID: requests[i].SourceID, Fence: requests[i].Fence}
		for j := range original.BindingDigest {
			original.BindingDigest[j] = 255
		}
		state := *value.State
		// Actual accepted policy observation bound (AutomationEnvelope.Valid).
		state.Credit = 1 << 40
		state.ObservedBytes = (1 << 40) - 1
		state.Stopped = true
		state.SourceStoppedAt = value.ReportedAt
		state.SnapshotUntil = value.ReportedAt.Add(20 * time.Second)
		originals[i] = original
		out[i] = targets.SourceSnapshotResolution{Original: original, Process: process, State: state, ReportedAt: value.ReportedAt, ReportFreshUntil: value.ReportFreshUntil, ObservedAt: process.ObservedAt, FreshUntil: process.FreshUntil}
		if !original.Valid() || !out[i].Valid(value.ReportedAt) {
			t.Fatal("maximum retained fixture invalid", i)
		}
	}
	return originals, out
}

func TestSnapshotBatchMaximumFitsActualOperationAndFrames(t *testing.T) {
	requests, replies := maximumSnapshotBatch(t, SourceSnapshotQueryBatchLimit)
	for name, value := range map[string]any{"request": requests, "reply": replies} {
		body, err := json.Marshal(value)
		if err != nil || len(body) > contracts.APIContextOperationBytes-1024 {
			t.Fatal(name, "oversized body", len(body), err)
		}
		var payload []byte
		kind := contracts.APIContextQueryFrame
		if name == "request" {
			payload, err = contracts.EncodeAPIContextOperation(contracts.APIContextOperation{Format: contracts.APIContextExchangeFormat, Sequence: 1, Method: queryResolveSourceSnapshots, Body: body})
		} else {
			kind = contracts.APIContextAnswerFrame
			payload, err = contracts.EncodeAPIContextOperationReply(contracts.APIContextOperationReply{Format: contracts.APIContextExchangeFormat, Sequence: 1, Method: queryResolveSourceSnapshots, Body: body})
		}
		if err != nil {
			t.Fatal(name, err)
		}
		var frame bytes.Buffer
		if err := contracts.WriteAPIContextFrame(&frame, contracts.APIContextFrame{Kind: kind, Payload: payload}); err != nil {
			t.Fatal(name, err)
		}
		framedBytes := frame.Len()
		decoded, err := contracts.ReadAPIContextFrame(&frame)
		if err != nil || decoded.Kind != kind || !bytes.Equal(decoded.Payload, payload) {
			t.Fatal("actual frame changed payload", err)
		}
		t.Logf("batch8 %s DTO=%d operation=%d frame=%d bytes", name, len(body), len(payload), framedBytes)
	}
}

func TestSnapshotBatchSixteenUsesTwoRealFramedRouterQueries(t *testing.T) {
	requests, replies := maximumSnapshotBatch(t, 16)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	count := 0
	f := newQueryLifecycleFixture(t, ctx, nil, func(reply contracts.APIContextOperationReply) contracts.APIContextFrame {
		if reply.Method != queryResolveSourceSnapshots {
			t.Error("wrong method", reply.Method)
		}
		start := count * SourceSnapshotQueryBatchLimit
		count++
		if start >= len(replies) {
			t.Error("too many queries")
			return contracts.APIContextFrame{}
		}
		body, _ := json.Marshal(replies[start:min(start+SourceSnapshotQueryBatchLimit, len(replies))])
		reply.Body = body
		return queryAnswerFrame(t, reply)
	})
	cluster := requests[0].Request.ClusterID
	router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{cluster, 1, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	standby, err := router.RegisterStandby(t.Context(), f.receiver, func(context.Context) (fleet.APIContextReceiver, error) { return f.receiver, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer standby.Finish()
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		for i := 0; i < 2; i++ {
			select {
			case job := <-standby.query:
				deadline, _ := job.ctx.Deadline()
				originalDeadline, _ := ctx.Deadline()
				if !deadline.Equal(originalDeadline) {
					t.Error("batch changed original caller deadline")
				}
				until, err := f.stream.query(job.ctx, job.method, job.in, job.out)
				job.result <- queryResult{until: until, err: err}
			case <-ctx.Done():
				return
			}
		}
	}()
	hub := Targets{Router: router, Now: func() time.Time { return replies[0].ObservedAt }}
	got, err := hub.ResolveSourceSnapshots(ctx, requests)
	<-joined
	if err != nil || len(got) != 16 || count != 2 || standby.queries != 2 || standby.queries >= contracts.APIContextMaximumQueries {
		t.Fatal("sixteen-member selection did not use two queries", len(got), count, err)
	}
	for index, value := range got {
		if value.Original != requests[index] || value.FreshUntil.After(f.receiver.ValidUntil) || !value.ReportedAt.Equal(replies[index].ReportedAt) {
			t.Fatal("changed target/freshness/report", index)
		}
	}
}

func TestSnapshotBatchRejectsPartialSwappedAndExpiredAnswers(t *testing.T) {
	for _, mode := range []string{"partial", "swapped", "missing", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			requests, replies := maximumSnapshotBatch(t, 2)
			now := replies[0].ObservedAt
			if mode == "partial" {
				replies = replies[:1]
			}
			if mode == "swapped" {
				replies[0], replies[1] = replies[1], replies[0]
			}
			if mode == "missing" {
				replies[1] = targets.SourceSnapshotResolution{}
			}
			work := workFixture()
			receiver := fleet.APIContextReceiver{Channel: work.Work.Channel, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{requests[0].Request.ClusterID, 1, 1}}})
			if err != nil {
				t.Fatal(err)
			}
			defer router.Close()
			standby, err := router.RegisterStandby(t.Context(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
			if err != nil {
				t.Fatal(err)
			}
			defer standby.Finish()
			hub := Targets{Router: router, Now: func() time.Time { return now }}
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				var job *queryJob
				select {
				case job = <-standby.query:
				case <-ctx.Done():
					return
				}
				*job.out.(*[]targets.SourceSnapshotResolution) = replies
				if mode == "deadline" {
					cancel()
				}
				job.result <- queryResult{until: receiver.ValidUntil}
			}()
			got, err := hub.ResolveSourceSnapshots(ctx, requests)
			<-joined
			if err == nil || len(got) != 0 {
				t.Fatal("partial selection escaped", mode, len(got), err)
			}
		})
	}
}

func TestSnapshotBatchAllowsSamePodDifferentSourcesAndRejectsMixedScope(t *testing.T) {
	requests, _ := maximumSnapshotBatch(t, 2)
	requests[1].Request = requests[0].Request
	requests[1].Pin = requests[0].Pin
	if !ValidSourceSnapshotBatch(requests, 8) {
		t.Fatal("different action sources on one Pod rejected")
	}
	requests[1].SourceID = requests[0].SourceID
	if ValidSourceSnapshotBatch(requests, 8) {
		t.Fatal("duplicate source accepted")
	}
	requests, _ = maximumSnapshotBatch(t, 2)
	requests[1].Request.Workload.UID = "other-workload"
	if ValidSourceSnapshotBatch(requests, 8) {
		t.Fatal("mixed workload accepted")
	}
}

func TestSnapshotBatchDoesNotRefreshEarlierChunkProof(t *testing.T) {
	requests, replies := maximumSnapshotBatch(t, 16)
	base := replies[0].ObservedAt
	now := base
	work := workFixture()
	receiver := fleet.APIContextReceiver{Channel: work.Work.Channel, ObservedAt: base, ValidUntil: base.Add(5 * time.Second)}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	router, err := NewRouter(RouterLimits{Standby: 1, Captures: 1, Clusters: []ClusterLimit{{requests[0].Request.ClusterID, 1, 1}}})
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	standby, err := router.RegisterStandby(t.Context(), receiver, func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer standby.Finish()
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		for index := 0; index < 2; index++ {
			var job *queryJob
			select {
			case job = <-standby.query:
			case <-ctx.Done():
				return
			}
			values := append([]targets.SourceSnapshotResolution(nil), replies[index*8:(index+1)*8]...)
			until := base.Add(time.Second)
			if index == 1 {
				now = base.Add(2 * time.Second)
				until = base.Add(4 * time.Second)
				for i := range values {
					values[i].ObservedAt = now
					values[i].Process.ObservedAt = now
				}
			}
			*job.out.(*[]targets.SourceSnapshotResolution) = values
			job.result <- queryResult{until: until}
		}
	}()
	hub := Targets{Router: router, Now: func() time.Time { return now }}
	got, err := hub.ResolveSourceSnapshots(ctx, requests)
	<-joined
	if err == nil || len(got) != 0 {
		t.Fatal("later chunk renewed expired earlier source observation", len(got), err)
	}
}
