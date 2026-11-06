package contextstart

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/targets"
)

type processStreamOutput struct {
	fakeRecorderOutput
	pin              artifact.PinnedPod
	startedAt, until time.Time
}

func (o *processStreamOutput) StartProcesses(_ context.Context, pin artifact.PinnedPod, started, until time.Time) (time.Time, error) {
	o.started++
	o.pin, o.startedAt, o.until = pin, started, until
	return started, o.err
}

type processStreamLocal struct {
	countingLocal
	out       *processStreamOutput
	resolved  targets.PodResolution
	committed value.Disposition
}

func (l *processStreamLocal) PrepareContext(context.Context, artifact.ContextExpectation) (evidence.PreparedContext, error) {
	return l.out, nil
}
func (l *processStreamLocal) ResolvePod(context.Context, targets.Request) (targets.PodResolution, error) {
	return l.resolved, nil
}
func (l *processStreamLocal) ConsumeStart(context.Context, value.Request) (value.Disposition, error) {
	return l.committed, nil
}

func TestProcessesStartRequiresExactCommittedExpectation(t *testing.T) {
	n := time.Now().UTC().Truncate(time.Microsecond)
	w := workFixture().Work
	pin := artifact.PinnedPod{Namespace: "app", NamespaceUID: w.Target.NamespaceUID, Name: "web", UID: w.Target.PodUID}
	for _, mode := range []string{"valid", "missing-start", "not-committed", "renewed-start", "renewed-until", "foreign-pin", "missing-expectation", "expired", "failed-dispatch"} {
		t.Run(mode, func(t *testing.T) {
			out := &processStreamOutput{}
			s := &regionalSession{local: (&countingLocal{}).local(), work: w, prepared: out, resolved: &targets.PodResolution{Pin: pin}, expectation: &artifact.ContextExpectation{Processes: &artifact.ProcessCapture{}}, consumed: &value.Disposition{MayStart: true, Phase: value.StartCommitted, CommittedAt: n, ValidUntil: n.Add(time.Second)}}
			r := acquireRequest{Pin: pin, Started: n, Until: n.Add(time.Second)}
			switch mode {
			case "missing-start":
				s.consumed = nil
			case "not-committed":
				s.consumed.MayStart = false
			case "renewed-start":
				r.Started = n.Add(time.Microsecond)
			case "renewed-until":
				r.Until = r.Until.Add(time.Microsecond)
			case "foreign-pin":
				r.Pin.UID = "other"
			case "missing-expectation":
				s.expectation.Processes = nil
			case "expired":
				r.Until = n.Add(-time.Second)
			case "failed-dispatch":
				out.err = value.ErrUnavailable
			}
			b, _ := json.Marshal(r)
			op := contracts.APIContextOperation{Format: contracts.APIContextExchangeFormat, Sequence: 1, Method: "start-processes", Body: b}
			reply, err := s.handle(t.Context(), op)
			if mode == "valid" {
				if err != nil || out.started != 1 || !reply.(recordingReply).Queued.Equal(n) || out.pin != pin || !out.until.Equal(r.Until) {
					t.Fatal("exact process start", reply, err, out.started)
				}
			} else if mode == "failed-dispatch" {
				if !errors.Is(err, value.ErrUnavailable) || out.started != 1 {
					t.Fatal("failed dispatch", err, out.started)
				}
			} else if !errors.Is(err, value.ErrDenied) || out.started != 0 {
				t.Fatal("invalid process start", err, out.started)
			}
			if s.acquired {
				if _, err := s.handle(t.Context(), op); !errors.Is(err, value.ErrDenied) || out.started != 1 {
					t.Fatal("process dispatch repeated after known or unknown result", err, out.started)
				}
			}
		})
	}
}

// Exercise the actual remote prepared output and regional operation receiver
// over TLS1.3 HTTP/2. Work verification, start authority and the final recorder
// are synthetic; this establishes transport composition, not native acquisition.
func TestProcessesRemoteOutputStartsOverHTTP2(t *testing.T) {
	authenticated := workFixture()
	w, n := authenticated.Work, authenticated.Work.IssuedAt
	pin := artifact.PinnedPod{Namespace: "app", NamespaceUID: w.Target.NamespaceUID, Name: "web", UID: w.Target.PodUID, ControllerUID: "replicaset"}
	e := artifact.ContextExpectation{CaptureUID: w.CaptureID, PodUID: pin.UID, Processes: &artifact.ProcessCapture{}}
	w.ExpectationDigest = evidence.ContextExpectationDigest(e)
	authenticated.Work = w
	request := targets.Request{ClusterID: w.Target.ClusterID, PodName: pin.Name, PodUID: pin.UID}
	request.Namespace.Name, request.Namespace.UID = pin.Namespace, pin.NamespaceUID
	request.Workload.Kind, request.Workload.Name, request.Workload.UID = "Deployment", "app", w.Target.WorkloadUID
	out := &processStreamOutput{}
	l := &processStreamLocal{out: out, resolved: targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: request, Pin: pin, PodResourceVersion: "1", WorkloadResourceVersion: "1", ObservedAt: n, FreshUntil: w.NotAfter}, committed: value.Disposition{MayStart: true, Phase: value.StartCommitted, CommittedAt: n, ValidUntil: n.Add(3 * time.Second)}}
	if !request.Valid() || !l.resolved.Valid(n) || l.resolved.Target() != w.Target {
		t.Fatal("invalid synthetic target")
	}
	ports := l.countingLocal.local()
	ports.Output, ports.Targets, ports.Starts = l, l, l
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	receiver := fleet.APIContextReceiver{Channel: w.Channel, ObservedAt: n, ValidUntil: w.NotAfter}
	check := func(context.Context) (fleet.APIContextReceiver, error) { return receiver, nil }
	joined := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(wr http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.TLS.Version != tls.VersionTLS13 {
			joined <- errors.New("not TLS1.3 HTTP/2")
			return
		}
		controller := http.NewResponseController(wr)
		region, err := newFrameStream(r.Context(), receiver.Channel, check, r.Body, wr, controller.SetReadDeadline, controller.SetWriteDeadline, controller.Flush, func() { _ = controller.SetReadDeadline(time.Now()); _ = r.Body.Close() })
		if err != nil {
			joined <- err
			return
		}
		defer region.Close()
		wr.WriteHeader(http.StatusOK)
		if err = controller.Flush(); err != nil {
			joined <- err
			return
		}
		joined <- ServeRegionalOperations(ctx, region, receiver, streamDiagnosticVerifier(func(context.Context, []byte, fleet.APIContextReceiver) (fleet.AuthenticatedAPIContextWork, error) {
			return authenticated, nil
		}), ports, time.Now)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	read, write := io.Pipe()
	defer read.Close()
	defer write.Close()
	var connection net.Conn
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { connection = info.Conn }}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost, server.URL, read)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	hub, err := newFrameStream(ctx, receiver.Channel, check, response.Body, write, connection.SetReadDeadline, connection.SetWriteDeadline, func() error { return nil }, func() { _ = write.Close(); _ = connection.Close(); _ = response.Body.Close() })
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	state, err := ServeHubOperations(ctx, hub, w, []byte("synthetic-signed-work"), func(call context.Context, ops *HubOperations) (string, error) {
		if _, err := ops.ResolvePod(call, request); err != nil {
			return "Unavailable", err
		}
		prepared, err := ops.PrepareContext(call, e)
		if err != nil {
			return "Unavailable", err
		}
		defer prepared.Close()
		recorder, ok := prepared.(evidence.ProcessesRecorder)
		if !ok {
			return "Unavailable", errors.New("actual remote output lacks ProcessesRecorder")
		}
		d, err := ops.ConsumeStart(call, value.Request{Binding: value.Binding{CaptureID: w.CaptureID, AttemptID: w.AttemptID, ClusterID: w.Target.ClusterID, PodUID: w.Target.PodUID, ScopeDigest: w.ScopeDigest}})
		if err != nil {
			return "Unavailable", err
		}
		queued, err := recorder.StartProcesses(call, pin, d.CommittedAt, d.ValidUntil)
		if err != nil {
			return "Unavailable", err
		}
		if !queued.Equal(n) {
			return "Unavailable", errors.New("original queued time changed")
		}
		return "Recording", nil
	}, time.Now)
	if err != nil || state != "Recording" {
		t.Fatal("real remote process start", state, err)
	}
	select {
	case err := <-joined:
		if err != nil {
			t.Fatal("regional join", err)
		}
	case <-ctx.Done():
		t.Fatal("regional join", ctx.Err())
	}
	if out.started != 1 || out.pin != pin || !out.startedAt.Equal(n) || !out.until.Equal(l.committed.ValidUntil) || l.calls != 0 {
		t.Fatal("process start changed, repeated or fell back", out.started, l.calls)
	}
}
