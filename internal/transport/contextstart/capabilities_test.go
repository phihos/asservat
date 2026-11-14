package contextstart

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/execution"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/targets"
)

// The connector's announcement names exactly the operations, queries and
// history work this package sends and answers (ADR-333).
func TestAnnouncedCapabilitiesMatchEveryMethod(t *testing.T) {
	want := []string{capabilityHistory}
	for _, m := range operationMethods {
		want = append(want, operationCapability(m))
	}
	for _, m := range queryMethods {
		want = append(want, queryCapability(m))
	}
	got := contracts.APIContextCapabilities()
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) || len(got) > contracts.MaxConnectorCapabilities {
		t.Fatalf("announcement differs from the methods\nwant %v\ngot  %v", want, got)
	}
}

func announcedWithout(missing string) contracts.ConnectorCapabilities {
	names := slices.DeleteFunc(contracts.APIContextCapabilities(), func(n string) bool { return n == missing })
	return contracts.NewConnectorCapabilities(names)
}

// A connector of an older release (another image digest, one operation
// missing from its announcement) still runs the work it supports over the
// real framed exchange; only the unannounced operation is refused, without
// sending it, as "connector too old".
func TestOlderConnectorRunsSupportedWorkAndRefusesMissingOperation(t *testing.T) {
	for _, mode := range []string{"current", "older"} {
		t.Run(mode, func(t *testing.T) {
			authenticated := workFixture()
			w := authenticated.Work
			// The executor runs another image than the hub's capability names.
			w.Channel.Executor.ImageDigest = artifact.Digest{0xee}
			w.Channel.Executor.StartupDigest = artifact.Digest{0xef}
			n := w.IssuedAt
			request := targets.Request{ClusterID: w.Target.ClusterID, Namespace: configuration.NamespaceRef{Name: "app", UID: w.Target.NamespaceUID}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "app", UID: w.Target.WorkloadUID}, PodName: "app-0", PodUID: w.Target.PodUID}
			pin := artifact.PinnedPod{Namespace: "app", NamespaceUID: w.Target.NamespaceUID, Name: request.PodName, UID: request.PodUID, ControllerUID: "rs"}
			source := targets.PacketSourceObservation{PodUID: pin.UID, NodeUID: "node", BootID: "boot", CollectorPodUID: "collector", CollectorEpoch: "epoch", ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
			e := argumentOperationExpectation(w.CaptureID, pin.UID, n)
			w.ExpectationDigest = evidence.ContextExpectationDigest(e)
			authenticated.Work = w
			permit := argumentOperationPermit(e, source, n)
			resolver := &argumentSourceResolver{result: targets.RecorderResolution{Target: targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: request, Pin: pin, PodResourceVersion: "1", WorkloadResourceVersion: "1", ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}, Recorder: targets.RecorderAnswer{Outcome: targets.RecorderAvailable, Source: &source}}}
			output := &argumentRecorderOutput{}
			local := &argumentStreamLocal{argumentSourceResolver: resolver, output: output}
			ports := resolver.countingLocal.local()
			ports.Targets, ports.Output = local, local
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			receiver := fleet.APIContextReceiver{Channel: w.Channel, Window: identity.Check(n, identity.Recheck).Narrow(w.NotAfter)}
			hub, region := historyStreamPair(t, ctx, receiver)
			hub.capabilities = contracts.NewConnectorCapabilities(contracts.APIContextCapabilities())
			if mode == "older" {
				hub.capabilities = announcedWithout(operationCapability(opStartArgumentRecording))
			}
			joined := make(chan error, 1)
			go func() {
				joined <- ServeRegionalOperations(ctx, region, receiver, streamDiagnosticVerifier(func(context.Context, []byte, fleet.APIContextReceiver) (fleet.AuthenticatedAPIContextWork, error) {
					return authenticated, nil
				}), ports, time.Now)
			}()
			var resolved, consumed bool
			state, err := ServeHubOperations(ctx, hub, w, []byte("synthetic-signed-work"), func(call context.Context, ops *HubOperations) (string, error) {
				r, err := ops.ResolveArgumentSource(call, request)
				if err != nil {
					return "Unavailable", err
				}
				resolved = r.ValidSource(time.Now())
				prepared, err := ops.PrepareContext(call, e)
				if err != nil {
					return "Unavailable", err
				}
				defer prepared.Close()
				d, err := startWindow{CommittedAt: n, ValidUntil: n.Add(3 * time.Second)}, call.Err()
				if err != nil {
					return "Unavailable", err
				}
				consumed = true
				if _, err = prepared.(evidence.ArgumentContextRecorder).StartArgumentRecording(call, pin, d.CommittedAt, d.ValidUntil, *r.Recorder.Source, permit); err != nil {
					return "Unavailable", err
				}
				return "Recording", nil
			}, time.Now)
			if !resolved || !consumed {
				t.Fatal("supported operations did not run", resolved, consumed, err)
			}
			if mode == "current" {
				if err != nil || state != "Recording" || output.argumentStarts != 1 {
					t.Fatal("current connector", state, err, output.argumentStarts)
				}
				return
			}
			var old *contracts.ConnectorTooOldError
			if !errors.As(err, &old) || old.Capability != "operation/start-argument-recording" || err.Error() != "connector too old for operation/start-argument-recording" || !errors.Is(err, value.ErrUnavailable) {
				t.Fatalf("refusal %v", err)
			}
			// Nothing was sent: the region never started, and the conversation
			// still ended with its finish, result and receipt.
			if state != "Unavailable" || output.argumentStarts != 0 {
				t.Fatal("older connector", state, output.argumentStarts)
			}
			if e := <-joined; e != nil {
				t.Fatal("region did not finish the conversation", e)
			}
		})
	}
}

// An unannounced pre-work query is answered by the hub itself before any
// I/O, leaving the standby usable; an announced one is asked as before.
func TestUnannouncedQueryIsRefusedWithoutIO(t *testing.T) {
	w := workFixture().Work
	receiver := fleet.APIContextReceiver{Channel: w.Channel, Window: identity.Check(w.IssuedAt, identity.Recheck).Narrow(w.NotAfter)}
	hub, _ := historyStreamPair(t, t.Context(), receiver)
	hub.capabilities = announcedWithout(queryCapability(queryReviewAccess))
	_, err := hub.query(t.Context(), queryReviewAccess, struct{}{}, nil)
	var answer errQueryAnswer
	var old *contracts.ConnectorTooOldError
	if !errors.As(err, &answer) || !errors.As(err, &old) || !errors.Is(err, targets.ErrUnsupported) || queryStep(err, nil) != "connector-too-old/query/review-access" {
		t.Fatalf("refusal %v", err)
	}
	if hub.frames != 0 || hub.querySeq != 0 || hub.closed {
		t.Fatal("refused query used the stream", hub.frames, hub.querySeq, hub.closed)
	}
}

func helloBody(t *testing.T, h contracts.APIContextHello) []byte {
	t.Helper()
	payload, e := contracts.EncodeAPIContextHello(h)
	if e != nil {
		t.Fatal(e)
	}
	var body bytes.Buffer
	if e = contracts.WriteAPIContextFrame(&body, contracts.APIContextFrame{Kind: contracts.APIContextHelloFrame, Payload: payload}); e != nil {
		t.Fatal(e)
	}
	return body.Bytes()
}

// The hub admits connectors of its protocol major regardless of image; an
// unversioned or other-major Hello is refused with HTTP 426 and a message
// naming the hub's protocol, and logged with a named stage. Real
// HTTP/2 over TLS 1.3, as the handler requires.
func TestHandlerChecksProtocolMajorOnly(t *testing.T) {
	router, e := NewRouter(RouterLimits{Standby: 1, Captures: 1})
	if e != nil {
		t.Fatal(e)
	}
	h, e := NewHandler("hub.example:9444", router, refusingIngress{}, 1)
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	var stages []string
	h.Refused = func(s string) { mu.Lock(); stages = append(stages, s); mu.Unlock() }
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	w := workFixture().Work
	for _, c := range []struct {
		name     string
		protocol int
		caps     []string
		stage    string
	}{
		{"unversioned", 0, nil, "connector-protocol"},
		{"next-major", contracts.ConnectorProtocolMajor + 1, contracts.APIContextCapabilities(), "connector-protocol"},
		// Same major, fewer capabilities (an older release): the Hello is
		// accepted and the exchange proceeds to its source frame.
		{"older-release", contracts.ConnectorProtocolMajor, []string{"history"}, "source"},
	} {
		t.Run(c.name, func(t *testing.T) {
			mu.Lock()
			stages = nil
			mu.Unlock()
			until := time.Now().Add(10 * time.Second).UTC().Truncate(time.Microsecond)
			body := helloBody(t, contracts.APIContextHello{Format: contracts.APIContextExchangeFormat, Channel: contracts.APIContextChannel{RootID: w.Channel.RootID, ExchangeID: w.Channel.ExchangeID}, StandbyUntil: until, Protocol: c.protocol, Capabilities: c.caps})
			reader, writer := io.Pipe()
			go func() { _, _ = writer.Write(body); _ = writer.Close() }()
			r, e := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+contracts.APIContextStartPath, reader)
			if e != nil {
				t.Fatal(e)
			}
			r.Host = "hub.example:9444"
			r.Header.Set("Content-Type", contracts.APIContextStartMedia)
			r.Header.Set("Accept", contracts.APIContextStartMedia)
			resp, e := srv.Client().Do(r)
			if e != nil {
				t.Fatal(e)
			}
			text, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			mu.Lock()
			defer mu.Unlock()
			want, wantBody := http.StatusNotFound, "Unavailable\n"
			if c.stage == "connector-protocol" {
				// A clear refusal naming the hub's protocol, not a bare 404.
				want, wantBody = http.StatusUpgradeRequired, ConnectorProtocolRefusal(c.protocol)
			}
			if resp.ProtoMajor != 2 || resp.StatusCode != want || string(text) != wantBody || len(stages) != 1 || stages[0] != c.stage {
				t.Fatalf("proto=%d status=%d body=%q stages=%v", resp.ProtoMajor, resp.StatusCode, text, stages)
			}
		})
	}
}

// A newer peer's unknown fields are ignored by this release's decoders.
func TestNewerPeerFieldsAreIgnored(t *testing.T) {
	op := []byte(`{"body":{},"format":"` + contracts.APIContextExchangeFormat + `","method":"finish","newField":{"x":1},"sequence":1}`)
	if v, e := contracts.DecodeAPIContextOperation(op); e != nil || v.Method != "finish" {
		t.Fatal("operation with a newer field", e)
	}
	var out struct{ Known int }
	if decodeOperationBody([]byte(`{"Known":1,"Added":true}`), &out) != nil || out.Known != 1 {
		t.Fatal("operation body with a newer field")
	}
}
