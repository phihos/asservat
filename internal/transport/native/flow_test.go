package native_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/transport/browser"
	native "asservat.local/asservat/internal/transport/native"
)

// Real h2/mTLS transport and final HTTPS sink; only source/SQL/human authority
// are synthetic. This deliberately does not stand in for the SQL/S3 fixture.
type flowSource struct{ reads atomic.Int32 }

var flowBody = []byte(`{"format":"synthetic-pod-status","phase":"Running"}`)

func (s *flowSource) ReadNativeContext(ctx context.Context, _ evidence.NativeContextSource, _ value.NativeOperation, _ string, _ time.Time) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	s.reads.Add(1)
	return append([]byte(nil), flowBody...), nil
}
func flowSourceValue(t *testing.T) evidence.NativeContextSource {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := nativeID
	e := artifact.ContextExpectation{ExecutionClass: artifact.ContextAPIExecution, Registration: artifact.Registration{Location: artifact.Location{ClusterID: id, ArtifactID: id, AttemptID: id}, StoreID: id, AllocationID: id, PoolRevision: 1, AllocationRevision: 1, NativeLimit: 4096, AnchorAt: now, WriteUntil: now.Add(30 * time.Second), ExpiresAt: now.Add(time.Minute), DeleteBy: now.Add(90 * time.Second)}, CaseID: id, OccurrenceID: id, PodUID: id, Namespace: "app", NamespaceUID: id, WorkloadUID: id, CollectorVersion: "synthetic", CollectorImageDigest: artifact.Digest{1}, RecipeDigest: artifact.Digest{2}, PlanDigest: artifact.Digest{3}, CaptureUID: id, ActionID: "pod-status", DataClass: "metadata", PurposeRef: "synthetic", Audience: []artifact.AudienceAssignment{{Kind: "Group", Issuer: "https://id.invalid", SubjectID: "team", Role: "workload-maintainer", BasisKind: "AccessBinding", BasisUID: id, AssignmentID: id, BasisDigest: artifact.Digest{4}}}, RequestedAgeSeconds: 60, MaximumAgeSeconds: 300, DeletionBudgetSeconds: 30, RetentionRules: []artifact.RetentionRule{{UID: id, Generation: 1, Digest: artifact.Digest{5}}}, TriggeredAt: now}
	s := evidence.NativeContextSource{Expectation: e}
	for i := range s.Copies {
		s.Copies[i] = artifact.CopyReceipt{ETag: "synthetic", Bytes: 128, SHA256: artifact.Digest{byte(i + 1)}}
	}
	if !s.Valid(evidence.ContextCopiesDigest(s.Copies)) {
		t.Fatal("invalid source")
	}
	return s
}

type flowConversation struct {
	native.Conversation
	label string
	t     *testing.T
}

func (c flowConversation) Serve(ctx context.Context, s native.Stream) error {
	err := c.Conversation.Serve(ctx, s)
	c.t.Log(c.label, "serve terminal", err)
	return err
}

type flowAdmission struct {
	t            *testing.T
	owner        context.Context
	operation    *native.HubOperation
	lease        value.NativeLease
	upstream     *mtls.NativeClient
	calls        atomic.Int32
	check        func(context.Context) (value.NativeLease, error)
	wrap         func(native.Stream) native.Stream
	observedGate func(*evidence.NativeFrameGate)
}

func (a *flowAdmission) OpenNative(ctx context.Context, peer *tls.ConnectionState, h contracts.NativeHello) (native.Conversation, error) {
	a.calls.Add(1)
	if peer == nil || !peer.HandshakeComplete || len(peer.VerifiedChains) == 0 || len(peer.PeerCertificates) != 1 {
		return nil, contracts.ErrNativeProtocol
	}
	if a.upstream == nil {
		c, e := a.operation.Attach(ctx, h)
		if e != nil {
			return nil, e
		}
		return flowConversation{c, "hub", a.t}, nil
	}
	h.Reference = contracts.NativeReference{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, OperationID: a.lease.Operation.Reference.OperationID, Fence: a.lease.Operation.Reference.Fence}
	h.WorkerLeaf = append([]byte(nil), peer.PeerCertificates[0].Raw...)
	stream, e := a.upstream.Open(a.owner, h)
	if e != nil {
		return nil, e
	}
	check := a.check
	if check == nil {
		check = func(context.Context) (value.NativeLease, error) { return a.lease, nil }
	}
	gate, e := evidence.NewNativeFrameGate(a.owner, check, time.Now)
	if e != nil {
		stream.Close()
		return nil, e
	}
	if a.observedGate != nil {
		a.observedGate(gate)
	}
	var wrapped native.Stream = stream
	if a.wrap != nil {
		wrapped = a.wrap(stream)
	}
	c, e := native.NewRelayConversation(gate, wrapped)
	if e != nil {
		return nil, e
	}
	return flowConversation{c, "connector", a.t}, nil
}
func flowServer(t *testing.T, path string, a native.Admission) *mtls.NativeClient {
	return flowServerReporting(t, path, a, nil)
}
func flowServerReporting(t *testing.T, path string, a native.Admission, refused func(context.Context, string, error)) *mtls.NativeClient {
	server, client, roots := testCertificates(t)
	var handler http.Handler
	var handlers sync.WaitGroup
	var admission sync.Mutex
	closing := false
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admission.Lock()
		if closing {
			admission.Unlock()
			return
		}
		handlers.Add(1)
		admission.Unlock()
		defer handlers.Done()
		handler.ServeHTTP(w, r)
	}))
	s.EnableHTTP2 = true
	s.TLS = &tls.Config{Certificates: []tls.Certificate{server}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS13}
	s.StartTLS()
	t.Cleanup(func() {
		admission.Lock()
		closing = true
		admission.Unlock()
		s.Close()
		handlers.Wait()
	})
	u, _ := url.Parse(s.URL)
	var e error
	h, e := native.NewHandler(path, u.Host, a, 1)
	if e != nil {
		t.Fatal(e)
	}
	h.Refused = refused
	handler = h
	c, e := mtls.NewNativeClient(s.URL+path, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{client}})
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func flowOperation(t *testing.T, ctx context.Context, source evidence.NativeContextSource, kind value.NativeOperationKind, fence int64, delivery artifact.DownloadDeliveryLease) (*native.HubOperation, *mtls.NativeClient, value.NativeOperation) {
	return flowOperationWithConnector(t, ctx, source, kind, fence, delivery, nil)
}
func flowOperationWithConnector(t *testing.T, ctx context.Context, source evidence.NativeContextSource, kind value.NativeOperationKind, fence int64, delivery artifact.DownloadDeliveryLease, construct func(*flowAdmission) native.Admission, observations ...func(value.NativeLease) value.NativeLease) (*native.HubOperation, *mtls.NativeClient, value.NativeOperation) {
	now := time.Now()
	until := now.Add(4 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(until) {
		until = d
	}
	o := value.NativeOperation{Reference: value.NativeReference{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, OperationID: nativeID, Fence: fence}, Kind: kind, HubPodUID: nativeID, HubProcessEpoch: nativeID, WorkerPodUID: nativeID, WorkerPublicKey: artifact.Digest{1}, SourceVersion: evidence.ContextCopiesDigest(source.Copies), ParentID: nativeID, Generation: 1, StartedAt: now, Until: until}
	if kind == value.NativeResponse {
		until = delivery.Until
		o.Until = until
		if len(observations) > 0 {
			o.Until = now.Add(identity.EvidenceReadRequestWindow)
		}
	}
	o = syntheticProcessingPath(o)
	o.Processing.Location = source.Expectation.Registration.Location
	o.Path.TargetClusterID = o.Processing.Location.ClusterID
	o.Path.StoreID = source.Expectation.Registration.StoreID
	l := value.NativeLease{Operation: o, Certificate: artifact.Digest{3}, Sequence: 1, ObservedAt: now, Until: until}
	check := func(context.Context) (value.NativeLease, error) {
		if len(observations) > 0 {
			return observations[0](l), nil
		}
		return l, nil
	}
	gate, e := evidence.NewNativeFrameGate(ctx, check, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(source)
	if kind == value.NativeObserve {
		b = []byte("null")
	}
	wire, _ := json.Marshal(o)
	command := contracts.NativeCommand{Format: contracts.NativeExchangeFormat, Reference: contracts.NativeReference{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, OperationID: nativeID, Fence: fence}, Kind: string(kind), Source: b, Operation: wire, ParentID: nativeID, Generation: 1, LeaseSequence: 1, Until: until.UTC().Format(time.RFC3339Nano)}
	var operation *native.HubOperation
	if kind == value.NativeResponse {
		if len(observations) > 0 {
			command.Until = o.Until.UTC().Format(time.RFC3339Nano)
		}
		command.WindowID = delivery.WindowID
		command.Offset = delivery.Offset
		command.Length = delivery.Length
		operation, e = native.NewHubResponseOperation(gate, command, source, delivery, syntheticNativeCompletion)
	} else {
		operation, e = native.NewHubOperation(gate, command, source, syntheticNativeCompletion)
	}
	if e != nil {
		t.Fatal("operation", e)
	}
	t.Cleanup(func() { operation.Close() })
	hub := &flowAdmission{t: t, owner: ctx, operation: operation, lease: l}
	upstream := flowServer(t, contracts.NativeOwnerPath, hub)
	connector := &flowAdmission{t: t, owner: ctx, lease: l, upstream: upstream, check: check}
	var admission native.Admission = connector
	if construct != nil {
		admission = construct(connector)
	}
	client := flowServer(t, contracts.NativeWorkerPath, admission)
	return operation, client, o
}
func flowRunWorker(t *testing.T, ctx context.Context, client *mtls.NativeClient, target value.WorkerCredentialTarget, result *evidence.RegionalContextResult) <-chan error {
	t.Helper()
	s, e := client.Open(ctx, workerHello())
	if e != nil {
		t.Fatal("worker stream", e)
	}
	done := make(chan error, 1)
	go func() { done <- native.RunWorker(ctx, s, workerHello(), target, artifact.Digest{1}, result) }()
	return done
}
func TestNativeTwoHopPreparationObservationAndFinalHTTPSink(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	source := flowSourceValue(t)
	now := time.Now()
	target := value.WorkerCredentialTarget{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, PodUID: nativeID, CreatedAt: now, RunUntil: now.Add(time.Minute)}
	reader := &flowSource{}
	result, e := evidence.NewRegionalContextResult(ctx, target, reader, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { result.Close(); result.Wait(context.Background()) }()
	preparation, client, _ := flowOperation(t, ctx, source, value.NativePrepare, 1, artifact.DownloadDeliveryLease{})
	done := flowRunWorker(t, ctx, client, target, result)
	m, e := preparation.Prepared(ctx)
	if e != nil {
		select {
		case workerErr := <-done:
			t.Fatal("prepare", e, "worker", workerErr)
		default:
			t.Fatal("prepare", e)
		}
	}
	if m.SHA256 != sha256.Sum256(flowBody) {
		t.Fatal("native checksum changed")
	}
	if e = preparation.Commit(ctx); e != nil {
		t.Fatal("commit", e)
	}
	if e = <-done; e != nil {
		t.Fatal("worker prepare", e)
	}
	preparation.Close()
	observation, client, _ := flowOperation(t, ctx, source, value.NativeObserve, 2, artifact.DownloadDeliveryLease{})
	done = flowRunWorker(t, ctx, client, target, result)
	// Delay the hub consumer deliberately. A completed metadata conversation
	// must not close its current gate before the original caller receives it.
	select {
	case err := <-done:
		t.Fatal("observation closed before metadata consumer joined", err)
	case <-time.After(100 * time.Millisecond):
	}
	got, e := observation.Prepared(ctx)
	if e != nil || got != m {
		t.Fatal("observe", e)
	}
	if e = <-done; e != nil {
		t.Fatal("worker observe", e)
	}
	observation.Close()
	if reader.reads.Load() != 1 {
		t.Fatal("metadata observation decrypted again")
	}
	now = time.Now()
	a := artifact.DownloadAuthority{Scope: artifact.DownloadScope{RootID: nativeID, ArtifactID: nativeID, CaptureID: nativeID, ClusterID: nativeID, NamespaceUID: nativeID, WorkloadUID: nativeID, PodUID: nativeID, Version: evidence.ContextCopiesDigest(source.Copies), Principal: identity.Principal{Issuer: "https://id.invalid", Subject: "dev", ClientID: "browser", Kind: identity.Human}}, PermissionEpoch: nativeID, PermissionSequence: 1, ProjectionDigest: artifact.Digest{1}, DecisionDigest: artifact.Digest{2}, IdentityRevision: identity.Revision{UID: "policy", Generation: 1, Digest: [32]byte{3}}, CheckedAt: now, ValidUntil: now.Add(4 * time.Second), AccessUntil: source.Expectation.Registration.ExpiresAt, DeleteBy: source.Expectation.Registration.DeleteBy}
	lease := artifact.DownloadDeliveryLease{ResponseID: nativeID, WindowID: nativeID, OwnerID: nativeID, Generation: 1, Sequence: 1, Length: m.Size, StartedAt: now, Until: a.ValidUntil, Authority: a}
	response, client, _ := flowOperation(t, ctx, source, value.NativeResponse, 3, lease)
	done = flowRunWorker(t, ctx, client, target, result)
	outcome := make(chan error, 1)
	httpServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		work, stop := context.WithDeadline(r.Context(), lease.Until)
		defer stop()
		chunk, e := response.ReadChunk(work, lease, 0, m.Size)
		if e != nil {
			outcome <- e
			return
		}
		defer clear(chunk.Bytes)
		plan := artifact.DownloadResponse{ID: nativeID, SessionID: nativeID, OwnerID: nativeID, Generation: 1, Plan: artifact.DownloadResponsePlan{Version: 1, Selection: artifact.DownloadSelection{Length: m.Size}, WholeFile: true, WindowReadLimit: evidence.ContextDownloadReadWork}, StartedAt: now, Until: target.RunUntil}
		sink, e := browser.NewHTTPDownloadResponse(w, r, m, plan)
		if e != nil {
			outcome <- e
			return
		}
		defer sink.Close()
		n, e := sink.WriteChunk(work, lease, 0, chunk.Bytes)
		if e == nil && n == m.Size {
			e = response.AcknowledgeNativeChunk(work, lease, 0, n)
		}
		if e == nil {
			e = sink.Finish(work)
		}
		outcome <- e
	}))
	defer httpServer.Close()
	httpReply, e := httpServer.Client().Get(httpServer.URL)
	if e != nil {
		t.Fatal(e)
	}
	body, e := io.ReadAll(httpReply.Body)
	httpReply.Body.Close()
	if e != nil || string(body) != string(flowBody) {
		t.Fatal("final native body", string(body), e)
	}
	if e = <-outcome; e != nil {
		t.Fatal("sink", e)
	}
	if e = <-done; e != nil {
		t.Fatal("worker content", e)
	}
	response.Close()
	if reader.reads.Load() != 2 {
		t.Fatal("incorrect preparation/content reads")
	}
}

// Installed native89: a download preparation conversation ran a complete
// current check (owner serving route, worker, operation) around every frame
// and failed one under load. Its frame checks now share one complete check for
// NativeRecheckInterval like an approved projection's.
func TestNativeDownloadPreparationSharesFrameChecksWithinInterval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	source := flowSourceValue(t)
	now := time.Now()
	target := value.WorkerCredentialTarget{InstallationID: nativeID, SessionID: nativeID, WorkerID: nativeID, PodUID: nativeID, CreatedAt: now, RunUntil: now.Add(time.Minute)}
	result, e := evidence.NewRegionalContextResult(ctx, target, &flowSource{}, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { result.Close(); result.Wait(context.Background()) }()
	var checks atomic.Int32
	prep, client, _ := flowOperationWithConnector(t, ctx, source, value.NativePrepare, 1, artifact.DownloadDeliveryLease{}, func(a *flowAdmission) native.Admission {
		a.check = func(c context.Context) (value.NativeLease, error) {
			checks.Add(1)
			select {
			case <-time.After(250 * time.Millisecond): // one installed complete check
			case <-c.Done():
				return value.NativeLease{}, c.Err()
			}
			return a.lease, nil
		}
		return a
	})
	started := time.Now()
	done := flowRunWorker(t, ctx, client, target, result)
	if _, e = prep.Prepared(ctx); e != nil {
		t.Fatal(e)
	}
	if e = prep.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal("preparation did not complete", e)
	}
	// With a complete check at every frame this preparation outlived its
	// four-second operation; with shared frame checks it completes (13
	// complete checks here, most in the connector relay's own path).
	t.Logf("connector complete checks=%d elapsed=%s", checks.Load(), time.Since(started))
}
