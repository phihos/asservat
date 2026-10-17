package mtls

import (
	"context"
	"crypto/tls"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// Actual process-owned keys and mutual TLS/h2 exporter; native source and SQL
// registration contents are explicit synthetic component fixtures. These tests
// do not qualify native APIs, the complete stream or installed availability.
type connectorOperationNativeFixture struct {
	f                            *connectorPairFixture
	pin                          value.ConnectorObservationPin
	opens, reads, finals, closes atomic.Int32
	openHook                     func(context.Context)
	readHook                     func(context.Context, int, *value.ConnectorObservationNativeValue) error
}
type connectorOperationNativeHandle struct {
	f            *connectorOperationNativeFixture
	root         context.Context
	cancel       context.CancelFunc
	request      value.OwnerObservationRequest
	process      value.ConnectorProcessIdentity
	start, until time.Time
	once         sync.Once
}

func (f *connectorOperationNativeFixture) OpenConnectorObservationOperation(ctx context.Context, r value.OwnerObservationRequest, p value.ConnectorProcessIdentity) (app.ConnectorNativeObservationOperation, error) {
	f.opens.Add(1)
	root, cancel := context.WithCancel(ctx)
	end, _ := ctx.Deadline()
	o := &connectorOperationNativeHandle{f, root, cancel, r, p, f.f.clock(), identity.Earlier(end, r.NotAfter), sync.Once{}}
	if f.openHook != nil {
		f.openHook(ctx)
	}
	return o, nil
}
func (o *connectorOperationNativeHandle) Close() { o.once.Do(func() { o.f.closes.Add(1); o.cancel() }) }
func (o *connectorOperationNativeHandle) Read(ctx context.Context, n int) (value.ConnectorObservationNativeValue, error) {
	o.f.reads.Add(1)
	if n == 4 {
		o.f.finals.Add(1)
	}
	if o.root.Err() != nil {
		return value.ConnectorObservationNativeValue{}, value.ErrUnavailable
	}
	source, _ := o.f.f.ReadConnectorIdentitySource(ctx)
	end, _ := ctx.Deadline()
	o.until = identity.Earlier(o.until, end)
	source.Observation.FreshUntil = o.until
	w := value.ConnectorObservationWorkload{Process: o.process, Pod: "connector-1", ReplicaSetUID: ownerTestID, TemplateDigest: o.f.pin.TemplateDigest, ImageDigest: o.f.pin.ImageDigest, ProtectionDigest: o.f.pin.ProtectionDigest, WorkloadDigest: artifact.Digest{16}, ObservedAt: o.start, FreshUntil: o.until}
	v := value.ConnectorObservationNativeValue{Request: o.request, Ordinal: n, Source: source, Workload: w, NativeStartedAt: o.start, NativeUntil: o.until, ValueObservedAt: o.f.f.clock(), Final: n == 4}
	if o.f.readHook != nil {
		if err := o.f.readHook(ctx, n, &v); err != nil {
			return value.ConnectorObservationNativeValue{}, err
		}
	}
	return v, nil
}

type connectorOperationTestExchange func(context.Context, int) (contracts.ConnectorObservationOperationReply, error)

func (f connectorOperationTestExchange) ReadConnectorObservationOperation(ctx context.Context, n int) (contracts.ConnectorObservationOperationReply, error) {
	return f(ctx, n)
}

type connectorOperationFixture struct {
	f           *connectorPairFixture
	credentials *ConnectorProcessCredentials
	pin         value.ConnectorObservationPin
	owner       value.OwnerObservationPin
	local       ConnectorProcessObservation
	root        context.Context
	state       *tls.ConnectionState
	request     value.OwnerObservationRequest
	native      *connectorOperationNativeFixture
	producer    *ConnectorObservationOperationProducer
}

func newConnectorOperationFixture(t *testing.T) *connectorOperationFixture {
	t.Helper()
	f, c, p, owner, local, outer, state := connectorObservationTestTLS(t)
	r := value.OwnerObservationRequest{RootID: p.Profile.RootID, ID: ownerTestID, Challenge: ownerOtherID, RequestedAt: f.clock(), NotAfter: f.clock().Add(5 * time.Second)}
	root, cancel := context.WithDeadline(outer, r.NotAfter)
	t.Cleanup(cancel)
	native := &connectorOperationNativeFixture{f: f, pin: p}
	producer, err := NewConnectorObservationOperationProducer(p, c, native, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	return &connectorOperationFixture{f, c, p, owner, local, root, state, r, native, producer}
}
func (f *connectorOperationFixture) begin(t *testing.T, call context.Context) *connectorProducedOperation {
	t.Helper()
	o, err := f.producer.begin(f.root, call, f.state, f.local.Registration.Certificate, f.request)
	if err != nil {
		t.Fatal("native operation admission", err)
	}
	t.Cleanup(o.Close)
	return o
}
func (f *connectorOperationFixture) source(t *testing.T, exchange connectorOperationExchange) *RemoteConnectorObservationOperationSource {
	t.Helper()
	s, err := NewRemoteConnectorObservationOperationSource(f.root, f.pin, f.owner, f.request, f.state, exchange, f.f.clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}
func operationTestRegistration(f *connectorOperationFixture, last value.ConnectorObservationOperationValue) app.ConnectorObservationOperationRegistration {
	r := f.local.Registration
	r.FreshUntil = identity.Earlier(r.FreshUntil, last.Until())
	return app.ConnectorObservationOperationRegistration{Registration: r, Last: last.Clone()}
}

func TestConnectorOperationOneNativeInstanceAcrossBothPairs(t *testing.T) {
	f := newConnectorOperationFixture(t)
	trap := &connectorObservationReadTrap{}
	f.credentials.source, f.credentials.registry = trap, trap
	admission, finish := context.WithCancel(f.root)
	o := f.begin(t, admission)
	finish() // A completed frame's call must not own the original stream.
	s := f.source(t, connectorOperationTestExchange(o.read))
	var first app.ConnectorObservationOperationRegistration
	for n := 1; n <= 4; n++ {
		call, done := context.WithCancel(f.root)
		v, err := s.ReadConnectorObservationValue(call, n)
		if err != nil {
			done()
			t.Fatal("actual numbered read", n, err)
		}
		if n == 2 || n == 4 {
			r := operationTestRegistration(f, v)
			if _, err = s.AcceptRegistration(call, r); err != nil {
				done()
				t.Fatal("registration pair", n, err)
			}
			if n == 2 {
				first = r
				if r.FinalMatches(f.pin, f.request, f.f.clock()) {
					t.Fatal("first pair became final")
				}
			}
			if n == 4 && (!r.FinalMatches(f.pin, f.request, f.f.clock()) || !r.Last.Continues(first.Last)) {
				t.Fatal("final pair lost original operation")
			}
		}
		done()
	}
	if f.native.opens.Load() != 1 || f.native.reads.Load() != 4 || f.native.finals.Load() != 1 || trap.calls.Load() != 0 {
		t.Fatal("native operation reused/reopened or legacy recursion", f.native.opens.Load(), f.native.reads.Load(), f.native.finals.Load(), trap.calls.Load())
	}
	o.Close()
	if f.native.closes.Load() != 1 {
		t.Fatal("native handle not joined exactly once")
	}
	if _, err := s.ReadConnectorObservationValue(f.root, 1); err == nil {
		t.Fatal("same source replayed")
	}
}

func TestConnectorOperationCrossPairSubstitutionIsTerminal(t *testing.T) {
	for _, mode := range []string{"new-operation", "backing", "roles", "native-start", "channel", "leaf", "early-final", "missing-final", "out-of-order", "missing-first-registration"} {
		t.Run(mode, func(t *testing.T) {
			f := newConnectorOperationFixture(t)
			o := f.begin(t, f.root)
			calls := 0
			exchange := connectorOperationTestExchange(func(ctx context.Context, n int) (contracts.ConnectorObservationOperationReply, error) {
				calls++
				w, err := o.read(ctx, n)
				if n == 3 {
					switch mode {
					case "new-operation":
						w.BracketID = ownerOtherID
					case "backing":
						w.BackingRevision++
					case "native-start":
						w.NativeStartedAt = f.request.RequestedAt.Add(time.Millisecond).Format(time.RFC3339Nano)
					case "channel":
						w.ConnectionBinding = ownerObservationHex(artifact.Digest{99})
					case "leaf":
						w.ConnectorLeaf = ownerObservationHex(artifact.Digest{99})
					case "early-final":
						w.Final = true
					}
				}
				if n == 4 && mode == "missing-final" {
					w.Final = false
				}
				return w, err
			})
			s := f.source(t, exchange)
			for n := 1; n <= 2; n++ {
				v, err := s.ReadConnectorObservationValue(f.root, n)
				if err != nil {
					t.Fatal(err)
				}
				if n == 2 && mode != "missing-first-registration" {
					if _, err = s.AcceptRegistration(f.root, operationTestRegistration(f, v)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if mode == "roles" {
				f.native.readHook = func(_ context.Context, _ int, v *value.ConnectorObservationNativeValue) error {
					v.Source.Roles.Source = "changed_source"
					return nil
				}
			}
			n := 3
			if mode == "out-of-order" {
				n = 4
			}
			_, err := s.ReadConnectorObservationValue(f.root, n)
			if mode == "missing-final" && err == nil {
				_, err = s.ReadConnectorObservationValue(f.root, 4)
			}
			if err == nil {
				t.Fatal("changed pair accepted")
			}
			spent := calls
			if _, err = s.ReadConnectorObservationValue(f.root, 3); err == nil || calls != spent {
				t.Fatal("failed phase replayed", calls, spent, err)
			}
		})
	}
}

func TestConnectorOperationCancellationDuringAdmissionCannotTransfer(t *testing.T) {
	f := newConnectorOperationFixture(t)
	entered := make(chan struct{})
	f.native.openHook = func(ctx context.Context) { close(entered); <-ctx.Done() }
	call, cancel := context.WithCancel(f.root)
	t.Cleanup(cancel)
	result := make(chan error, 1)
	go func() {
		o, err := f.producer.begin(f.root, call, f.state, f.local.Registration.Certificate, f.request)
		if o != nil {
			o.Close()
		}
		result <- err
	}()
	<-entered
	cancel()
	if err := <-result; err == nil || f.native.opens.Load() != 1 || f.native.closes.Load() != 1 {
		t.Fatal("cancelled native open transferred ownership", err, f.native.closes.Load())
	}
}

func TestConnectorOperationCloseJoinsNativeAndRemoteReads(t *testing.T) {
	for _, where := range []string{"native", "remote"} {
		t.Run(where, func(t *testing.T) {
			f := newConnectorOperationFixture(t)
			o := f.begin(t, f.root)
			entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			block := func(ctx context.Context) { close(entered); <-ctx.Done(); close(cancelled); <-release }
			exchange := connectorOperationTestExchange(o.read)
			if where == "native" {
				f.native.readHook = func(ctx context.Context, _ int, _ *value.ConnectorObservationNativeValue) error {
					block(ctx)
					return ctx.Err()
				}
			} else {
				exchange = func(ctx context.Context, _ int) (contracts.ConnectorObservationOperationReply, error) {
					block(ctx)
					return contracts.ConnectorObservationOperationReply{}, ctx.Err()
				}
			}
			s := f.source(t, exchange)
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			ended := make(chan error, 1)
			go func() { _, err := s.ReadConnectorObservationValue(f.root, 1); ended <- err }()
			<-entered
			closed := make(chan struct{})
			go func() {
				if where == "native" {
					o.Close()
				}
				s.Close()
				close(closed)
			}()
			<-cancelled
			select {
			case <-closed:
				t.Fatal("Close returned before actual read joined")
			default:
			}
			releaseOnce.Do(func() { close(release) })
			if err := <-ended; err == nil {
				t.Fatal("cancelled read returned a value")
			}
			<-closed
		})
	}
}

func TestConnectorOperationShortenedCallAndSocketNeverRenew(t *testing.T) {
	for _, where := range []string{"admission", "ordinal2", "late-attachment"} {
		t.Run(where, func(t *testing.T) {
			f := newConnectorOperationFixture(t)
			end := time.Now().Add(300 * time.Millisecond)
			short, cancel := context.WithDeadline(f.root, end)
			defer cancel()
			admission := f.root
			if where == "admission" {
				admission = short
			}
			if where == "late-attachment" {
				f.root = short
				admission = short
			}
			o := f.begin(t, admission)
			for n := 1; n <= 2; n++ {
				call := f.root
				if where == "ordinal2" && n == 2 {
					call = short
				}
				w, err := o.read(call, n)
				if err != nil {
					t.Fatal(err)
				}
				if (where != "ordinal2" || n == 2) && ownerObservationTime(w.NativeUntil).After(end) {
					t.Fatal("original bound extended")
				}
			}
			<-short.Done()
			if _, err := o.read(f.root, 3); err == nil || f.native.reads.Load() != 2 {
				t.Fatal("short bound renewed", err, f.native.reads.Load())
			}
		})
	}
}

func TestConnectorOperationCurrentKeysAndFinalMutationDeny(t *testing.T) {
	for _, mode := range []string{"replacement-before", "replacement-after", "renewal-after", "root-cancel", "final-source", "issuer-change"} {
		t.Run(mode, func(t *testing.T) {
			f := newConnectorOperationFixture(t)
			o := f.begin(t, f.root)
			for n := 1; n <= 3; n++ {
				if _, err := o.read(f.root, n); err != nil {
					t.Fatal(err)
				}
			}
			replace := func() {
				f.credentials.mu.Lock()
				p := *f.credentials.active
				f.credentials.active = &p
				f.credentials.mu.Unlock()
			}
			if mode == "replacement-before" {
				replace()
			}
			f.native.readHook = func(_ context.Context, _ int, v *value.ConnectorObservationNativeValue) error {
				switch mode {
				case "replacement-after":
					replace()
				case "renewal-after":
					f.credentials.mu.Lock()
					f.credentials.active.installed[0].Digest = artifact.Digest{99}
					f.credentials.mu.Unlock()
				case "root-cancel":
					f.credentials.Close()
				case "final-source":
					v.Source.Observation.Backing.Revision++
				case "issuer-change":
					v.Source.Observation.Profile.ClientIssuerRoots = [][]byte{f.f.serverCA.cert.Raw}
				}
				return nil
			}
			if w, err := o.read(f.root, 4); err == nil || w.Format != "" {
				t.Fatal("changed final native/process facts returned", err)
			}
			calls := f.native.reads.Load()
			if mode == "replacement-before" && calls != 3 {
				t.Fatal("known changed key reached native I/O")
			}
			if _, err := o.read(f.root, 4); err == nil || f.native.reads.Load() != calls {
				t.Fatal("failed final phase replayed")
			}
		})
	}
}

func TestConnectorOperationRegistrationMustMatchActualStoredPair(t *testing.T) {
	for _, mode := range []string{"different-bracket", "different-leaf", "different-observed-date", "different-backing", "registration-process", "registration-revision", "registration-end", "final-pair-is-first"} {
		t.Run(mode, func(t *testing.T) {
			f := newConnectorOperationFixture(t)
			o := f.begin(t, f.root)
			s := f.source(t, connectorOperationTestExchange(o.read))
			var r app.ConnectorObservationOperationRegistration
			for n := 1; n <= 2; n++ {
				v, err := s.ReadConnectorObservationValue(f.root, n)
				if err != nil {
					t.Fatal(err)
				}
				r = operationTestRegistration(f, v)
			}
			switch mode {
			case "different-bracket":
				r.Last.BracketID = ownerOtherID
			case "different-leaf":
				r.Last.Certificate.Digest = artifact.Digest{99}
			case "different-observed-date":
				r.Last.Native.ValueObservedAt = r.Last.Native.ValueObservedAt.Add(time.Millisecond)
			case "different-backing":
				r.Last.Native.Source.Observation.Backing.Revision++
			case "registration-process":
				r.Registration.Process.ProcessEpoch = ownerOtherID
			case "registration-revision":
				r.Registration.Revision.Generation++
			case "registration-end":
				r.Registration.FreshUntil = f.request.NotAfter.Add(time.Second)
			case "final-pair-is-first":
				r.Last.Native.Ordinal = 4
				r.Last.Native.Final = true
			}
			if _, err := s.AcceptRegistration(f.root, r); err == nil {
				t.Fatal("substituted SQL/source pair accepted")
			}
			if _, err := s.ReadConnectorObservationValue(f.root, 3); err == nil || f.native.reads.Load() != 2 {
				t.Fatal("rejected registration reached final source")
			}
		})
	}
}
