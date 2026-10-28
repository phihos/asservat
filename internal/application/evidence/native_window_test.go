package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
)

// windowNativePorts admit every exchange synthetically; they count
// registrations and releases so a window can be shown to use one conversation.
type windowNativePorts struct {
	unusedActiveNativePorts
	exchange       *windowExchange
	registrations  int
	releases       int
	onRegister     func(NativeExchangeRegistration, func(context.Context, NativeOrigin) (value.NativeLease, error))
	observation    value.NativeLease
	nextLease      artifact.DownloadDeliveryLease
	renewals       int
	registered     value.NativeOperation
	normalizeClaim bool
}

func (p *windowNativePorts) NextNativeFence(context.Context, string) (int64, error) { return 1, nil }
func (p *windowNativePorts) ClaimNativeOperation(_ context.Context, _ value.WorkerEnrollment, _ artifact.DownloadAuthority, o value.NativeOperation) (value.NativeOperation, error) {
	if p.normalizeClaim {
		o.StartedAt = o.StartedAt.UTC().Truncate(time.Microsecond)
		o.Until = o.Until.UTC().Truncate(time.Microsecond)
	}
	return o, nil
}
func (p *windowNativePorts) ReleaseNativeOperation(context.Context, value.NativeOperation) error {
	p.releases++
	return nil
}
func (p *windowNativePorts) RegisterNativeExchange(_ context.Context, r NativeExchangeRegistration, _ func(context.Context, NativeOrigin) error, check func(context.Context, NativeOrigin) (value.NativeLease, error)) (NativePendingExchange, error) {
	p.registrations++
	p.registered = r.Operation
	p.exchange.delivery = r.Delivery
	if p.onRegister != nil {
		p.onRegister(r, check)
	}
	return windowPending{p.exchange}, nil
}

type windowPending struct{ e *windowExchange }

func (p windowPending) Wait(context.Context) (NativeExchange, error) { return p.e, nil }
func (windowPending) Close()                                         {}

// windowExchange serves exact chunks of body inside its delivery window and
// records the final-sink acknowledgements it receives.
type windowExchange struct {
	body          []byte
	delivery      artifact.DownloadDeliveryLease
	reads         []int64
	acks          []int64
	failAck       bool
	missingCutoff bool
}

func (e *windowExchange) Commit(context.Context) error { return nil }
func (e *windowExchange) Close() error                 { return nil }
func (e *windowExchange) Prepared(context.Context) (artifact.NativeDownloadMetadata, error) {
	return artifact.NativeDownloadMetadata{}, artifact.ErrDownloadUnavailable
}
func (e *windowExchange) ReadChunk(_ context.Context, l artifact.DownloadDeliveryLease, offset, length int64) (NativeResponseChunk, error) {
	if !SameNativeWindow(l, e.delivery) || l.Sequence < e.delivery.Sequence || !l.Allows(offset, length, time.Now()) || offset+length > int64(len(e.body)) {
		return NativeResponseChunk{}, artifact.ErrDownloadUnavailable
	}
	e.reads = append(e.reads, offset)
	until := l.Until
	if e.missingCutoff {
		until = time.Time{}
	}
	return NativeResponseChunk{Bytes: append([]byte(nil), e.body[offset:offset+length]...), FinalVerified: true, NativeUntil: until}, nil
}
func (e *windowExchange) AcknowledgeNativeChunk(_ context.Context, l artifact.DownloadDeliveryLease, offset, length int64) error {
	if !SameNativeWindow(l, e.delivery) || l.Sequence < e.delivery.Sequence || !l.Allows(offset, length, time.Now()) || e.failAck {
		return artifact.ErrDownloadUnavailable
	}
	e.acks = append(e.acks, offset+length)
	return nil
}

// One delivery lease window is read as several chunks through one remote
// conversation: each chunk needs the previous chunk's acknowledgement, only
// the window's last acknowledgement (or a failed one) closes it, and a new
// lease opens a new conversation.
func TestRemoteContextSourceServesWindowChunksThroughOneConversation(t *testing.T) {
	for _, mode := range []string{"complete", "failed-ack", "missing-cutoff", "representation-read", "representation-ack"} {
		t.Run(mode, func(t *testing.T) {
			f := newActiveEnrollmentFixture(t)
			body := []byte("0123456789abcdefg") // a 17-byte window read as 10+7
			ports := &windowNativePorts{exchange: &windowExchange{body: body, failAck: mode == "failed-ack", missingCutoff: mode == "missing-cutoff"}, normalizeClaim: true}
			en := *f.lookup.value.Enrollment
			f.r.config.Native = NativeAttachmentConfig{HubPodUID: en.Worker.Binding.PodUID, HubProcessEpoch: en.Worker.Intent.ID, KeyScope: value.KeyScope{InstallationID: en.Worker.Binding.InstallationID, Purpose: "artifact", KeyID: "synthetic"}, Owners: ports, Fences: ports, Origins: NativeOrigins{Operations: ports, Now: f.r.config.Now}, Registrar: ports, PreparationKeys: ports, WindowKeys: ports}
			attachment, err := f.r.native(en)
			if err != nil {
				t.Fatal(err)
			}
			request := ContextDownloadRequest{SessionID: f.f.s.ID, Scope: f.f.s.Scope, Expectation: f.source.Expectation, Copies: f.source.Copies}
			owner, stopOwner := context.WithDeadline(t.Context(), time.Now().UTC().Truncate(time.Microsecond).Add(10*time.Second+123*time.Nanosecond))
			defer stopOwner()
			source, err := NewRemoteContextSource(owner, attachment, request, artifact.DownloadPreparation{SessionID: f.f.s.ID, BatchID: "30000000-0000-4000-8000-000000000001", Generation: 1})
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			id := f.f.s.ID
			lease := artifact.DownloadDeliveryLease{ResponseID: id, WindowID: id, OwnerID: id, Generation: 1, Sequence: 1, Offset: 0, Length: int64(len(body)), StartedAt: f.f.now, Until: f.f.a.ValidUntil, Authority: f.f.a}
			if !lease.Valid(f.f.now) {
				t.Fatal("synthetic lease invalid")
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if _, err = source.ReadChunkCurrent(ctx, f.f, lease, 3, 7); err == nil {
				t.Fatal("window opened away from its offset")
			}
			first, err := source.ReadChunkCurrent(ctx, f.f, lease, 0, 10)
			if mode == "missing-cutoff" {
				if err == nil || ports.releases != 1 {
					t.Fatal("remote cutoff omitted", err, ports.releases)
				}
				return
			}
			if end, _ := owner.Deadline(); ports.registered.Until.After(end) {
				t.Fatal("native operation advertised past original response owner", ports.registered.Until, end)
			}
			if err != nil || !bytes.Equal(first.Bytes, body[:10]) {
				t.Fatal("first chunk", err)
			}
			if _, err = source.ReadChunkCurrent(ctx, f.f, lease, 10, 7); err == nil {
				t.Fatal("next chunk read before the final-sink acknowledgement")
			}
			ackLease := lease
			if mode == "representation-ack" {
				ackLease = sameInstantWindowLease(t, lease)
			}
			err = source.AcknowledgeNativeChunk(ctx, ackLease, 0, 10)
			if mode == "failed-ack" {
				if err == nil || ports.releases != 1 {
					t.Fatal("failed acknowledgement kept the conversation", err, ports.releases)
				}
				if _, err = source.ReadChunkCurrent(ctx, f.f, lease, 10, 7); err == nil {
					t.Fatal("failed window continued")
				}
				return
			}
			if err != nil || ports.releases != 0 {
				t.Fatal("intermediate acknowledgement", err, ports.releases)
			}
			if _, err = source.ReadChunkCurrent(ctx, f.f, lease, 11, 6); err == nil {
				t.Fatal("gap admitted")
			}
			readLease := lease
			if mode == "representation-read" {
				readLease = sameInstantWindowLease(t, lease)
			}
			changed := readLease
			changed.Authority.Scope.Principal.Subject = "different-scope"
			if _, err := source.ReadChunkCurrent(ctx, f.f, changed, 10, 7); err == nil {
				t.Fatal("changed lease scope continued the window")
			}
			last, err := source.ReadChunkCurrent(ctx, f.f, readLease, 10, 7)
			if err != nil || !bytes.Equal(last.Bytes, body[10:]) {
				t.Fatal("last chunk", err)
			}
			expired := readLease
			expired.Until = time.Now().Add(-time.Second)
			if err = source.AcknowledgeNativeChunk(ctx, expired, 10, 7); err == nil {
				t.Fatal("expired lease acknowledged a chunk")
			}
			finalLease := lease
			if mode == "representation-read" || mode == "representation-ack" {
				finalLease = sameInstantWindowLease(t, readLease)
			}
			if err = source.AcknowledgeNativeChunk(ctx, finalLease, 10, 7); err != nil {
				t.Fatal("last acknowledgement", err)
			}
			if ports.registrations != 1 || ports.releases != 1 || len(ports.exchange.reads) != 2 || len(ports.exchange.acks) != 2 {
				t.Fatal("window did not use exactly one joined conversation", ports.registrations, ports.releases, ports.exchange.reads, ports.exchange.acks)
			}
			// The next lease (a resumed window) opens its own conversation.
			next := lease
			next.Sequence, next.Offset, next.Length = 2, 10, 7
			if _, err = source.ReadChunkCurrent(ctx, f.f, next, 10, 7); err != nil || ports.registrations != 2 {
				t.Fatal("next window", err, ports.registrations)
			}
		})
	}
}

func sameInstantWindowLease(t *testing.T, lease artifact.DownloadDeliveryLease) artifact.DownloadDeliveryLease {
	t.Helper()
	raw, err := json.Marshal(lease)
	if err != nil {
		t.Fatal(err)
	}
	var represented artifact.DownloadDeliveryLease
	if err := json.Unmarshal(raw, &represented); err != nil {
		t.Fatal(err)
	}
	represented.Until = represented.Until.In(time.FixedZone("same-instant", 3600))
	if represented == lease || !represented.Until.Equal(lease.Until) || !represented.StartedAt.Equal(lease.StartedAt) || !represented.Valid(time.Now()) {
		t.Fatal("equivalent lease fixture changed validity or instants")
	}
	return represented
}

// Worker-side window reads: pod status is served from its single checked
// buffer; another type is opened once per window and delivered in delivery
// chunks; a reader without the framed port, or relabelled metadata, refuses.
func TestRegionalResultFramedWindowChunks(t *testing.T) {
	r, _, source, o := nativeResultFixture(t)
	e := &source.Expectation
	now := e.TriggeredAt
	e.ExecutionClass = artifact.ContextNodeExecution
	e.NativeType = artifact.PCAPNGArtifact
	e.NodeUID, e.NodeBootID = "synthetic-node-uid", o.Reference.InstallationID
	e.ActionID = "a0123456789abcdef01234567"
	e.Registration.NativeLimit = artifact.RemoteNativeLimit
	e.TriggeredAt = now.Add(-20 * time.Second)
	e.Lifecycle = &artifact.OngoingLifecycle{TriggerKind: "policy", SourceSessionID: o.Reference.InstallationID, SourceStartedAt: now.Add(-2 * time.Minute), SnapshotID: o.Reference.InstallationID, RequestedBefore: 30 * time.Second, After: 10 * time.Second, HistoryCoverage: "full", GapReasons: []string{}, WindowCoverage: "full"}
	if !source.Valid(o.SourceVersion) {
		t.Fatal("synthetic pcapng source invalid", e.Validate())
	}
	body := bytes.Repeat([]byte{0x0a, 0x0d, 0x0d, 0x0a}, (2*artifact.DeliveryBytes+12345)/4)
	framed := &framedReadFixture{body: body, m: expectedNativeMetadata(source, int64(len(body)), sha256.Sum256(body))}
	r.reader = framed
	ctx, stop := context.WithDeadline(context.Background(), o.Until)
	defer stop()
	m, err := r.Prepare(ctx, o, source)
	if err != nil || m.Filename != "artifact-"+e.Registration.Location.ArtifactID+".pcapng" || m.Format != artifact.PCAPNGFormat || m.Size != int64(len(body)) || !ValidNativeSourceMetadata(source, m) {
		t.Fatalf("pcapng preparation %v %+v", err, m)
	}
	if err = r.Commit(ctx, o); err != nil {
		t.Fatal(err)
	}
	response := o
	response.Kind = value.NativeResponse
	response.Reference.Fence += 2
	var chunks []int
	var got []byte
	err = r.ReadWindow(ctx, response, source, o.ParentID, 0, m.Size, func(_ context.Context, b []byte) error {
		chunks = append(chunks, len(b))
		got = append(got, b...)
		return nil
	})
	if err != nil || !bytes.Equal(got, body) || len(chunks) != 3 || chunks[0] != int(artifact.DeliveryBytes) || framed.opens != 2 {
		t.Fatal("framed window", err, chunks, framed.opens)
	}
	// A partial window (resume) starts at its own offset.
	got = got[:0]
	if err = r.ReadWindow(ctx, response, source, o.ParentID, artifact.DeliveryBytes+1, 100, func(_ context.Context, b []byte) error { got = append(got, b...); return nil }); err != nil || !bytes.Equal(got, body[artifact.DeliveryBytes+1:artifact.DeliveryBytes+101]) {
		t.Fatal("partial framed window", err)
	}
	// A worker reader that reports another type's metadata is refused.
	r2, _, _, o2 := nativeResultFixture(t)
	relabel := expectedNativeMetadata(source, int64(len(body)), sha256.Sum256(body))
	relabel.Filename = "artifact-" + e.Registration.Location.ArtifactID + ".json"
	r2.reader = &framedReadFixture{body: body, m: relabel}
	o2.SourceVersion = o.SourceVersion
	if _, err = r2.Prepare(ctx, o2, source); err == nil {
		t.Fatal("relabelled metadata accepted")
	}
	// A pod-status-only reader cannot serve another type.
	r3, _, _, o3 := nativeResultFixture(t)
	o3.SourceVersion = o.SourceVersion
	if _, err = r3.Prepare(ctx, o3, source); err == nil {
		t.Fatal("pod-status reader served pcapng")
	}
}

type framedReadFixture struct {
	nativeReadFixture
	body  []byte
	m     artifact.NativeDownloadMetadata
	opens int
}

func (f *framedReadFixture) OpenNativeArtifact(ctx context.Context, s NativeContextSource, o value.NativeOperation, window string, until time.Time) (NativeArtifactSource, error) {
	if ctx.Err() != nil || s.podStatus() {
		return nil, artifact.ErrInvalid
	}
	f.opens++
	return &framedSourceFixture{f: f, next: -1}, nil
}

type framedSourceFixture struct {
	f    *framedReadFixture
	next int64
}

func (s *framedSourceFixture) Metadata() artifact.NativeDownloadMetadata { return s.f.m }
func (s *framedSourceFixture) ReadNext(_ context.Context, offset, length int64) ([]byte, bool, error) {
	if s.next >= 0 && offset != s.next || offset+length > int64(len(s.f.body)) {
		return nil, false, artifact.ErrDownloadUnavailable
	}
	s.next = offset + length
	return append([]byte(nil), s.f.body[offset:offset+length]...), true, nil
}
func (*framedSourceFixture) Close() {}

func (p *windowNativePorts) ObserveNativeOperation(context.Context, value.NativeReference, value.KeyPeer) (value.NativeLease, error) {
	return p.observation, nil
}
func (p *windowNativePorts) RenewNativeOperation(_ context.Context, ref value.NativeReference, a artifact.DownloadAuthority, peer value.KeyPeer) (value.NativeLease, error) {
	p.renewals++
	if ref != p.observation.Operation.Reference || peer.Certificate != p.observation.Certificate || p.nextLease.Sequence <= p.observation.Sequence {
		return value.NativeLease{}, artifact.ErrDownloadUnavailable
	}
	p.observation.Sequence = p.nextLease.Sequence
	p.observation.ObservedAt = p.nextLease.StartedAt
	p.observation.Until = p.nextLease.Until
	p.exchange.delivery = p.nextLease
	return p.observation, nil
}

func TestRemoteContextSourceRenewalPreservesCursorAndRejectsDowngrade(t *testing.T) {
	f := newActiveEnrollmentFixture(t)
	body := []byte("0123456789abcdefg")
	ports := &windowNativePorts{exchange: &windowExchange{body: body}}
	en := *f.lookup.value.Enrollment
	peer := value.KeyPeer{InstallationID: en.Worker.Binding.InstallationID, PeerID: en.Worker.Binding.PodUID, Role: "acquisition", Certificate: artifact.Digest{31}, NotBefore: f.f.now.Add(-time.Second), NotAfter: en.Worker.Intent.RunUntil}
	ports.onRegister = func(r NativeExchangeRegistration, check func(context.Context, NativeOrigin) (value.NativeLease, error)) {
		ports.observation = value.NativeLease{Operation: r.Operation, Certificate: peer.Certificate, Sequence: r.Delivery.Sequence, ObservedAt: f.f.now, Until: r.Delivery.Until}
		origin := NativeOrigin{Lease: ports.observation, Proof: value.AcquisitionPeerProof{Binding: en.Worker.Binding.Acquisition(), Peer: peer, TokenDigest: artifact.Digest{1}, ObservedAt: f.f.now, FreshUntil: r.Delivery.Until}}
		keyProof, _ := origin.Proof.DownloadProof()
		origin.response = &nativeResponseAdmission{proof: NativeResponsePeerProof{Proof: keyProof, TokenNotAfter: en.Worker.Intent.RunUntil}, at: f.f.now}
		if _, err := check(t.Context(), origin); err != nil {
			t.Fatal("synthetic initial current check", err)
		}
	}
	f.r.config.Native = NativeAttachmentConfig{HubPodUID: en.Worker.Binding.PodUID, HubProcessEpoch: en.Worker.Intent.ID, KeyScope: value.KeyScope{InstallationID: en.Worker.Binding.InstallationID, Purpose: "artifact", KeyID: "synthetic"}, Owners: ports, Fences: ports, Origins: NativeOrigins{Operations: ports, Now: f.r.config.Now, Recent: NewNativeRecentObservations()}, Registrar: ports, PreparationKeys: ports, WindowKeys: ports}
	attachment, err := f.r.native(en)
	if err != nil {
		t.Fatal(err)
	}
	request := ContextDownloadRequest{SessionID: f.f.s.ID, Scope: f.f.s.Scope, Expectation: f.source.Expectation, Copies: f.source.Copies}
	source, err := NewRemoteContextSource(t.Context(), attachment, request, artifact.DownloadPreparation{SessionID: f.f.s.ID, BatchID: "30000000-0000-4000-8000-000000000001", Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	id := f.f.s.ID
	lease := artifact.DownloadDeliveryLease{ResponseID: id, WindowID: id, OwnerID: id, Generation: 1, Sequence: 1, Length: int64(len(body)), StartedAt: f.f.now, Until: f.f.a.ValidUntil, Authority: f.f.a}
	first, err := source.ReadChunkCurrent(t.Context(), f.f, lease, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	clear(first.Bytes)
	if err = source.AcknowledgeNativeChunk(t.Context(), lease, 0, 10); err != nil {
		t.Fatal(err)
	}
	next := lease
	next.Sequence++
	ports.nextLease = next
	last, err := source.ReadChunkCurrent(t.Context(), f.f, next, 10, 7)
	if err != nil || !bytes.Equal(last.Bytes, body[10:]) {
		t.Fatal("renewed exact cursor", err)
	}
	clear(last.Bytes)
	if err = source.AcknowledgeNativeChunk(t.Context(), lease, 10, 7); err == nil {
		t.Fatal("old lease acknowledged renewed chunk")
	}
	if err = source.AcknowledgeNativeChunk(t.Context(), next, 10, 7); err != nil {
		t.Fatal(err)
	}
	if ports.registrations != 1 || ports.renewals != 1 || ports.releases != 1 {
		t.Fatal("renewal reopened/refilled conversation", ports.registrations, ports.renewals, ports.releases)
	}
}
