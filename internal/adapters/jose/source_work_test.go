package jose

import (
	deliveryapp "asservat.local/asservat/internal/application/delivery"
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/kms"
	app "asservat.local/asservat/internal/application/fleet"
	compiler "asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/configuration"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

func sourceSignatureWork(base value.APIContextWork, now time.Time) app.SourceWork {
	id := base.CaptureID
	resources := collector.SourceResources{PolicyUID: "capacity-policy"}
	p := collector.SourcePermit{Binding: collector.SourceBinding{RootID: base.Channel.RootID, PolicyUID: "policy", AcceptanceID: base.AttemptID, SourceID: id, Fence: id, ActionID: "packets", PodUID: base.Target.PodUID, NodeUID: id, BootID: id, CollectorPodUID: id, CollectorEpoch: id, Scope: [32]byte{1}, ExpectationDigest: [32]byte{2}, ResourceDigest: deliveryapp.SourceResourcesDigest(resources)}, StartedAt: now, HardUntil: now.Add(24 * time.Hour), StartBy: now.Add(5 * time.Second), IssuedAt: now, DispatchUntil: now.Add(5 * time.Second), LeafUntil: now.Add(30 * time.Second), Credit: 1 << 40, BytesPerSecond: 1 << 20}
	target := targets.PodResolution{ExecutionClass: artifact.ContextAPIExecution, Request: targets.Request{ClusterID: base.Target.ClusterID, Namespace: configuration.NamespaceRef{Name: "app", UID: base.Target.NamespaceUID}, Workload: configuration.WorkloadRef{Kind: "Deployment", Name: "app", UID: base.Target.WorkloadUID}, PodName: "app-0", PodUID: base.Target.PodUID}, Pin: artifact.PinnedPod{Namespace: "app", NamespaceUID: base.Target.NamespaceUID, Name: "app-0", UID: base.Target.PodUID, ControllerUID: id}, PodResourceVersion: "1", WorkloadResourceVersion: "1", ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}
	return app.SourceWork{Channel: base.Channel, Target: target, Node: targets.PacketSourceObservation{PodUID: p.Binding.PodUID, NodeUID: p.Binding.NodeUID, BootID: p.Binding.BootID, CollectorPodUID: p.Binding.CollectorPodUID, CollectorEpoch: p.Binding.CollectorEpoch, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, Source: collector.PacketSource{Permit: p, Resources: resources, Ring: collector.SourceRingLimits{MaxAge: time.Minute, MaxBytes: 1 << 20, SegmentBytes: 256 << 10, MaxSegments: 4, MaxFrozenBytes: 1 << 20, MaxConcurrentSnapshots: 2}}, NotAfter: now.Add(5 * time.Second)}
}

func TestSourceWorkMaximumFitsActualBoundedTransitSigner(t *testing.T) {
	base, receiver, trust, key, now := apiWorkFixture(t)
	w := sourceSignatureWork(base, *now)
	w.Source.Program = make([]planning.BPFInstruction, planning.MaxFilterInstructions)
	for i := range w.Source.Program {
		w.Source.Program[i] = planning.BPFInstruction{Code: 65535, Jt: 255, Jf: 255, K: 1<<32 - 1}
	}
	w.Source.Permit.Binding.ProgramDigest = [32]byte(compiler.FilterProgramDigest(w.Source.Program))
	w.Target.Request.Namespace.Name = strings.Repeat("n", 63)
	w.Target.Pin.Namespace = w.Target.Request.Namespace.Name
	w.Target.Request.Workload.Name = strings.Repeat("w", 253)
	w.Target.Request.PodName = strings.Repeat("p", 253)
	w.Target.Pin.Name = w.Target.Request.PodName
	w.Target.PodResourceVersion = strings.Repeat("9", 128)
	w.Target.WorkloadResourceVersion = strings.Repeat("9", 128)
	kid := strings.Repeat("&", 128)
	trust.Trust.Keys[0].ID = kid
	var calls atomic.Int64
	var maximum atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		var input struct {
			Input     string `json:"input"`
			Version   int    `json:"key_version"`
			Prehashed bool   `json:"prehashed"`
		}
		if request.URL.Path != "/v1/work/sign/source" || request.Method != http.MethodPost || json.NewDecoder(request.Body).Decode(&input) != nil || input.Version != 1 || input.Prehashed {
			t.Error("changed signing provider request")
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		message, err := base64.StdEncoding.Strict().DecodeString(input.Input)
		if err != nil {
			t.Error(err)
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		maximum.Store(int64(len(message)))
		_ = json.NewEncoder(response).Encode(map[string]any{"data": map[string]any{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(key, message))}})
	}))
	defer server.Close()
	provider, err := kms.NewSigningKey(server.URL, "fixture-work-token", "work", "source", 1, key.Public().(ed25519.PublicKey), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewAPIContextWorkSignatures(apiTrustFunc(func(context.Context) (value.APIContextWorkTrust, error) { return trust, nil }), kid, provider.ForContext, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	// The unchanged production signer refuses the old oversized input before
	// any HTTP call. The compact maximum source uses that same real adapter.
	if _, err = provider.ForContext(t.Context()).Sign(nil, make([]byte, 16385), crypto.Hash(0)); err == nil || calls.Load() != 0 {
		t.Fatal("provider size guard weakened")
	}
	signed, err := signer.SignSourceWork(t.Context(), w)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = signer.VerifySourceWork(t.Context(), signed, receiver); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || maximum.Load() > 16384 || len(signed) > contracts.SourceSignedWorkBytes {
		t.Fatal("source exceeds actual signer", calls.Load(), maximum.Load(), len(signed))
	}
	t.Logf("maximum program/legal names/key ID: signing input %d bytes, signed source %d bytes, actual Transit-adapter HTTP calls %d", maximum.Load(), len(signed), calls.Load())
}

func TestSourceWorkSigningSeparatesOrdinarySourceStopAndFinitePurpose(t *testing.T) {
	base, receiver, trust, key, now := apiWorkFixture(t)
	w := sourceSignatureWork(base, *now)
	s := apiSignatures(t, func(context.Context) (value.APIContextWorkTrust, error) { return trust, nil }, key, now)
	signed, err := s.SignSourceWork(t.Context(), w)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.VerifySourceWork(t.Context(), signed, receiver)
	if err != nil || !got.Valid(*now) || got.Work.Source.Permit != w.Source.Permit {
		t.Fatal("ordinary source roundtrip", err)
	}
	if _, err = s.VerifyAPIContextWork(t.Context(), signed, receiver); err == nil {
		t.Fatal("ordinary source became finite execution")
	}
	if _, err = s.VerifyHistoryWork(t.Context(), signed, receiver); err == nil {
		t.Fatal("ordinary source became history effect")
	}
	finite, err := s.SignAPIContextWork(t.Context(), base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.VerifySourceWork(t.Context(), finite, receiver); err == nil {
		t.Fatal("finite work became source")
	}
	wrong := receiver
	wrong.Channel.Challenge = base.AttemptID
	if _, err = s.VerifySourceWork(t.Context(), signed, wrong); err == nil {
		t.Fatal("source crossed conversation")
	}
	stop := app.SourceWork{Channel: w.Channel, Source: collector.PacketSource{Permit: collector.SourcePermit{Binding: w.Source.Permit.Binding}}, Stop: true, StopIssuedAt: *now, NotAfter: w.NotAfter}
	encoded, err := s.SignSourceWork(t.Context(), stop)
	if err != nil {
		t.Fatal("restrictive stop needs no gone Pod read", err)
	}
	if _, err = s.VerifySourceWork(t.Context(), encoded, receiver); err != nil {
		t.Fatal(err)
	}
	stop.Stop = false
	if _, err = s.SignSourceWork(t.Context(), stop); err == nil {
		t.Fatal("stop payload became arm")
	}
	trust.Trust.Keys = nil
	if _, err = s.VerifySourceWork(t.Context(), signed, receiver); err == nil {
		t.Fatal("removed work signing key reused")
	}
}

func TestSourceWorkMaximumProgramAndEarlierHardBounds(t *testing.T) {
	base, receiver, trust, key, now := apiWorkFixture(t)
	w := sourceSignatureWork(base, *now)
	w.Source.Program = make([]planning.BPFInstruction, planning.MaxFilterInstructions)
	for i := range w.Source.Program {
		w.Source.Program[i] = planning.BPFInstruction{Code: 65535, Jt: 255, Jf: 255, K: 1<<32 - 1}
	}
	w.Source.Permit.Binding.ProgramDigest = [32]byte(compiler.FilterProgramDigest(w.Source.Program))
	s := apiSignatures(t, func(context.Context) (value.APIContextWorkTrust, error) { return trust, nil }, key, now)
	signed, err := s.SignSourceWork(t.Context(), w)
	if err != nil || len(signed) > contracts.SourceSignedWorkBytes {
		t.Fatal("maximum source work", len(signed), err)
	}
	if _, err = s.VerifySourceWork(t.Context(), signed, receiver); err != nil {
		t.Fatal(err)
	}
	t.Logf("maximum program signed source work: %d bytes", len(signed))
	for name, change := range map[string]func(*app.SourceWork){
		"resource-lowering":   func(w *app.SourceWork) { w.Source.Resources.Node.RingBytes = 1024 },
		"target-replaced":     func(w *app.SourceWork) { w.Target.Pin.UID = base.AttemptID },
		"source-process":      func(w *app.SourceWork) { w.Node.CollectorEpoch = base.AttemptID },
		"leaf-beyond-hardend": func(w *app.SourceWork) { w.Source.Permit.HardUntil = w.Source.Permit.LeafUntil.Add(-time.Nanosecond) },
		"long-leaf":           func(w *app.SourceWork) { w.Source.Permit.LeafUntil = w.Source.Permit.LeafUntil.Add(time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			next := w
			change(&next)
			if _, err = s.SignSourceWork(t.Context(), next); err == nil {
				t.Fatal("invalid authority signed")
			}
		})
	}
}

func TestSourceWorkSnapshotCancellationUsesCurrentControlAndOriginalWriter(t *testing.T) {
	base, receiver, trust, key, now := apiWorkFixture(t)
	arm := sourceSignatureWork(base, *now)
	b := arm.Source.Permit.Binding
	b.AudienceDigest = [32]byte{7}
	q := artifact.SourceSnapshotRequest{SourceBindingDigest: artifact.Digest(deliveryapp.SourceBindingDigest(b)), SourceID: b.SourceID, Fence: b.Fence, SnapshotID: "66666666-6666-4666-8666-666666666666", SourceStartedAt: now.Add(-time.Minute), SourceHardUntil: now.Add(-time.Second), T0: now.Add(-30 * time.Second), IssuedAt: now.Add(-30 * time.Second), StartBy: now.Add(-25 * time.Second), ProcessingUntil: now.Add(time.Minute), Before: time.Second, MaxBytes: 65536}
	x := collector.SourceSnapshot{Binding: b, CaptureID: "44444444-4444-4444-8444-444444444444", AttemptID: base.AttemptID, WriterPodUID: base.Channel.Executor.PodUID, WriterEpoch: base.Channel.Executor.ProcessEpoch, ExpectationDigest: [32]byte{5}, Request: q}
	w := app.SourceWork{Channel: base.Channel, StopSnapshot: &x, StopIssuedAt: *now, NotAfter: now.Add(3 * time.Second)}
	signatures := apiSignatures(t, func(context.Context) (value.APIContextWorkTrust, error) { return trust, nil }, key, now)
	signed, err := signatures.SignSourceWork(t.Context(), w)
	if err != nil {
		t.Fatal("expired source wrongly blocked restrictive cancel", err)
	}
	accepted, err := signatures.VerifySourceWork(t.Context(), signed, receiver)
	if err != nil || accepted.Work.StopSnapshot == nil || !accepted.Work.StopSnapshot.Equal(x) || accepted.Work.RouteID() != x.CaptureID {
		t.Fatal("lost exact snapshot cancellation", accepted, err)
	}
	for name, change := range map[string]func(*app.SourceWork){
		"replacementWriter": func(v *app.SourceWork) {
			copy := *v.StopSnapshot
			copy.WriterEpoch = base.AttemptID
			v.StopSnapshot = &copy
		},
		"mixedStopSource":        func(v *app.SourceWork) { v.Stop = true },
		"mixedArm":               func(v *app.SourceWork) { v.Source = arm.Source },
		"renewedControlDeadline": func(v *app.SourceWork) { v.NotAfter = v.StopIssuedAt.Add(5*time.Second + time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			v := w
			change(&v)
			if _, err := signatures.SignSourceWork(t.Context(), v); err == nil {
				t.Fatal("invalid restrictive cancellation signed")
			}
		})
	}
}
