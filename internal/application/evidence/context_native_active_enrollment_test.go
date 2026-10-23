package evidence

import (
	"context"
	"errors"
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
)

// These tests exercise the actual Continue orchestration with synthetic current
// Pod/SQL/identity ports. They stop at an unknown first batch admission; no
// network, provider, key or native conversation success is inferred.
type activePreparationSessions struct {
	*downloadResultFixture
	lookup         *boundWorkerAttachments
	deadline       time.Time
	authorityUntil time.Time
}

func (*activePreparationSessions) FirstContextPreparationOnly() {}
func (s *activePreparationSessions) BeginDownloadBatch(ctx context.Context, id string, a artifact.DownloadAuthority, b artifact.DownloadBatch) (audit.DownloadIntent, error) {
	s.deadline, _ = ctx.Deadline()
	s.authorityUntil = a.ValidUntil
	out, err := s.downloadResultFixture.BeginDownloadBatch(ctx, id, a, b)
	// The synthetic durable ledger retains the spent original batch even when
	// its acknowledgement is lost. A later attachment exposes only that fact.
	if s.downloadResultFixture.s.Requests > 0 {
		s.lookup.value.MetadataAttempted = true
	}
	return out, err
}

// Non-nil purpose facets satisfy the real NativeAttachment constructor. The
// unknown first batch response must prevent every method from being called.
// An unexpected native effect consequently panics instead of silently passing.
type unusedActiveNativePorts struct {
	NativeOperations
	NativeFenceReader
	NativeExchangeRegistrar
	DownloadKeyBindingLedger
	NativeWindowKeyBindings
}

type activeEnrollmentFixture struct {
	boundWorkerFixture
	preparation *activePreparationSessions
}

func newActiveEnrollmentFixture(t *testing.T) *activeEnrollmentFixture {
	t.Helper()
	base := newBoundWorkerFixture(t)
	f := &activeEnrollmentFixture{boundWorkerFixture: base}
	en := f.f.enrollment
	peer := value.KeyPeer{InstallationID: en.Worker.Binding.InstallationID, PeerID: en.Worker.Binding.PodUID, Role: "acquisition", Certificate: artifact.Digest{31}, NotBefore: f.f.now.Add(-time.Second), NotAfter: en.Worker.Intent.RunUntil.UTC().Truncate(time.Second)}
	f.lookup.value.Enrollment, f.lookup.value.ActivatedPeer = &en, &peer
	f.f.lostBeginReply = true
	f.preparation = &activePreparationSessions{downloadResultFixture: f.f, lookup: f.lookup}
	f.r.config.Preparation, f.r.config.Audit, f.r.config.Acknowledgements = f.preparation, f.f, f.f
	ports := &unusedActiveNativePorts{}
	f.r.config.Native = NativeAttachmentConfig{HubPodUID: en.Worker.Binding.PodUID, HubProcessEpoch: en.Worker.Intent.ID, KeyScope: value.KeyScope{InstallationID: en.Worker.Binding.InstallationID, Purpose: "artifact", KeyID: "synthetic"}, Owners: ports, Fences: ports, Origins: NativeOrigins{Operations: ports, Now: f.r.config.Now}, Registrar: ports, PreparationKeys: ports, WindowKeys: ports}
	if !f.lookup.value.Valid(f.f.now) {
		t.Fatal("invalid synthetic activated attachment")
	}
	return f
}

// This is the failing-before regression: ordinary preparation must not depend
// on an unused enrollment-owner claim once the exact current peer is active.
func TestContextRuntimeActiveEnrollmentAvoidsUnusedOwnerClaim(t *testing.T) {
	f := newActiveEnrollmentFixture(t)
	original := f.f.s
	until := f.f.now.Add(400 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), until)
	defer cancel()
	f.launch.hooks["observe-job"] = func() { f.advance(100 * time.Millisecond) }
	out, err := f.r.ContinueContextDownload(ctx, f.f, original, f.source)
	if err == nil || out.Pending || f.f.count("begin") != 1 {
		t.Fatal("already active preparation used enrollment or missed original first batch", out.Pending, f.f.count("begin"), err)
	}
	f.noLaunchEffects(t)
	if f.lookup.reads != 2 || f.launch.count("observe-job") != 1 || f.launch.count("read-enrollment") != 0 {
		t.Fatal("missing current Pod/SQL checks or repeated enrollment", f.lookup.reads, f.launch.calls)
	}
	if !f.preparation.deadline.Equal(until) || !f.preparation.authorityUntil.Equal(until) || !f.f.i.Batch.LeaseUntil.Equal(until) {
		t.Fatal("first batch renewed or lost the original shorter parent bound")
	}
	if f.f.s.Requests != 1 || f.f.s.Generation != 1 || f.f.s.ChargedRead != ContextDownloadReadWork || f.f.s.ChargedOutput != 0 || f.f.s.ReadLimit != original.ReadLimit || f.f.s.OutputLimit != original.OutputLimit || f.f.s.RequestLimit != original.RequestLimit || f.f.s.Deadline != original.Deadline || f.f.s.ID != original.ID {
		t.Fatal("unknown first batch lost spend or changed original session/backing")
	}
	_, err = f.r.ContinueContextDownload(ctx, f.f, original, f.source)
	if !errors.Is(err, ErrDownloadMetadataUnavailable) || f.f.count("begin") != 1 || f.f.count("finish") != 0 || f.f.s.Requests != 1 || f.f.s.ChargedRead != ContextDownloadReadWork {
		t.Fatal("unknown first admission was replayed, repaired or refunded", err)
	}
}

func TestContextRuntimeActiveEnrollmentDeniesChangedCurrentState(t *testing.T) {
	for _, mode := range []string{"revoked-before", "peer-removed", "peer-replaced", "peer-mutated", "key-replaced", "enrollment-removed", "worker-replaced", "busy", "uncertain", "metadata-started", "deadline", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := newActiveEnrollmentFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "revoked-before" {
				f.f.failure = "current-authority"
			}
			f.lookup.before = func(n int) {
				if n != 2 {
					return
				}
				switch mode {
				case "peer-removed":
					f.lookup.value.ActivatedPeer = nil
				case "peer-replaced":
					p := *f.lookup.value.ActivatedPeer
					p.Certificate[0]++
					f.lookup.value.ActivatedPeer = &p
				case "peer-mutated":
					f.lookup.value.ActivatedPeer.Certificate[0]++
				case "key-replaced":
					en := *f.lookup.value.Enrollment
					en.PublicKeyDigest[0]++
					f.lookup.value.Enrollment = &en
				case "enrollment-removed":
					f.lookup.value.Enrollment, f.lookup.value.ActivatedPeer = nil, nil
				case "worker-replaced":
					w := *f.lookup.value.Worker
					w.Binding.PodUID = "10000000-0000-4000-8000-000000000998"
					f.lookup.value.Worker = &w
				case "busy":
					f.lookup.value.NativeBusy = true
				case "uncertain":
					f.lookup.value.NativeUncertain = true
				case "metadata-started":
					f.lookup.value.MetadataAttempted = true
				case "deadline":
					f.advance(6 * time.Second)
				case "cancelled":
					cancel()
				}
			}
			out, err := f.r.ContinueContextDownload(ctx, f.f, f.f.s, f.source)
			if err == nil || out.Pending || f.f.count("begin") != 0 {
				t.Fatal("changed active identity started enrollment or preparation", out.Pending, f.f.count("begin"), err)
			}
			if mode == "revoked-before" && (f.lookup.reads != 0 || f.launch.count("observe-job") != 0) {
				t.Fatal("ordinary deny followed evidence lookup")
			}
		})
	}
}

func TestContextRuntimeIncompleteOrShortPeerReturnsPending(t *testing.T) {
	for _, mode := range []string{"no-enrollment", "no-peer", "short-peer"} {
		t.Run(mode, func(t *testing.T) {
			f := newActiveEnrollmentFixture(t)
			switch mode {
			case "no-enrollment":
				f.lookup.value.Enrollment, f.lookup.value.ActivatedPeer = nil, nil
			case "no-peer":
				f.lookup.value.ActivatedPeer = nil
			case "short-peer":
				p := *f.lookup.value.ActivatedPeer
				p.NotAfter = f.f.now.Add(3 * time.Second)
				f.lookup.value.ActivatedPeer = &p
			}
			out, err := f.r.ContinueContextDownload(context.Background(), f.f, f.f.s, f.source)
			if err != nil || !out.Pending || f.f.count("begin") != 0 || f.lookup.reads != 2 {
				t.Fatal("incomplete independent enrollment did not remain pending", mode, err)
			}
		})
	}
}

func TestActiveContextEnrollmentPreservesOriginalRenewalBoundary(t *testing.T) {
	w := routeTestWorker(t, 1)
	// The epoch calculation keeps this fraction but issued NotAfter drops it.
	// Scheduling must use the actual leaf boundary, including equality.
	w.Intent.CreatedAt = w.Intent.CreatedAt.UTC().Truncate(time.Second).Add(500 * time.Millisecond)
	w.Intent.Authority.CheckedAt = w.Intent.CreatedAt
	w.Intent.Authority.ValidUntil = w.Intent.CreatedAt.Add(5 * time.Second)
	w.Intent.Authority.Environment.ObservedAt = w.Intent.CreatedAt
	w.Intent.Authority.Environment.ValidUntil = w.Intent.Authority.ValidUntil
	w.Intent.Profile.MaxRuntime = 40 * time.Minute
	w.Intent.RunUntil = w.Intent.CreatedAt.Add(40 * time.Minute)
	en := value.WorkerEnrollment{Worker: w, PublicKeyDigest: artifact.Digest{4}, ClaimedAt: w.Intent.CreatedAt}
	_, certEnd, err := value.WorkerCertificateEpoch(w, w.Intent.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	peer := value.KeyPeer{InstallationID: w.Binding.InstallationID, PeerID: w.Binding.PodUID, Role: "acquisition", Certificate: artifact.Digest{5}, NotBefore: w.Intent.CreatedAt.Add(-time.Minute), NotAfter: certEnd}
	boundary := certEnd.Add(-value.WorkerCertificateRenewBefore)
	now := boundary.Add(-4 * time.Second)
	a := ContextDownloadAttachment{SessionID: w.Intent.SessionID, Scope: w.Intent.Authority.Scope, State: artifact.DownloadPreparing, Found: true, Intent: w.Intent, Worker: &w, Enrollment: &en, ActivatedPeer: &peer, ObservedAt: now, ValidUntil: now.Add(5 * time.Second)}
	if !a.Valid(now) {
		t.Fatal("invalid synthetic renewal observation")
	}
	for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		if got := activeContextEnrollment(a, now, boundary.Add(delta)); got != (delta < 0) {
			t.Fatal("renewal boundary changed", delta, got)
		}
	}
	// The final certificate ends at the original worker bound and cannot renew.
	peer.NotAfter = w.Intent.RunUntil.UTC().Truncate(time.Second)
	now = peer.NotAfter.Add(-3 * time.Second)
	a.ObservedAt, a.ValidUntil = now, peer.NotAfter
	if !activeContextEnrollment(a, now, peer.NotAfter) || activeContextEnrollment(a, now, peer.NotAfter.Add(time.Nanosecond)) {
		t.Fatal("final-period exception changed original certificate lifetime")
	}
}

func TestContextRuntimeActiveEnrollmentReusesOneAuthorityObservation(t *testing.T) {
	for _, phase := range []string{"pod", "sql"} {
		t.Run(phase, func(t *testing.T) {
			f := newActiveEnrollmentFixture(t)
			original := f.f.s
			if phase == "pod" {
				f.launch.hooks["observe-job"] = func() { f.f.failure = "current-authority" }
			}
			f.lookup.before = func(n int) {
				if phase == "sql" && n == 2 {
					f.f.failure = "current-authority"
				}
			}
			out, err := f.r.ContinueContextDownload(t.Context(), f.f, original, f.source)
			// This fixture deliberately loses the first SQL batch reply. A bounded
			// observation must reach that unchanged, non-replayable admission once.
			if err == nil || out.Pending || f.f.count("begin") != 1 || f.f.count("current-authority") != 1 {
				t.Fatal("original observation did not reach the existing first preparation", err, f.f.count("begin"), f.f.count("current-authority"))
			}
			f.noLaunchEffects(t)
			reads := f.lookup.reads
			if _, err = f.r.ContinueContextDownload(t.Context(), f.f, original, f.source); err == nil || f.lookup.reads != reads || f.f.count("begin") != 1 {
				t.Fatal("next operation bypassed changed authority or replayed admission", err)
			}
		})
	}
}
