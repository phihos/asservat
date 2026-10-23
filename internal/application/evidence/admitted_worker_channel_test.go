package evidence

import (
	"context"
	"testing"
	"time"

	value "asservat.local/asservat/internal/domain/authorization"
)

// SQL, token attestation and signing are explicit component fakes. The real
// handler/coordinator must use admitted identity without a live human request;
// actual provider and transaction fences are qualified separately.
type admittedBindingsFunc func(context.Context, value.AcquisitionParent, string) (value.AcquisitionWorkerIdentity, error)

func (f admittedBindingsFunc) ReadAcquisitionEnrollment(ctx context.Context, parent value.AcquisitionParent, worker string) (value.AcquisitionWorkerIdentity, error) {
	return f(ctx, parent, worker)
}

func admittedChannelFixture(t *testing.T) (*workerLifecycleFixture, *AdmittedWorkerEnrollment) {
	t.Helper()
	f, _, service, _ := newWorkerLifecycleFixture(t)
	service.Authority, service.CurrentAuthority = nil, nil
	s := &AdmittedWorkerEnrollment{InstallationID: f.w.Binding.InstallationID, Download: service, Now: f.Now}
	s.Bindings = admittedBindingsFunc(func(ctx context.Context, p value.AcquisitionParent, w string) (value.AcquisitionWorkerIdentity, error) {
		err := f.step(ctx, "admitted-identity")
		return value.AcquisitionWorkerIdentity{Worker: f.w.Acquisition(), ObservedAt: f.Now(), FreshUntil: f.Now().Add(5 * time.Second)}, err
	})
	s.DownloadProofs = func(tokens DownloadPeerToken) (WorkerEnrollmentProofReader, error) {
		b, err := tokens.ReadDownloadPeerToken(context.Background())
		defer clear(b)
		if err != nil || string(b) != "pod-token" {
			t.Fatal("worker token was replaced", err)
		}
		return f, nil
	}
	return f, s
}

func TestAdmittedEnrollmentOutlivesOriginalHumanObservation(t *testing.T) {
	f, s := admittedChannelFixture(t)
	f.now = f.a.ValidUntil.Add(time.Second)
	if f.a.Valid(f.now) || !f.w.Valid() {
		t.Fatal("fixture must retain admission after human observation expiry")
	}
	parent := f.w.Intent.Acquisition().Parent
	until := time.Now().Add(20 * time.Second)
	ctx, stop := context.WithDeadline(context.Background(), until)
	defer stop()
	var retained DownloadPeerToken
	factory := s.DownloadProofs
	s.DownloadProofs = func(token DownloadPeerToken) (WorkerEnrollmentProofReader, error) {
		retained = token
		return factory(token)
	}
	token := []byte("pod-token")
	d, err := s.BeginAcquisitionEnrollment(ctx, s.InstallationID, parent, f.w.Intent.ID, token, []byte("same-process-csr"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if d.Certificate().Peer.Role != "acquisition" || f.count("authority") != 0 || f.count("proof") != 1 || f.count("admitted-identity") != 2 || f.count("sign") != 1 {
		t.Fatal("admitted identity did not own enrollment", f.calls)
	}
	if deadline, ok := d.Context().Deadline(); !ok || !deadline.Equal(f.Now().Add(5*time.Second)) {
		t.Fatal("delivery renewed final original identity cutoff", deadline)
	}
	if string(token) != "pod-token" {
		t.Fatal("caller token buffer mutated")
	}
	if b, err := retained.ReadDownloadPeerToken(ctx); err == nil {
		for _, v := range b {
			if v != 0 {
				t.Fatal("retained private token not cleared")
			}
		}
		clear(b)
	}
	d.Close()
	if d.Context().Err() == nil {
		t.Fatal("delivery close left request alive")
	}
}

func TestAdmittedEnrollmentRejectsChangedFinalIdentity(t *testing.T) {
	f, s := admittedChannelFixture(t)
	original := s.Bindings
	calls := 0
	s.Bindings = admittedBindingsFunc(func(ctx context.Context, p value.AcquisitionParent, w string) (value.AcquisitionWorkerIdentity, error) {
		result, err := original.ReadAcquisitionEnrollment(ctx, p, w)
		calls++
		if calls == 2 {
			result.Worker.Binding.PodUID = "22222222-2222-4222-8222-222222222222"
		}
		return result, err
	})
	if d, err := s.BeginAcquisitionEnrollment(context.Background(), s.InstallationID, f.w.Intent.Acquisition().Parent, f.w.Intent.ID, []byte("pod-token"), []byte("same-process-csr")); err == nil || d != nil {
		t.Fatal("replacement Pod received original certificate")
	}
	if f.count("sign") != 1 || calls != 2 {
		t.Fatal("did not reach final identity boundary", f.calls)
	}
}

func TestAdmittedEnrollmentJoinsOriginalCancellation(t *testing.T) {
	for _, phase := range []string{"admitted-identity", "proof", "claim-enrollment", "sign", "activate"} {
		t.Run(phase, func(t *testing.T) {
			f, s := admittedChannelFixture(t)
			until := time.Now().Add(time.Second)
			ctx, cancel := context.WithDeadline(context.Background(), until)
			defer cancel()
			entered := make(chan struct{})
			f.hooks[phase] = func() { close(entered); <-ctx.Done() }
			done := make(chan struct{})
			go func() {
				defer close(done)
				d, err := s.BeginAcquisitionEnrollment(ctx, s.InstallationID, f.w.Intent.Acquisition().Parent, f.w.Intent.ID, []byte("pod-token"), []byte("same-process-csr"))
				if err == nil || d != nil {
					t.Error("canceled enrollment returned delivery")
				}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("blocking stage not reached")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("enrollment did not join canceled dependency")
			}
			if f.calls[len(f.calls)-1] != phase {
				t.Fatal("new effect after cancellation", f.calls)
			}
			if !f.deadlines[phase].Equal(until) {
				t.Fatal("original shorter HTTP lifetime changed", f.deadlines[phase])
			}
		})
	}
}
