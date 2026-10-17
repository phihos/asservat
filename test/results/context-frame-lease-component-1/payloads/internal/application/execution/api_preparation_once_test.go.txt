package execution

import (
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/execution"
	"context"
	"errors"
	"testing"
	"time"
)

type pausedAPIProducer struct {
	inner   evidence.ContextProducer
	entered chan struct{}
	release chan struct{}
}

func (p pausedAPIProducer) PrepareContext(ctx context.Context, e artifact.ContextExpectation) (evidence.PreparedContext, error) {
	h, err := p.inner.PrepareContext(ctx, e)
	select {
	case p.entered <- struct{}{}:
	default:
	}
	if err != nil {
		return h, err
	}
	select {
	case <-ctx.Done():
		h.Close()
		return nil, ctx.Err()
	case <-p.release:
		return h, nil
	}
}
func TestAPIContextConcurrentPreparedReplayNeverCreatesSecondKeys(t *testing.T) {
	f, s, current := apiRunner(t)
	p := pausedAPIProducer{inner: f, entered: make(chan struct{}, 2), release: make(chan struct{})}
	s.Output = p
	done := make(chan error, 1)
	go func() { _, err := s.Execute(context.Background(), current, f.work.Accepted.CaptureID); done <- err }()
	select {
	case <-p.entered:
	case <-time.After(time.Second):
		t.Fatal("first preparation did not begin")
	}
	// Existing prepared state is ambiguous: it must neither wait by issuing keys
	// nor be reported as a positively recorded acquisition.
	second := make(chan error, 1)
	go func() { _, err := s.Execute(context.Background(), current, f.work.Accepted.CaptureID); second <- err }()
	received := false
	select {
	case err := <-second:
		received = true
		if !errors.Is(err, value.ErrPreparationUncertain) {
			t.Error("prepared replay not classified uncertain", err)
		}
	case <-p.entered:
		t.Error("second invocation generated keys")
	case <-time.After(time.Second):
		t.Error("prepared replay blocked in key provider")
	}
	close(p.release)
	if err := <-done; err != nil {
		t.Error("original preparation failed", err)
	}
	if !received {
		<-second
	}
	if f.prepares.Load() != 1 || f.captures.Load() != 1 || f.stores.Load() != 1 || f.closes.Load() != 1 {
		t.Fatal("not exactly one original key/acquisition effect", f.prepares.Load(), f.captures.Load())
	}
}
func TestAPIContextUnknownPreparationReplyDoesNotCreateKeysOnRetry(t *testing.T) {
	f, s, current := apiRunner(t)
	f.mode = "lost-preparation-reply"
	if _, err := s.Execute(context.Background(), current, f.work.Accepted.CaptureID); err == nil {
		t.Fatal("fixture did not lose preparation reply")
	}
	binding := f.record.Binding
	f.mode = ""
	out, err := s.Execute(context.Background(), current, f.work.Accepted.CaptureID)
	if !errors.Is(err, value.ErrPreparationUncertain) || out.State != "Indeterminate" || f.prepares.Load() != 0 || f.captures.Load() != 0 || f.record.Binding != binding {
		t.Fatal("unknown preparation recreated keys/interval", out.State, err)
	}
}

type blockedPreparationReply struct{ *apiRunnerFixture }

func (f blockedPreparationReply) PrepareAPIExecution(ctx context.Context, c APIExecutionCheck) (value.APIExecution, bool, error) {
	r, fresh, err := f.apiRunnerFixture.PrepareAPIExecution(ctx, c)
	if err != nil {
		return r, fresh, err
	}
	r.Binding.NotAfter = time.Now().UTC().Truncate(time.Microsecond).Add(25 * time.Millisecond)
	if !r.Valid() {
		panic("invalid bounded preparation fixture")
	}
	// A positively committed row can reach its caller only after its shorter
	// interval expired. This is not a fresh preparation or a provider retry grant.
	timer := time.NewTimer(time.Until(r.Binding.NotAfter.Add(time.Millisecond)))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return value.APIExecution{}, false, ctx.Err()
	case <-timer.C:
	}
	return r, fresh, nil
}
func TestAPIContextOriginalPreparationIntervalExpiresBeforeKeys(t *testing.T) {
	f, s, current := apiRunner(t)
	s.Prepare = blockedPreparationReply{f}
	_, err := s.Execute(context.Background(), current, f.work.Accepted.CaptureID)
	if err == nil || f.prepares.Load() != 0 || f.captures.Load() != 0 {
		t.Fatal("expired original preparation reached key provider", err, f.prepares.Load(), f.captures.Load())
	}
}
