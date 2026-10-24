package mtls

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	app "asservat.local/asservat/internal/application/fleet"
	execution "asservat.local/asservat/internal/domain/execution"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"golang.org/x/time/rate"
)

type contextStartMeteredSource struct {
	source  app.ConnectorIdentitySourceReader
	limiter *rate.Limiter
	reads   atomic.Int32
}

func (s *contextStartMeteredSource) ReadConnectorIdentitySource(ctx context.Context) (value.ConnectorIdentitySource, error) {
	s.reads.Add(1)
	// Native43's source reader makes approximately fifteen observer calls.
	// This is an explicit limiter model, not native API qualification.
	for range 15 {
		if err := s.limiter.Wait(ctx); err != nil {
			return value.ConnectorIdentitySource{}, err
		}
	}
	return s.source.ReadConnectorIdentitySource(ctx)
}

type contextStartCombinedProcessFixture struct {
	credentials *ConnectorProcessCredentials
	process     contextStartAPIProcess
	limiter     *rate.Limiter
}

func (p *contextStartCombinedProcessFixture) ReadAPIProcess(ctx context.Context) (execution.APIProcessObservation, error) {
	observed, _, err := p.ReadAPIProcessConnector(ctx, p.credentials)
	return observed, err
}

func (p *contextStartCombinedProcessFixture) ReadAPIProcessConnector(ctx context.Context, credentials *ConnectorProcessCredentials) (execution.APIProcessObservation, ConnectorProcessObservation, error) {
	if credentials != p.credentials {
		return execution.APIProcessObservation{}, ConnectorProcessObservation{}, value.ErrDenied
	}
	owned, err := credentials.ObserveConnectorProcess(ctx)
	if err != nil {
		return execution.APIProcessObservation{}, ConnectorProcessObservation{}, err
	}
	// The thirteen local current checks from ADR-173 are represented only by
	// their existing observer limiter cost. Authority itself stays synthetic.
	for range 13 {
		if err = p.limiter.Wait(ctx); err != nil {
			return execution.APIProcessObservation{}, ConnectorProcessObservation{}, err
		}
	}
	observed, err := p.process(ctx)
	observed.ValidUntil = identity.Earlier(observed.ValidUntil, owned.ValidUntil)
	return observed, owned, err
}

func TestContextStartLocalUsesTheConnectorAlreadyProvedByItsExecutor(t *testing.T) {
	f := newContextStartTLSFixture(t)
	limiter := rate.NewLimiter(20, 20)
	source := &contextStartMeteredSource{source: f.connector, limiter: limiter}
	f.credential.source = source
	f.client.process = &contextStartCombinedProcessFixture{credentials: f.credential, process: f.api, limiter: limiter}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	original, _ := ctx.Deadline()
	observed, executor, until, err := f.client.local(ctx, nil)
	if err != nil || !executor.Valid() || observed.Request.Process != observed.Registration.Process {
		t.Fatal("duplicate connector observations exhausted the original local interval", err)
	}
	if source.reads.Load() != 2 || until.After(original) || until.After(observed.ValidUntil) {
		t.Fatal("local proof repeated source work or renewed its original bounds", source.reads.Load())
	}
}
