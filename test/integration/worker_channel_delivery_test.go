package integration

import (
	"asservat.local/asservat/internal/application/evidence"
	value "asservat.local/asservat/internal/domain/authorization"
	"context"
	"sync"
	"time"
)

type fixtureWorkerIssuance interface {
	EnrollWorker(context.Context, string, string, string, []byte, []byte) (value.WorkerCertificate, error)
}
type fixtureWorkerDelivery struct {
	ctx    context.Context
	cancel context.CancelFunc
	cert   value.WorkerCertificate
	once   sync.Once
}

func (d *fixtureWorkerDelivery) Context() context.Context             { return d.ctx }
func (d *fixtureWorkerDelivery) Certificate() value.WorkerCertificate { return d.cert }
func (d *fixtureWorkerDelivery) Close()                               { d.once.Do(d.cancel) }
func fixtureWorkerBegin(ctx context.Context, issuer fixtureWorkerIssuance, installation, session, worker string, token, csr []byte) (evidence.WorkerEnrollmentDelivery, error) {
	call, cancel := context.WithTimeout(ctx, 30*time.Second)
	c, err := issuer.EnrollWorker(call, installation, session, worker, token, csr)
	if err != nil {
		cancel()
		return nil, err
	}
	return &fixtureWorkerDelivery{ctx: call, cancel: cancel, cert: c}, nil
}
func (f *workerChannelFixture) BeginWorkerEnrollment(ctx context.Context, installation, session, worker string, token, csr []byte) (evidence.WorkerEnrollmentDelivery, error) {
	return fixtureWorkerBegin(ctx, f, installation, session, worker, token, csr)
}
func (f *actualWorkerEnrollmentExchange) BeginWorkerEnrollment(ctx context.Context, installation, session, worker string, token, csr []byte) (evidence.WorkerEnrollmentDelivery, error) {
	return fixtureWorkerBegin(ctx, f, installation, session, worker, token, csr)
}
