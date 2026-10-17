package integration

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/evidence"
	identities "asservat.local/asservat/internal/application/identity"
	privacyapp "asservat.local/asservat/internal/application/privacy"
	"asservat.local/asservat/internal/domain/artifact"
	auditvalue "asservat.local/asservat/internal/domain/audit"
	value "asservat.local/asservat/internal/domain/authorization"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type journeyDownloadPrivateError struct{}

func (*journeyDownloadPrivateError) Error() string { panic("private error text must not be read") }

type journeyDownloadWrappedError struct{ inner error }

func (*journeyDownloadWrappedError) Error() string   { panic("private wrapped text must not be read") }
func (e *journeyDownloadWrappedError) Unwrap() error { return e.inner }

type journeyDownloadProbe struct {
	wantName string
	wantArgs []any
	calls    int
	err      error
	delivery evidence.WorkerEnrollmentDelivery
}

func (f *journeyDownloadProbe) accept(name string, args ...any) {
	if name != f.wantName || !reflect.DeepEqual(args, f.wantArgs) {
		panic("original enrollment arguments changed")
	}
	f.calls++
}

type journeyDownloadDelivery struct {
	ctx    context.Context
	closed int
}

func (d *journeyDownloadDelivery) Context() context.Context { return d.ctx }
func (*journeyDownloadDelivery) Certificate() value.WorkerCertificate {
	return value.WorkerCertificate{DER: []byte{42}}
}
func (d *journeyDownloadDelivery) Close() { d.closed++ }
func (f *journeyDownloadProbe) BeginWorkerEnrollment(c context.Context, i, s, w string, token, csr []byte) (evidence.WorkerEnrollmentDelivery, error) {
	f.accept("BeginWorkerEnrollment", c, i, s, w, token, csr)
	return f.delivery, f.err
}
func (f *journeyDownloadProbe) CheckDownloadCurrent(c context.Context, i identities.CurrentIdentity, s artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	f.accept("CheckDownloadCurrent", c, i, s)
	return artifact.DownloadAuthority{Scope: artifact.DownloadScope{RootID: "original-root"}}, f.err
}
func (f *journeyDownloadProbe) ReadWorkerEnrollmentProof(c context.Context, s, w string, k artifact.Digest) (value.WorkerEnrollmentProof, error) {
	f.accept("ReadWorkerEnrollmentProof", c, s, w, k)
	return value.WorkerEnrollmentProof{PublicKeyDigest: artifact.Digest{4}}, f.err
}
func (f *journeyDownloadProbe) ClaimWorkerEnrollment(c context.Context, p value.WorkerEnrollmentProof, a artifact.DownloadAuthority) (value.WorkerEnrollment, auditvalue.Receipt, bool, error) {
	f.accept("ClaimWorkerEnrollment", c, p, a)
	return value.WorkerEnrollment{PublicKeyDigest: artifact.Digest{5}}, auditvalue.Receipt{}, true, f.err
}
func (f *journeyDownloadProbe) PrepareWorkerCertificate(c context.Context, p value.WorkerEnrollmentProof, a artifact.DownloadAuthority) (value.WorkerCertificateProgress, error) {
	f.accept("PrepareWorkerCertificate", c, p, a)
	return value.WorkerCertificateProgress{MaySign: true}, f.err
}
func (f *journeyDownloadProbe) StoreWorkerCertificate(c context.Context, a value.WorkerCertificateAttempt, v value.WorkerCertificate, p artifact.DownloadAuthority) error {
	f.accept("StoreWorkerCertificate", c, a, v, p)
	return f.err
}
func (f *journeyDownloadProbe) WriteWorkerEnrollment(c context.Context, v value.WorkerEnrollment) (auditvalue.Receipt, error) {
	f.accept("WriteWorkerEnrollment", c, v)
	return auditvalue.Receipt{}, f.err
}
func (f *journeyDownloadProbe) WriteWorkerCertificate(c context.Context, v auditvalue.WorkerCertificate) (auditvalue.Receipt, error) {
	f.accept("WriteWorkerCertificate", c, v)
	return auditvalue.Receipt{}, f.err
}
func (f *journeyDownloadProbe) AcknowledgeWorkerEnrollment(c context.Context, v value.WorkerEnrollment, r auditvalue.Receipt) error {
	f.accept("AcknowledgeWorkerEnrollment", c, v, r)
	return f.err
}
func (f *journeyDownloadProbe) ReadWorkerCertificateReceipt(c context.Context, v auditvalue.WorkerCertificate) (auditvalue.Receipt, bool, error) {
	f.accept("ReadWorkerCertificateReceipt", c, v)
	return auditvalue.Receipt{}, true, f.err
}
func (f *journeyDownloadProbe) AcknowledgeWorkerCertificate(c context.Context, v auditvalue.WorkerCertificate, r auditvalue.Receipt) error {
	f.accept("AcknowledgeWorkerCertificate", c, v, r)
	return f.err
}
func (f *journeyDownloadProbe) SignWorkerCertificate(c context.Context, a value.WorkerCertificateAttempt, csr []byte) (value.WorkerCertificate, error) {
	f.accept("SignWorkerCertificate", c, a, csr)
	return value.WorkerCertificate{DER: []byte{11}}, f.err
}
func (f *journeyDownloadProbe) ActivateWorkerCertificate(c context.Context, p value.WorkerEnrollmentProof, a value.WorkerCertificateAttempt, v artifact.DownloadAuthority) (value.WorkerCertificate, error) {
	f.accept("ActivateWorkerCertificate", c, p, a, v)
	return value.WorkerCertificate{DER: []byte{12}}, f.err
}
func (f *journeyDownloadProbe) EnrollmentKey(csr []byte) (artifact.Digest, error) {
	f.accept("EnrollmentKey", csr)
	return artifact.Digest{13}, f.err
}
func (f *journeyDownloadProbe) CheckDownload(c context.Context, credential string, s artifact.DownloadScope) (artifact.DownloadAuthority, error) {
	f.accept("CheckDownload", c, credential, s)
	return artifact.DownloadAuthority{Scope: artifact.DownloadScope{RootID: "legacy-root"}}, f.err
}

func TestPublicJourneyDownloadDiagnosticsOriginalFacets(t *testing.T) {
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), struct{}{}, "private-context"))
	defer cancel()
	private := &journeyDownloadPrivateError{}
	source := identities.CurrentIdentity(nil)
	scope := artifact.DownloadScope{RootID: "original-scope"}
	proof := value.WorkerEnrollmentProof{PublicKeyDigest: artifact.Digest{31}}
	auth := artifact.DownloadAuthority{Scope: scope}
	en := value.WorkerEnrollment{PublicKeyDigest: artifact.Digest{32}}
	attempt := value.WorkerCertificateAttempt{}
	cert := value.WorkerCertificate{DER: []byte("private-original-certificate")}
	signed := auditvalue.WorkerCertificate{Attempt: attempt}
	receipt := auditvalue.Receipt{}
	csr, token := []byte("private-original-csr"), []byte("private-original-token")
	delivery := &journeyDownloadDelivery{ctx: ctx}
	cases := []struct {
		name  string
		stage int
		args  []any
		call  func(journeyEnrollmentPorts) ([]any, error)
		want  []any
	}{
		{"BeginWorkerEnrollment", 0, []any{ctx, "installation", "session", "worker", token, csr}, func(p journeyEnrollmentPorts) ([]any, error) {
			v, e := p.BeginWorkerEnrollment(ctx, "installation", "session", "worker", token, csr)
			return []any{v}, e
		}, []any{delivery}},
		{"CheckDownloadCurrent", 1, []any{ctx, source, scope}, func(p journeyEnrollmentPorts) ([]any, error) {
			v, e := p.CheckDownloadCurrent(ctx, source, scope)
			return []any{v}, e
		}, []any{artifact.DownloadAuthority{Scope: artifact.DownloadScope{RootID: "original-root"}}}},
		{"ReadWorkerEnrollmentProof", 2, []any{ctx, "session", "worker", artifact.Digest{3}}, func(p journeyEnrollmentPorts) ([]any, error) {
			v, e := p.ReadWorkerEnrollmentProof(ctx, "session", "worker", artifact.Digest{3})
			return []any{v}, e
		}, []any{value.WorkerEnrollmentProof{PublicKeyDigest: artifact.Digest{4}}}},
		{"ClaimWorkerEnrollment", 3, []any{ctx, proof, auth}, func(p journeyEnrollmentPorts) ([]any, error) {
			v, r, b, e := p.ClaimWorkerEnrollment(ctx, proof, auth)
			return []any{v, r, b}, e
		}, []any{value.WorkerEnrollment{PublicKeyDigest: artifact.Digest{5}}, receipt, true}},
		{"PrepareWorkerCertificate", 4, []any{ctx, proof, auth}, func(p journeyEnrollmentPorts) ([]any, error) {
			v, e := p.PrepareWorkerCertificate(ctx, proof, auth)
			return []any{v}, e
		}, []any{value.WorkerCertificateProgress{MaySign: true}}},
		{"StoreWorkerCertificate", 5, []any{ctx, attempt, cert, auth}, func(p journeyEnrollmentPorts) ([]any, error) {
			e := p.StoreWorkerCertificate(ctx, attempt, cert, auth)
			return nil, e
		}, nil},
		{"WriteWorkerEnrollment", 6, []any{ctx, en}, func(p journeyEnrollmentPorts) ([]any, error) {
			vout, e := p.WriteWorkerEnrollment(ctx, en)
			return []any{vout}, e
		}, []any{receipt}},
		{"WriteWorkerCertificate", 7, []any{ctx, signed}, func(p journeyEnrollmentPorts) ([]any, error) {
			vout, e := p.WriteWorkerCertificate(ctx, signed)
			return []any{vout}, e
		}, []any{receipt}},
		{"AcknowledgeWorkerEnrollment", 8, []any{ctx, en, receipt}, func(p journeyEnrollmentPorts) ([]any, error) {
			e := p.AcknowledgeWorkerEnrollment(ctx, en, receipt)
			return nil, e
		}, nil},
		{"ReadWorkerCertificateReceipt", 9, []any{ctx, signed}, func(p journeyEnrollmentPorts) ([]any, error) {
			r, b, e := p.ReadWorkerCertificateReceipt(ctx, signed)
			return []any{r, b}, e
		}, []any{receipt, true}},
		{"AcknowledgeWorkerCertificate", 10, []any{ctx, signed, receipt}, func(p journeyEnrollmentPorts) ([]any, error) {
			e := p.AcknowledgeWorkerCertificate(ctx, signed, receipt)
			return nil, e
		}, nil},
		{"SignWorkerCertificate", 11, []any{ctx, attempt, csr}, func(p journeyEnrollmentPorts) ([]any, error) {
			v, e := p.SignWorkerCertificate(ctx, attempt, csr)
			return []any{v}, e
		}, []any{value.WorkerCertificate{DER: []byte{11}}}},
		{"ActivateWorkerCertificate", 12, []any{ctx, proof, attempt, auth}, func(p journeyEnrollmentPorts) ([]any, error) {
			out, e := p.ActivateWorkerCertificate(ctx, proof, attempt, auth)
			return []any{out}, e
		}, []any{value.WorkerCertificate{DER: []byte{12}}}},
		{"EnrollmentKey", 13, []any{csr}, func(p journeyEnrollmentPorts) ([]any, error) { v, e := p.EnrollmentKey(csr); return []any{v}, e }, []any{artifact.Digest{13}}},
		{"CheckDownload", 14, []any{ctx, "private-credential", scope}, func(p journeyEnrollmentPorts) ([]any, error) {
			v, e := p.CheckDownload(ctx, "private-credential", scope)
			return []any{v}, e
		}, []any{artifact.DownloadAuthority{Scope: artifact.DownloadScope{RootID: "legacy-root"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &journeyDownloadProbe{wantName: tc.name, wantArgs: tc.args, err: private, delivery: delivery}
			trace := &journeyEnrollmentTrace{}
			p := journeyEnrollmentPorts{f, f, f, f, f, f, f, f, f, f, trace}
			got, err := tc.call(p)
			if err != private || !reflect.DeepEqual(got, tc.want) || f.calls != 1 || trace.calls[tc.stage] != 1 || trace.refusals[tc.stage] != 1 || trace.first != tc.stage+1 || trace.reasons[tc.stage] != 9 {
				t.Fatal("original return, single dispatch or fixed diagnostic changed")
			}
			if delivery.closed != 0 || delivery.Context() != ctx {
				t.Fatal("diagnostic took delivery ownership")
			}
			trace.stopped = true
			tc.call(p)
			if f.calls != 2 || trace.calls[tc.stage] != 1 {
				t.Fatal("stopped diagnostic changed original delegation")
			}
		})
	}
	// A canceled context is still delivered unchanged; the decorator does not
	// introduce an earlier refusal, fresh context, retry, or different error.
	cancel()
	trace := &journeyEnrollmentTrace{}
	f := &journeyDownloadProbe{wantName: "ReadWorkerEnrollmentProof", wantArgs: []any{ctx, "s", "w", artifact.Digest{}}, err: private}
	_, err := (journeyEnrollmentPorts{WorkerEnrollmentProofReader: f, trace: trace}).ReadWorkerEnrollmentProof(ctx, "s", "w", artifact.Digest{})
	if err != private || f.calls != 1 {
		t.Fatal("canceled original dispatch changed")
	}
}
func TestPublicJourneyDownloadDiagnosticsNilAndPrivacy(t *testing.T) {
	trace := &journeyEnrollmentTrace{}
	var empty evidence.WorkerEnrollmentCoordinator
	if !reflect.DeepEqual(trace.Wrap(empty), empty) {
		t.Fatal("nil coordinator capabilities manufactured")
	}
	f := &journeyDownloadProbe{}
	full := evidence.WorkerEnrollmentCoordinator{CSR: f, Proofs: f, Ledger: f, Activation: f, Audit: f, Acknowledgements: f, Issuer: f, Authority: f, CurrentAuthority: f, Now: time.Now}
	wrapped := trace.Wrap(full)
	for _, name := range []string{"CSR", "Proofs", "Ledger", "Activation", "Audit", "Acknowledgements", "Issuer", "Authority", "CurrentAuthority"} {
		in := reflect.ValueOf(&full).Elem()
		copy := reflect.New(in.Type()).Elem()
		copy.Set(in)
		copy.FieldByName(name).Set(reflect.Zero(copy.FieldByName(name).Type()))
		got := trace.Wrap(copy.Interface().(evidence.WorkerEnrollmentCoordinator))
		if !reflect.ValueOf(got).FieldByName(name).IsNil() {
			t.Fatal("absent capability supplied", name)
		}
		if _, ok := reflect.ValueOf(wrapped).FieldByName(name).Interface().(journeyEnrollmentPorts); !ok {
			t.Fatal("facet lost diagnostic", name)
		}
	}
	if reflect.ValueOf(wrapped.Now).Pointer() != reflect.ValueOf(full.Now).Pointer() {
		t.Fatal("original clock changed")
	}
	raw := &journeyDownloadPrivateError{}
	for _, e := range []error{raw, &journeyDownloadWrappedError{raw}} {
		if journeyDownloadReason(e) != 9 || journeyDownloadReasonName(journeyDownloadReason(e)) != "other" {
			t.Fatal("unrecognized private error became public detail")
		}
	}
	trace.record(3, artifact.ErrDownloadExpired)
	trace.record(3, artifact.ErrDownloadConflict)
	trace.record(2, artifact.ErrDownloadUnavailable)
	if trace.first != 4 || trace.reasons[3] != 4 || trace.refusals[3] != 2 || trace.reasons[2] != 3 {
		t.Fatal("first original refusal overwritten")
	}
}

// A traced fixture pool passed the old recorder tests but postgres.New refused
// it before the native journey ran. Exercise that actual constructor boundary.
// No socket is opened and no schema/authority success is fabricated here.
func TestPublicJourneySQLPoolConstructorCompatibility(t *testing.T) {
	for _, traced := range []bool{false, true} {
		name := "original-pool-reaches-schema-read"
		if traced {
			name = "tracer-denied-before-connection"
		}
		t.Run(name, func(t *testing.T) {
			transport := &tls.Config{ServerName: "synthetic.fixture.invalid", MinVersion: tls.VersionTLS13}
			pc, err := captureAdmissionPoolConfig("postgres://synthetic:synthetic@127.0.0.1:1/custody_test?sslmode=disable", transport)
			if err != nil {
				t.Fatal("fixture pool configuration failed")
			}
			if pc.MaxConns != 16 || pc.MinConns != 0 || pc.ConnConfig.TLSConfig != transport || len(pc.ConnConfig.Fallbacks) != 0 || pc.ConnConfig.Tracer != nil {
				t.Fatal("fixture pool configuration changed")
			}
			var calls atomic.Int32
			pc.ConnConfig.DialFunc = func(context.Context, string, string) (net.Conn, error) {
				calls.Add(1)
				return nil, errors.New("synthetic connection unavailable")
			}
			if traced {
				pc.ConnConfig.Tracer = journeyRejectedQueryTracer{}
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			pool, err := pgxpool.NewWithConfig(ctx, pc)
			if err != nil {
				t.Fatal("lazy fixture pool construction failed")
			}
			defer pool.Close()
			ledger, err := postgres.New(ctx, pool)
			if traced {
				if ledger != nil || err != artifact.ErrInvalid || calls.Load() != 0 {
					t.Fatal("traced pool crossed production configuration boundary")
				}
			} else if ledger != nil || err != privacyapp.ErrUnavailable || calls.Load() != 1 {
				t.Fatal("original pool did not reach exactly one controlled schema connection")
			}
		})
	}
}

type journeyRejectedQueryTracer struct{}

func (journeyRejectedQueryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	return ctx
}
func (journeyRejectedQueryTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
