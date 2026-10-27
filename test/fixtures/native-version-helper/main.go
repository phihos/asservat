//go:build ignore

// native-version-helper is a finite synthetic test subprocess, never a product
// command. The same fixture file is compiled against each actual production
// worktree; it contains no copied old/new authorization or protocol predicates.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"time"

	"asservat.local/asservat/internal/adapters/mtls"
	"asservat.local/asservat/internal/adapters/postgres"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	native "asservat.local/asservat/internal/transport/native"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maxInput = 256 << 10

var productionRevision string

type input struct {
	Action                         string
	Postgres                       string
	SQLRoots                       []byte
	SQLServerName                  string
	SQLMinimumVersion              uint16
	Root, Installation             string
	TopologySource                 privacy.PolicySourceRef
	Profile                        value.DownloadWorkerProfile
	Enrollment                     value.WorkerEnrollment
	Authority                      artifact.DownloadAuthority
	Operation                      value.NativeOperation
	Peer                           value.KeyPeer
	Endpoint                       string
	Roots, Certificate, PrivateKey []byte
	Hello                          contracts.NativeHello
	Worker                         value.WorkerCredentialTarget
	WorkerKey                      artifact.Digest
	Source                         evidence.NativeContextSource
	Warmup                         *value.NativeOperation
	BodyBytes                      int
}
type output struct {
	Format, ProductionRevision, Stage, ErrorClass string
	CompiledSchema                                int64
	Accepted, HasRenewer                          bool
	OperationSHA256                               string
	Sequence                                      int64
	Until                                         time.Time
	NativeState                                   contracts.NativeConversationState
	ReaderCalls, DataFrames, DataBytes            int64
}

func hashOperation(o value.NativeOperation) string {
	b, _ := json.Marshal(o)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func class(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, artifact.ErrInvalid):
		return "invalid"
	case errors.Is(err, artifact.ErrDownloadExpired), errors.Is(err, context.DeadlineExceeded):
		return "expired"
	case errors.Is(err, artifact.ErrDownloadUnavailable):
		return "unavailable"
	case errors.Is(err, contracts.ErrNativeProtocol):
		return "protocol"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	default:
		return "other"
	}
}
func main() {
	out := output{Format: "native-version-helper/v1", ProductionRevision: productionRevision, CompiledSchema: postgres.CompiledSchemaVersion, Stage: "input", ErrorClass: "invalid"}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxInput+1))
	if err != nil || len(raw) > maxInput {
		emit(out, 2)
	}
	var in input
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&in)
	clear(raw)
	if err != nil || decoder.Decode(new(any)) != io.EOF {
		emit(out, 2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if in.Action == "worker" {
		out = worker(ctx, in, out)
	} else {
		out = owner(ctx, in, out)
	}
	emit(out, 0)
}
func emit(out output, code int) { _ = json.NewEncoder(os.Stdout).Encode(out); os.Exit(code) }

type topology struct {
	root   string
	source privacy.PolicySourceRef
}

func (t topology) RetentionTopology(_ context.Context, cluster string) (privacy.PolicyTopology, error) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return privacy.PolicyTopology{RootID: t.root, TargetClusterID: cluster, Revision: identity.Revision{UID: "topology", Generation: 1, Digest: artifact.Digest{42}}, Sources: []privacy.PolicySourceRef{t.source}, ObservedAt: now, FreshUntil: now.Add(5 * time.Second)}, nil
}

type renewer interface {
	RenewNativeOperation(context.Context, value.NativeReference, artifact.DownloadAuthority, value.KeyPeer) (value.NativeLease, error)
}

func postgresConfig(in input) (*pgxpool.Config, error) {
	config, err := pgxpool.ParseConfig(in.Postgres)
	if err != nil || config.ConnConfig.User != "native_owner_runtime" || config.ConnConfig.Database != "custody_test" || in.SQLServerName == "" || in.SQLMinimumVersion < tls.VersionTLS12 {
		return nil, artifact.ErrInvalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(in.SQLRoots) {
		return nil, artifact.ErrInvalid
	}
	config.ConnConfig.TLSConfig = &tls.Config{RootCAs: roots, ServerName: in.SQLServerName, MinVersion: in.SQLMinimumVersion}
	config.ConnConfig.Fallbacks = nil
	return config, nil
}

func owner(ctx context.Context, in input, out output) output {
	switch in.Action {
	case "claim", "observe", "renew", "release":
	default:
		return out
	}
	out.Stage = "pool"
	config, err := postgresConfig(in)
	if err != nil {
		return out
	}
	config.MaxConns = 1
	config.MinConns = 0
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return out
	}
	defer pool.Close()
	out.Stage = "guards"
	retention, err := postgres.NewRetentionTransactionGuard(in.Root, topology{in.Root, in.TopologySource})
	if err != nil {
		return out
	}
	recovery, err := postgres.NewRecoveryTransactionGuard(in.Root, in.Installation)
	if err != nil {
		return out
	}
	out.Stage = "owner-constructor"
	owners, err := postgres.NewNativeOwners(ctx, pool, in.Root, in.Profile, postgres.DownloadTransactionGuards{Retention: retention, Recovery: recovery})
	if err != nil {
		out.ErrorClass = class(err)
		return out
	}
	r, ok := any(owners).(renewer)
	out.HasRenewer = ok
	out.Stage = in.Action
	var operation value.NativeOperation
	var lease value.NativeLease
	switch in.Action {
	case "claim":
		operation, err = owners.ClaimNativeOperation(ctx, in.Enrollment, in.Authority, in.Operation)
	case "observe":
		lease, err = owners.ObserveNativeOperation(ctx, in.Operation.Reference, in.Peer)
		operation = lease.Operation
	case "renew":
		if !ok {
			out.Stage = "renew-unimplemented"
			out.ErrorClass = "unavailable"
			return out
		}
		lease, err = r.RenewNativeOperation(ctx, in.Operation.Reference, in.Authority, in.Peer)
		operation = lease.Operation
	case "release":
		err = owners.ReleaseNativeOperation(ctx, in.Operation)
		operation = in.Operation
	}
	out.ErrorClass = class(err)
	out.Accepted = err == nil
	if err == nil {
		out.OperationSHA256 = hashOperation(operation)
		out.Sequence = lease.Sequence
		out.Until = lease.Until
	}
	return out
}

type reader struct {
	bytes int
	calls int64
}

func (r *reader) body() []byte {
	b := make([]byte, r.bytes)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}
func (r *reader) ReadNativeContext(context.Context, evidence.NativeContextSource, value.NativeOperation, string, time.Time) ([]byte, error) {
	r.calls++
	return r.body(), nil
}
func (r *reader) OpenNativeArtifact(_ context.Context, source evidence.NativeContextSource, _ value.NativeOperation, _ string, _ time.Time) (evidence.NativeArtifactSource, error) {
	r.calls++
	body := r.body()
	kind := source.Expectation.Type()
	metadata := artifact.NativeDownloadMetadata{Filename: kind.Filename(source.Expectation.Registration.Location.ArtifactID), Format: kind.Format, ETag: evidence.NativeETag(evidence.ContextCopiesDigest(source.Copies)), Coverage: kind.CoverageFor(source.Expectation.Lifecycle), Size: int64(len(body)), SHA256: sha256.Sum256(body), ReadUntil: source.Expectation.Registration.ExpiresAt, DeleteBy: source.Expectation.Registration.DeleteBy}
	return &framed{body: body, metadata: metadata}, nil
}

type framed struct {
	body     []byte
	metadata artifact.NativeDownloadMetadata
	next     int64
	started  bool
}

func (f *framed) Metadata() artifact.NativeDownloadMetadata { return f.metadata }
func (f *framed) ReadNext(ctx context.Context, offset, length int64) ([]byte, bool, error) {
	if ctx.Err() != nil || offset < 0 || length < 1 || offset > int64(len(f.body)) || length > int64(len(f.body))-offset || f.started && offset != f.next {
		return nil, false, artifact.ErrDownloadUnavailable
	}
	f.started = true
	f.next = offset + length
	return append([]byte(nil), f.body[offset:f.next]...), true, nil
}
func (f *framed) Close() { clear(f.body); f.body = nil }

type countedStream struct {
	*mtls.NativeClientStream
	frames, bytes int64
}

func (s *countedStream) Send(ctx context.Context, f contracts.NativeFrame) error {
	err := s.NativeClientStream.Send(ctx, f)
	if err == nil && f.Kind == contracts.NativeDataFrame {
		s.frames++
		s.bytes += int64(len(f.Payload))
	}
	return err
}
func worker(ctx context.Context, in input, out output) output {
	if in.BodyBytes < 1 || in.BodyBytes > 2*int(artifact.DeliveryBytes)+17 {
		return out
	}
	out.Stage = "tls"
	endpoint, err := url.Parse(in.Endpoint)
	if err != nil || !net.ParseIP(endpoint.Hostname()).IsLoopback() {
		return out
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(in.Roots) {
		return out
	}
	certificate, err := tls.X509KeyPair(in.Certificate, in.PrivateKey)
	if err != nil {
		return out
	}
	client, err := mtls.NewNativeClient(in.Endpoint, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{certificate}})
	if err != nil {
		return out
	}
	source := &reader{bytes: in.BodyBytes}
	out.Stage = "result"
	result, err := evidence.NewRegionalContextResult(ctx, in.Worker, source, time.Now)
	if err != nil {
		return out
	}
	defer func() { result.Close(); _ = result.Wait(context.Background()) }()
	if in.Warmup != nil {
		out.Stage = "warmup"
		call, stop := context.WithDeadline(ctx, in.Warmup.Until)
		_, err = result.Prepare(call, *in.Warmup, in.Source)
		if err == nil {
			err = result.Commit(call, *in.Warmup)
		}
		stop()
		if err != nil {
			out.ErrorClass = class(err)
			out.ReaderCalls = source.calls
			return out
		}
	}
	out.Stage = "open"
	stream, err := client.Open(ctx, in.Hello)
	if err != nil {
		out.ErrorClass = class(err)
		out.ReaderCalls = source.calls
		return out
	}
	counted := &countedStream{NativeClientStream: stream}
	defer counted.Close()
	out.Stage = "conversation"
	disposition, err := native.RunWorkerConversation(ctx, counted, in.Hello, in.Worker, in.WorkerKey, result)
	out.NativeState = disposition.State
	out.Accepted = err == nil && disposition.State == contracts.NativeJoined
	out.ErrorClass = class(err)
	out.ReaderCalls = source.calls
	out.DataFrames = counted.frames
	out.DataBytes = counted.bytes
	return out
}
