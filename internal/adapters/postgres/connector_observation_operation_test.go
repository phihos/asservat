package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"asservat.local/asservat/internal/adapters/postgres/custodydb"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
)

// Fixed generated-query seam only. It does not execute PL/pgSQL or qualify
// native revocation/lock behavior. The existing real SQL49 fixture remains a
// separate required composition gate.
type operationRegistryFixture struct {
	t             *testing.T
	registry      *ConnectorObservationOperationRegistry
	request       value.OwnerObservationRequest
	prototype     value.ConnectorObservationOperationValue
	calls         []string
	mode          string
	ordinal       int
	queryCalls    int
	queryDeadline time.Time
	lastDeadline  time.Time
}

func newOperationRegistryFixture(t *testing.T) *operationRegistryFixture {
	t.Helper()
	id := "00000000-0000-4000-8000-000000000001"
	now := time.Now().UTC()
	start, end := now.Add(-time.Millisecond), now.Add(3*time.Second)
	b := value.PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: value.ConnectorPeer}
	p := value.ConnectorObservationPin{Profile: value.ConnectorCredentialProfile{RootID: id, Binding: b, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, ServerName: "regional.invalid", ClientIssuerRoots: [][]byte{{1}}, ServerIssuerRoots: [][]byte{{2}}, Deployment: value.ConnectorDeployment{Namespace: "regional", NamespaceUID: id, ServiceAccount: "regional", AccountUID: id, Deployment: "regional", DeploymentUID: id, ServingSlots: 2, RetainedProcesses: 8}}, Roles: value.ConnectorIdentityRoles{Source: "source", Journal: "journal", Acknowledgement: "ack", Cleanup: "cleanup", Verifier: "verifier", Finalizer: "finalizer"}, TemplateDigest: artifact.Digest{3}, ImageDigest: artifact.Digest{4}, ProtectionDigest: artifact.Digest{5}}
	r := value.OwnerObservationRequest{RootID: id, ID: id, Challenge: id, RequestedAt: start, NotAfter: end}
	s := value.ConnectorIdentitySource{Roles: p.Roles, Observation: value.ConnectorCredentialObservation{Profile: p.Profile.Clone(), Backing: value.ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{6}, SourceDigest: artifact.Digest{7}}, ObservedAt: now, FreshUntil: end}}
	w := value.ConnectorObservationWorkload{Process: value.ConnectorProcessIdentity{Binding: b, PodUID: id, ProcessEpoch: id}, Pod: "regional-pod", ReplicaSetUID: id, TemplateDigest: p.TemplateDigest, ImageDigest: p.ImageDigest, ProtectionDigest: p.ProtectionDigest, WorkloadDigest: artifact.Digest{8}, ObservedAt: start, FreshUntil: end}
	v := value.ConnectorObservationOperationValue{Native: value.ConnectorObservationNativeValue{Request: r, Ordinal: 1, Source: s, Workload: w, NativeStartedAt: start, NativeUntil: end, ValueObservedAt: now}, BracketID: id, ConnectionBinding: artifact.Digest{9}, Certificate: value.ConnectorCredentialCertificate{Binding: b, Usage: "client", Digest: artifact.Digest{10}, PublicKeyDigest: artifact.Digest{11}, NotBefore: start, NotAfter: end.Add(time.Minute)}}
	if !v.Matches(p, r, 1, now) {
		t.Fatal("invalid original fixture")
	}
	return &operationRegistryFixture{t: t, registry: &ConnectorObservationOperationRegistry{ledger: &Ledger{}, pin: p.Clone()}, request: r, prototype: v}
}

func (f *operationRegistryFixture) ReadConnectorObservationValue(ctx context.Context, ordinal int) (value.ConnectorObservationOperationValue, error) {
	f.calls = append(f.calls, fmt.Sprintf("source-%d", ordinal))
	f.lastDeadline, _ = ctx.Deadline()
	if ordinal != f.ordinal+1 {
		return value.ConnectorObservationOperationValue{}, value.ErrUnavailable
	}
	f.ordinal = ordinal
	if f.mode == "source-error" {
		return value.ConnectorObservationOperationValue{}, value.ErrUnavailable
	}
	if f.mode == "source-wait" && ordinal%2 == 0 {
		<-ctx.Done()
	}
	v := f.prototype.Clone()
	v.Native.Ordinal, v.Native.Final = ordinal, ordinal == 4
	v.Native.ValueObservedAt = time.Now().UTC()
	v.Native.Source.Observation.ObservedAt = v.Native.ValueObservedAt
	if f.mode == "bad-first" && ordinal == 1 {
		v.BracketID = ""
	}
	if ordinal%2 == 0 {
		switch f.mode {
		case "source-revision":
			v.Native.Source.Observation.Profile.Revision.Generation++
		case "source-roles":
			v.Native.Source.Roles.Source = "different_source"
		case "source-backing":
			v.Native.Source.Observation.Backing.Revision++
		case "source-roots":
			v.Native.Source.Observation.Profile.ClientIssuerRoots[0][0]++
		case "source-channel":
			v.ConnectionBinding[0]++
		case "source-bracket":
			v.BracketID = "00000000-0000-4000-8000-000000000002"
		case "source-process":
			v.Native.Workload.Process.ProcessEpoch = "00000000-0000-4000-8000-000000000002"
		case "early-final":
			v.Native.Final = true
		case "missing-final":
			v.Native.Final = false
		}
	}
	return v, nil
}

func (f *operationRegistryFixture) ReadConnectorActivatedLeaf(ctx context.Context, arg custodydb.ReadConnectorActivatedLeafParams) ([]byte, error) {
	f.queryCalls++
	f.calls = append(f.calls, "sql")
	f.queryDeadline, _ = ctx.Deadline()
	var observed value.ConnectorCredentialObservation
	if json.Unmarshal(arg.SourceValue, &observed) != nil || !observed.SameSource(f.prototype.Native.Source.Observation) || arg.RootID != id(f.request.RootID) || arg.PeerID != id(f.registry.pin.Profile.Binding.PeerID) || arg.UsageValue != "client" || !reflect.DeepEqual(arg.DigestValue, f.prototype.Certificate.Digest[:]) {
		f.t.Fatal("fixed SQL49 arguments changed")
	}
	if f.mode == "sql-error" || f.mode == "sql-revoked" {
		return nil, errors.New("synthetic current SQL rejection")
	}
	if f.mode == "sql-wait" {
		<-ctx.Done()
	}
	now := time.Now().UTC()
	out := app.ConnectorLeafRegistration{Certificate: f.prototype.Certificate, Process: f.prototype.Native.Workload.Process, Revision: f.registry.pin.Profile.Revision, ObservedAt: now, FreshUntil: f.prototype.Native.NativeUntil}
	switch f.mode {
	case "sql-leaf":
		out.Certificate.Digest[0]++
	case "sql-process":
		out.Process.ProcessEpoch = "00000000-0000-4000-8000-000000000002"
	case "sql-revision":
		out.Revision.Generation++
	case "sql-expired":
		out.FreshUntil = now
	case "sql-shorten":
		out.FreshUntil = now.Add(200 * time.Millisecond)
	case "sql-oversize":
		return make([]byte, 8193), nil
	case "sql-malformed":
		return []byte(`{`), nil
	}
	return json.Marshal(out)
}

func (f *operationRegistryFixture) read(ctx context.Context, ordinal int) (app.ConnectorObservationOperationRegistration, error) {
	return f.registry.readOperation(ctx, f.request, f, f.prototype.Certificate, ordinal, f)
}

func TestConnectorObservationOperationRegistryActualOrderedSourceCalls(t *testing.T) {
	f := newOperationRegistryFixture(t)
	ctx, cancel := context.WithDeadline(context.Background(), f.request.NotAfter)
	defer cancel()
	first, err := f.read(ctx, 1)
	if err != nil || first.Last.Native.Ordinal != 2 || first.Last.Native.Final {
		t.Fatal("first pair lost incomplete phase", err)
	}
	if first.FinalMatches(f.registry.pin, f.request, time.Now()) {
		t.Fatal("first registry pair released a final metadata result")
	}
	last, err := f.read(ctx, 3)
	if err != nil || last.Last.Native.Ordinal != 4 || !last.Last.Native.Final || !last.Last.Continues(first.Last) {
		t.Fatal("final pair missing", err)
	}
	if !last.FinalMatches(f.registry.pin, f.request, time.Now()) {
		t.Fatal("final result boundary lost exact final source phase")
	}
	if !reflect.DeepEqual(f.calls, []string{"source-1", "sql", "source-2", "source-3", "sql", "source-4"}) {
		t.Fatal("source calls did not bracket each SQL query", f.calls)
	}
	if !f.queryDeadline.Equal(f.request.NotAfter) || !f.lastDeadline.Equal(f.request.NotAfter) {
		t.Fatal("original deadline changed")
	}
	if _, err = f.read(ctx, 3); err == nil || f.queryCalls != 2 {
		t.Fatal("duplicate phase reached SQL")
	}
}

func TestConnectorObservationOperationRegistryFailuresRetainPhase(t *testing.T) {
	for _, mode := range []string{"source-error", "bad-first", "sql-error", "sql-revoked", "sql-leaf", "sql-process", "sql-revision", "sql-expired", "sql-oversize", "sql-malformed", "source-revision", "source-roles", "source-backing", "source-roots", "source-channel", "source-bracket", "source-process", "early-final", "missing-final"} {
		t.Run(mode, func(t *testing.T) {
			f := newOperationRegistryFixture(t)
			f.mode = mode
			ordinal := 1
			if mode == "missing-final" {
				ordinal, f.ordinal = 3, 2
			}
			ctx, cancel := context.WithDeadline(context.Background(), f.request.NotAfter)
			defer cancel()
			got, err := f.read(ctx, ordinal)
			if err == nil || got.Last.BracketID != "" || got.Registration != (app.ConnectorLeafRegistration{}) {
				t.Fatal("failed/unknown phase returned registration")
			}
			wantSQL, wantCalls := 1, 2
			if mode == "source-error" || mode == "bad-first" {
				wantSQL, wantCalls = 0, 1
			} else if len(mode) >= 7 && mode[:7] == "source-" || mode == "early-final" || mode == "missing-final" {
				wantCalls = 3
			}
			if f.queryCalls != wantSQL || len(f.calls) != wantCalls {
				t.Fatal("wrong failure effect boundary", f.calls)
			}
		})
	}
}

func TestConnectorObservationOperationRegistryDeadlineAfterWait(t *testing.T) {
	for _, mode := range []string{"sql-wait", "source-wait"} {
		t.Run(mode, func(t *testing.T) {
			f := newOperationRegistryFixture(t)
			f.mode = mode
			end := time.Now().Add(60 * time.Millisecond)
			ctx, cancel := context.WithDeadline(context.Background(), end)
			defer cancel()
			got, err := f.read(ctx, 1)
			if err == nil || got.Last.BracketID != "" || !f.queryDeadline.Equal(end) {
				t.Fatal("original caller expiry renewed after wait")
			}
			if mode == "sql-wait" && len(f.calls) != 2 {
				t.Fatal("source read after expired SQL")
			}
		})
	}
	for _, cap := range []string{"native", "source", "workload", "sql"} {
		t.Run(cap, func(t *testing.T) {
			f := newOperationRegistryFixture(t)
			end := f.request.NotAfter.Add(-time.Second)
			switch cap {
			case "native":
				f.prototype.Native.NativeUntil = end
				f.prototype.Native.Source.Observation.FreshUntil = end
				f.prototype.Native.Workload.FreshUntil = end
			case "source":
				f.prototype.Native.Source.Observation.FreshUntil = end
			case "workload":
				f.prototype.Native.Workload.FreshUntil = end
			case "sql":
				f.mode = "sql-shorten"
			}
			ctx, cancel := context.WithDeadline(context.Background(), f.request.NotAfter)
			defer cancel()
			got, err := f.read(ctx, 1)
			if err != nil {
				t.Fatal("shortening rejected", err)
			}
			if cap != "sql" && (!f.queryDeadline.Equal(end) || !f.lastDeadline.Equal(end) || !got.Registration.FreshUntil.Equal(end)) {
				t.Fatal("original observed cap lost")
			}
			if cap == "sql" && (!f.lastDeadline.Equal(got.Registration.FreshUntil) || !f.lastDeadline.Before(end)) {
				t.Fatal("SQL shortening lost before actual final source")
			}
		})
	}
}

func TestConnectorObservationOperationRegistryOriginalBindingBeforeIO(t *testing.T) {
	for _, mode := range []string{"missing-deadline", "cancelled", "root", "leaf", "server", "ordinal", "expired"} {
		t.Run(mode, func(t *testing.T) {
			f := newOperationRegistryFixture(t)
			ctx, cancel := context.WithDeadline(context.Background(), f.request.NotAfter)
			defer cancel()
			ordinal := 1
			switch mode {
			case "missing-deadline":
				ctx = context.Background()
			case "cancelled":
				cancel()
			case "root":
				f.request.RootID = "00000000-0000-4000-8000-000000000002"
			case "leaf":
				f.prototype.Certificate.Binding.PeerID = "00000000-0000-4000-8000-000000000002"
			case "server":
				f.prototype.Certificate.Usage, f.prototype.Certificate.ServerName = "server", f.registry.pin.Profile.ServerName
			case "ordinal":
				ordinal = 2
			case "expired":
				f.request.NotAfter = time.Now()
			}
			if _, err := f.read(ctx, ordinal); err == nil || len(f.calls) != 0 {
				t.Fatal("invalid original binding reached source or SQL")
			}
		})
	}
}
