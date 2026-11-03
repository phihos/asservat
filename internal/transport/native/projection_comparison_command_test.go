package native_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/contracts"
	query "asservat.local/asservat/internal/domain/analysis"
	"asservat.local/asservat/internal/domain/artifact"
	value "asservat.local/asservat/internal/domain/authorization"
	native "asservat.local/asservat/internal/transport/native"
)

func TestNativeComparisonMaximumFullSourcesFitExistingCommand(t *testing.T) {
	f := pairedProtocolFixture(t)
	source := maximumNativeSource(t)
	e := &source.Expectation
	e.NativeType, e.DataClass, e.ActionID = artifact.PprofArtifact, "raw", "a0123456789abcdef01234567"
	e.Profile = &artifact.GoProfileAcquisition{SourceRef: "go", EndpointDigest: artifact.Digest{255}, Type: "heap", Mode: "snapshot"}
	e.Registration.NativeLimit = artifact.MaxPprofBytes
	// The original maximum-domain superset exceeds capture admission. Keep
	// every selected provenance entry intact and choose the largest complete
	// audience prefix accepted by that same canonical 65536-byte contract.
	for !evidence.CanonicalProjectionExpectationBound(source) && len(e.Audience) > 1 {
		e.Audience = e.Audience[:len(e.Audience)-1]
	}
	if !source.Valid(evidence.ContextCopiesDigest(source.Copies)) || !evidence.CanonicalProjectionExpectationBound(source) {
		t.Fatal("bounded full fixture invalid")
	}
	s := f.scope
	s.CaseID, s.CaptureID, s.ArtifactID, s.ClusterID = e.CaseID, e.CaptureUID, e.Registration.Location.ArtifactID, e.Registration.Location.ClusterID
	s.NamespaceUID, s.WorkloadUID, s.PodUID = e.NamespaceUID, e.WorkloadUID, e.PodUID
	s.Version = evidence.ContextCopiesDigest(source.Copies)
	s.Comparison.Baseline = query.ProfileComparisonBaseline{CaseID: s.CaseID, ArtifactID: s.ArtifactID, CaptureID: s.CaptureID, ClusterID: s.ClusterID, NamespaceUID: s.NamespaceUID, WorkloadUID: s.WorkloadUID, PodUID: s.PodUID, Version: s.Version}
	o := f.lease.Operation
	o.SourceVersion = s.Version
	o.Processing.Location = e.Registration.Location
	o.Processing.CaptureID = e.CaptureUID
	o.Path.TargetClusterID = s.ClusterID
	o.Path.StoreID = e.Registration.StoreID
	o.Path.StorageRegion, o.Path.AcquisitionRegion, o.Path.ConnectorRegion, o.Path.HubRegion = strings.Repeat("<", 63), strings.Repeat("<", 63), strings.Repeat("<", 63), strings.Repeat("<", 63)
	o.Baseline = value.NativeProjectionSource{SourceVersion: s.Version, Path: o.Path, Processing: o.Processing}
	if !s.Valid() || !o.CurrentValid(o.StartedAt) || !evidence.NativeComparisonSourcesMatch([2]evidence.NativeContextSource{source, source}, s, o) {
		t.Fatal("invalid maximal command pins")
	}
	b, _ := json.Marshal(source)
	operation, _ := json.Marshal(o)
	scope, _ := json.Marshal(s)
	c := contracts.NativeCommand{Format: contracts.NativeExchangeFormat, Reference: contracts.NativeReference{InstallationID: o.Reference.InstallationID, QueryID: o.Reference.QueryID, WorkerID: o.Reference.WorkerID, OperationID: o.Reference.OperationID, Fence: o.Reference.Fence}, Nonce: strings.Repeat("A", 43), Kind: string(o.Kind), Source: b, BaselineSource: b, Operation: operation, Projection: scope, ParentID: o.ParentID, Generation: o.Generation, LeaseSequence: 1, Until: o.Until.Format(time.RFC3339Nano)}
	encoded, err := json.Marshal(c)
	if err != nil || len(encoded) > contracts.NativeCommandBytes || len(operation) > 16<<10 {
		t.Fatal("existing command/operation bound exceeded", len(encoded), len(operation), err)
	}
	if _, err := contracts.DecodeNativeCommand(encoded); err != nil {
		t.Fatal("full pair command decode", err)
	}
	if len(b) < 90<<10 || len(encoded) < 200<<10 {
		t.Fatal("maximum escaped receipts/provenance not exercised", len(b), len(encoded))
	}
	oversized := source
	oversized.Expectation.Audience = append(append([]artifact.AudienceAssignment{}, source.Expectation.Audience...), source.Expectation.Audience[0])
	if evidence.CanonicalProjectionExpectationBound(oversized) {
		t.Fatal("canonical complete expectation cap not reached")
	}
	if evidence.NativeComparisonSourcesMatch([2]evidence.NativeContextSource{oversized, source}, s, o) {
		t.Fatal("oversized baseline provenance accepted")
	}
	t.Logf("complete expectation audience=%d source=%dB x2 operation=%dB scope=%dB command=%dB ceiling=%dB", len(e.Audience), len(b), len(operation), len(scope), len(encoded), contracts.NativeCommandBytes)
}

func TestNativeComparisonCommandRefusesChangedOrMixedBaseline(t *testing.T) {
	for _, mode := range []string{"missing", "null", "unknown", "noncanonical", "version", "route", "root", "legacy-scope"} {
		t.Run(mode, func(t *testing.T) {
			f := pairedProtocolFixture(t)
			operation, _ := json.Marshal(f.lease.Operation)
			source, _ := json.Marshal(f.source)
			scope, _ := json.Marshal(f.scope)
			r := f.lease.Operation.Reference
			c := contracts.NativeCommand{Format: contracts.NativeExchangeFormat, Reference: contracts.NativeReference{InstallationID: r.InstallationID, QueryID: r.QueryID, WorkerID: r.WorkerID, OperationID: r.OperationID, Fence: r.Fence}, Kind: string(value.NativeProjection), Source: source, BaselineSource: source, Operation: operation, Projection: scope, ParentID: f.lease.Operation.ParentID, Generation: 1, LeaseSequence: 1, Until: f.lease.Until.Format(time.RFC3339Nano)}
			switch mode {
			case "missing":
				c.BaselineSource = nil
			case "null":
				c.BaselineSource = []byte("null")
			case "unknown":
				c.BaselineSource = append(append([]byte{}, source[:len(source)-1]...), []byte(`,"user_data":"sensitive-marker"}`)...)
			case "noncanonical":
				c.BaselineSource = append([]byte(" "), source...)
			case "version":
				altered := f.source
				altered.Copies[0].SHA256[0]++
				c.BaselineSource, _ = json.Marshal(altered)
			case "route":
				altered := f.source
				altered.Expectation.CaptureUID = "99999999-9999-4999-8999-999999999999"
				c.BaselineSource, _ = json.Marshal(altered)
			case "legacy-scope":
				single, _ := f.scope.IncidentScope()
				c.Projection, _ = json.Marshal(single)
			case "root":
				changed := f.scope
				changed.RootID = "99999999-9999-4999-8999-999999999999"
				c.Projection, _ = json.Marshal(changed)
			}
			gate, err := evidence.NewNativeFrameGate(f.ctx, func(context.Context) (value.NativeLease, error) { return f.lease, nil }, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { gate.Close(); _ = gate.Wait(context.Background()) }()
			if op, err := native.NewHubOperation(gate, c, f.source, syntheticNativeCompletion); err == nil || op != nil {
				if op != nil {
					_ = op.Close()
				}
				t.Fatal("changed/mixed source command accepted")
			}
		})
	}
}

func TestNativeComparisonOperationKeepsBothCurrentProofsAndLegacyBytes(t *testing.T) {
	f := pairedProtocolFixture(t)
	o := f.lease.Operation
	legacy := o
	legacy.Baseline = value.NativeProjectionSource{}
	b, _ := json.Marshal(legacy)
	if bytes.Contains(b, []byte("Baseline")) {
		t.Fatal("legacy operation bytes gained comparison field")
	}
	for _, mode := range []string{"store", "configuration", "version", "interval", "root", "location"} {
		x := o
		switch mode {
		case "store":
			x.Baseline.Path.StoreID = "99999999-9999-4999-8999-999999999999"
		case "configuration":
			x.Baseline.Path.WorkerConfiguration.Generation++
		case "version":
			x.Baseline.SourceVersion = artifact.Digest{}
		case "interval":
			x.Baseline.Processing.ValidUntil = o.Until.Add(-time.Microsecond)
		case "root":
			x.Baseline.Processing.RootID = "99999999-9999-4999-8999-999999999999"
		case "location":
			x.Baseline.Path.TargetClusterID = "99999999-9999-4999-8999-999999999999"
		}
		if x.CurrentValid(o.StartedAt) {
			t.Fatal("invalid baseline proof accepted", mode)
		}
	}
	x := o
	x.Baseline.Processing.ObservedAt = x.Baseline.Processing.ObservedAt.In(time.FixedZone("same-instant", 3600))
	x.Baseline.Processing.ValidUntil = x.Baseline.Processing.ValidUntil.In(time.FixedZone("same-instant", 3600))
	if !o.Equal(x) {
		t.Fatal("baseline proof dates compared by representation")
	}
	x.Baseline.Processing.Sequence++
	if o.Equal(x) {
		t.Fatal("different baseline state accepted")
	}
}
