package fleet

import (
	"testing"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

func operationValueFixture(t *testing.T) (ConnectorObservationPin, ConnectorObservationOperationValue, time.Time) {
	t.Helper()
	id := "00000000-0000-4000-8000-000000000001"
	now := time.Now().UTC()
	start, end := now.Add(-time.Second), now.Add(2*time.Second)
	b := PeerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PeerID: id, Role: ConnectorPeer}
	p := ConnectorObservationPin{Profile: ConnectorCredentialProfile{RootID: id, Binding: b, Revision: identity.Revision{UID: id, Generation: 1, Digest: artifact.Digest{1}}, ProtectionDigest: artifact.Digest{2}, ServerName: "regional.invalid", ClientIssuerRoots: [][]byte{{1}}, ServerIssuerRoots: [][]byte{{2}}, Deployment: ConnectorDeployment{Namespace: "regional", NamespaceUID: id, ServiceAccount: "regional", AccountUID: id, Deployment: "regional", DeploymentUID: id, ServingSlots: 2, RetainedProcesses: 8}}, Roles: ConnectorIdentityRoles{"source", "journal", "ack", "cleanup", "verifier", "finalizer"}, TemplateDigest: artifact.Digest{3}, ImageDigest: artifact.Digest{4}, ProtectionDigest: artifact.Digest{5}}
	r := OwnerObservationRequest{RootID: id, ID: id, Challenge: id, RequestedAt: start, NotAfter: end}
	s := ConnectorIdentitySource{Roles: p.Roles, Observation: ConnectorCredentialObservation{Profile: p.Profile.Clone(), Backing: ConnectorBackingObservation{Revision: 1, Digest: artifact.Digest{6}, SourceDigest: artifact.Digest{7}}, ObservedAt: now, FreshUntil: end}}
	w := ConnectorObservationWorkload{Process: ConnectorProcessIdentity{Binding: b, PodUID: id, ProcessEpoch: id}, Pod: "regional-pod", ReplicaSetUID: id, TemplateDigest: p.TemplateDigest, ImageDigest: p.ImageDigest, ProtectionDigest: p.ProtectionDigest, WorkloadDigest: artifact.Digest{8}, ObservedAt: start, FreshUntil: end}
	v := ConnectorObservationOperationValue{Native: ConnectorObservationNativeValue{Request: r, Ordinal: 1, Source: s, Workload: w, NativeStartedAt: start, NativeUntil: end, ValueObservedAt: now}, BracketID: id, ConnectionBinding: artifact.Digest{9}, Certificate: ConnectorCredentialCertificate{Binding: b, Usage: "client", Digest: artifact.Digest{10}, PublicKeyDigest: artifact.Digest{11}, NotBefore: start, NotAfter: end.Add(time.Minute)}}
	if !v.Matches(p, r, 1, now) {
		t.Fatal("invalid original fixture")
	}
	return p, v, now
}

func TestObservationOperationValueSeparatesDatesAndFinalPhase(t *testing.T) {
	p, v, now := operationValueFixture(t)
	for _, mode := range []string{"bracket-id", "channel", "wrong-request", "wrong-ordinal", "early-final", "missing-final", "native-before-request", "native-renewal", "value-before-native", "false-value-date", "workload-date", "source-renewal", "wrong-roles", "wrong-roots", "expired", "server-leaf"} {
		t.Run(mode, func(t *testing.T) {
			x := v.Clone()
			ordinal := 1
			switch mode {
			case "bracket-id":
				x.BracketID = ""
			case "channel":
				x.ConnectionBinding = artifact.Digest{}
			case "wrong-request":
				x.Native.Request.Challenge = "00000000-0000-4000-8000-000000000002"
			case "wrong-ordinal":
				x.Native.Ordinal = 2
			case "early-final":
				x.Native.Final = true
			case "missing-final":
				x.Native.Ordinal, ordinal = 4, 4
			case "native-before-request":
				x.Native.NativeStartedAt = x.Native.Request.RequestedAt.Add(-time.Nanosecond)
			case "native-renewal":
				x.Native.NativeUntil = x.Native.Request.NotAfter.Add(time.Nanosecond)
			case "value-before-native":
				x.Native.ValueObservedAt = x.Native.NativeStartedAt.Add(-time.Nanosecond)
				x.Native.Source.Observation.ObservedAt = x.Native.ValueObservedAt
			case "false-value-date":
				x.Native.ValueObservedAt = x.Native.ValueObservedAt.Add(-time.Nanosecond)
			case "workload-date":
				x.Native.Workload.ObservedAt = now
			case "source-renewal":
				x.Native.Source.Observation.FreshUntil = x.Native.NativeUntil.Add(time.Nanosecond)
			case "wrong-roles":
				x.Native.Source.Roles.Source = "another_source"
			case "wrong-roots":
				x.Native.Source.Observation.Profile.ClientIssuerRoots[0][0]++
			case "expired":
				x.Native.NativeUntil = now
			case "server-leaf":
				x.Certificate.Usage, x.Certificate.ServerName = "server", p.Profile.ServerName
			}
			if x.Matches(p, v.Native.Request, ordinal, now) {
				t.Fatal("invalid native/value phase accepted")
			}
		})
	}
	final := v.Clone()
	final.Native.Ordinal, final.Native.Final = 4, true
	final.Native.ValueObservedAt = now.Add(time.Millisecond)
	final.Native.Source.Observation.ObservedAt = final.Native.ValueObservedAt
	if !final.Matches(p, v.Native.Request, 4, now.Add(time.Millisecond)) || !final.Continues(v) {
		t.Fatal("actual final phase rejected")
	}
	if v.Matches(p, v.Native.Request, 4, now) {
		t.Fatal("initial phase certified completion")
	}
	if !v.Native.Source.Observation.Profile.Equal(p.Profile) {
		t.Fatal("mutation escaped cloned native value")
	}
}

func TestObservationOperationValueContinuityAndCaps(t *testing.T) {
	_, first, _ := operationValueFixture(t)
	for _, mode := range []string{"new-bracket", "new-channel", "new-process", "new-source", "new-backing", "new-native-start", "new-leaf", "new-workload", "longer-source"} {
		t.Run(mode, func(t *testing.T) {
			x := first.Clone()
			switch mode {
			case "new-bracket":
				x.BracketID = "00000000-0000-4000-8000-000000000002"
			case "new-channel":
				x.ConnectionBinding[0]++
			case "new-process":
				x.Native.Workload.Process.ProcessEpoch = "00000000-0000-4000-8000-000000000002"
			case "new-source":
				x.Native.Source.Observation.Profile.Revision.Generation++
			case "new-backing":
				x.Native.Source.Observation.Backing.Revision++
			case "new-native-start":
				x.Native.NativeStartedAt = x.Native.NativeStartedAt.Add(time.Nanosecond)
			case "new-leaf":
				x.Certificate.Digest[0]++
			case "new-workload":
				x.Native.Workload.WorkloadDigest[0]++
			case "longer-source":
				x.Native.Source.Observation.FreshUntil = x.Native.Source.Observation.FreshUntil.Add(time.Nanosecond)
			}
			if x.Continues(first) {
				t.Fatal("different operation or extended source accepted")
			}
		})
	}
	short := first.Clone()
	short.Native.Workload.FreshUntil = short.Native.Workload.FreshUntil.Add(-time.Second)
	if !short.Until().Equal(short.Native.Workload.FreshUntil) || !short.Continues(first) {
		t.Fatal("restrictive workload bound lost")
	}
}

func TestObservationOperationOwnerFactsCloneAndNativeScope(t *testing.T) {
	_, v, now := operationValueFixture(t)
	id := v.Native.Request.ID
	p := OwnerPool{InstallationID: id, ClusterID: id, IssuerEpoch: id, Namespace: "owners", NamespaceUID: id, Service: "owners", ServiceUID: id, Deployment: "owners", DeploymentUID: id, ServiceAccount: "owners", AccountUID: id, Port: 9443, NativePort: 9444, NativeBootstrap: OwnerBootstrapProfile}
	b := OwnerBinding{InstallationID: id, ClusterID: id, IssuerEpoch: id, PodUID: id, ProcessEpoch: id}
	f := OwnerObservationNativeFacts{Request: v.Native.Request, Pin: OwnerObservationPin{RootID: id, SourceUID: id, Pool: p, TemplateDigest: artifact.Digest{1}, ImageDigest: artifact.Digest{2}, ProtectionDigest: artifact.Digest{3}}, Peers: []OwnerObservationNativePeer{{Binding: b, Pod: "owner-pod", ReplicaSetUID: id, Addresses: []string{"10.0.0.1"}, WorkloadDigest: artifact.Digest{4}}}, ObservedAt: v.Native.NativeStartedAt, FreshUntil: v.Native.NativeUntil}
	if !f.Valid(now) {
		t.Fatal("invalid native facts fixture")
	}
	c := f.Clone()
	c.Peers[0].Addresses[0] = "10.0.0.2"
	if f.Peers[0].Addresses[0] != "10.0.0.1" {
		t.Fatal("native address alias escaped")
	}
	c.Peers = append(c.Peers, c.Peers[0])
	if c.Valid(now) {
		t.Fatal("duplicate exact peer accepted")
	}
	f.FreshUntil = f.Request.NotAfter.Add(time.Nanosecond)
	if f.Valid(now) {
		t.Fatal("native facts extended original request")
	}
}
