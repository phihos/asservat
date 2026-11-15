package contextstart

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"time"

	deliveryapp "asservat.local/asservat/internal/application/delivery"
	app "asservat.local/asservat/internal/application/fleet"
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/fleet"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
)

// Work frames are plain JSON messages on the connector's authenticated
// stream (ADR-330 D2): the connection is bound to the hub owner's TLS
// certificate and the connector's ServiceAccount token, and each work names
// the stream's channel. The connector only checks that the work belongs to
// its channel and cluster; the hub authorized it before sending.

func hexDigest(d artifact.Digest) string { return hex.EncodeToString(d[:]) }
func digestValue(s string) artifact.Digest {
	var d artifact.Digest
	b, _ := hex.DecodeString(s)
	copy(d[:], b)
	return d
}
func instant(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t.UTC(), err == nil && t.UTC().Format(time.RFC3339Nano) == s
}

func channelWire(c fleet.APIContextChannel) contracts.APIContextChannel {
	p, e, h := c.Connector, c.Executor, c.Hub
	return contracts.APIContextChannel{RootID: c.RootID, ExchangeID: c.ExchangeID, Challenge: c.Challenge,
		Hub:       contracts.APIContextOwner{InstallationID: h.InstallationID, ClusterID: h.ClusterID, IssuerEpoch: h.IssuerEpoch, PodUID: h.PodUID, ProcessEpoch: h.ProcessEpoch},
		Connector: contracts.APIContextConnector{InstallationID: p.Binding.InstallationID, ClusterID: p.Binding.ClusterID, IssuerEpoch: p.Binding.IssuerEpoch, PeerID: p.Binding.PeerID, PodUID: p.PodUID, ProcessEpoch: p.ProcessEpoch},
		Executor:  contracts.APIContextExecutor{NamespaceUID: e.NamespaceUID, AccountUID: e.AccountUID, PodUID: e.PodUID, ProcessEpoch: e.ProcessEpoch, StartupDigest: hexDigest(e.StartupDigest), ImageDigest: hexDigest(e.ImageDigest)}}
}
func channelValue(c contracts.APIContextChannel) fleet.APIContextChannel {
	p, e, h := c.Connector, c.Executor, c.Hub
	return fleet.APIContextChannel{RootID: c.RootID, ExchangeID: c.ExchangeID, Challenge: c.Challenge,
		Hub:       fleet.OwnerBinding{InstallationID: h.InstallationID, ClusterID: h.ClusterID, IssuerEpoch: h.IssuerEpoch, PodUID: h.PodUID, ProcessEpoch: h.ProcessEpoch},
		Connector: fleet.ConnectorProcessIdentity{Binding: fleet.PeerBinding{InstallationID: p.InstallationID, ClusterID: p.ClusterID, IssuerEpoch: p.IssuerEpoch, PeerID: p.PeerID, Role: fleet.ConnectorPeer}, PodUID: p.PodUID, ProcessEpoch: p.ProcessEpoch},
		Executor:  fleet.APIContextExecutor{NamespaceUID: e.NamespaceUID, AccountUID: e.AccountUID, PodUID: e.PodUID, ProcessEpoch: e.ProcessEpoch, StartupDigest: digestValue(e.StartupDigest), ImageDigest: digestValue(e.ImageDigest)}}
}

func encodeAPIContextWork(w fleet.APIContextWork, now time.Time) ([]byte, error) {
	if !w.Valid(now) {
		return nil, fleet.ErrInvalid
	}
	return contracts.EncodeAPIContextWork(contracts.APIContextWork{Format: contracts.APIContextWorkFormat, Purpose: "runAction", ExecutionClass: string(artifact.ContextAPIExecution), ActionID: "pod-status", NativeBytes: artifact.MaxContextBytes,
		Channel: channelWire(w.Channel), CaptureID: w.CaptureID, AttemptID: w.AttemptID, Actor: contracts.APIContextActor{Issuer: w.Actor.Issuer, Subject: w.Actor.Subject, ClientID: w.Actor.ClientID, Kind: string(w.Actor.Kind)},
		Target:      contracts.APIContextTarget{ClusterID: w.Target.ClusterID, NamespaceUID: w.Target.NamespaceUID, WorkloadUID: w.Target.WorkloadUID, PodUID: w.Target.PodUID},
		ScopeDigest: hexDigest(w.ScopeDigest), ExpectationDigest: hexDigest(w.ExpectationDigest), IntentDigest: hexDigest(w.IntentDigest), BudgetDigest: hexDigest(w.BudgetDigest),
		Capability: contracts.APIContextRevision{UID: w.Capability.UID, Generation: w.Capability.Generation, Digest: hexDigest(w.Capability.Digest)}, ProjectionDigest: hexDigest(w.ProjectionDigest), IssuedAt: w.IssuedAt.Format(time.RFC3339Nano), NotAfter: w.NotAfter.Format(time.RFC3339Nano)})
}

// decodeAPIContextWork accepts only work for the receiver's own channel.
func decodeAPIContextWork(b []byte, r fleet.APIContextReceiver, now time.Time) (fleet.APIContextWork, error) {
	d, err := contracts.DecodeAPIContextWork(b)
	if err != nil {
		return fleet.APIContextWork{}, fleet.ErrInvalid
	}
	issued, ok1 := instant(d.IssuedAt)
	notAfter, ok2 := instant(d.NotAfter)
	if !ok1 || !ok2 || d.Purpose != "runAction" || d.ExecutionClass != string(artifact.ContextAPIExecution) || d.ActionID != "pod-status" || d.NativeBytes != artifact.MaxContextBytes {
		return fleet.APIContextWork{}, fleet.ErrInvalid
	}
	w := fleet.APIContextWork{Channel: channelValue(d.Channel), CaptureID: d.CaptureID, AttemptID: d.AttemptID, Actor: identity.Principal{Issuer: d.Actor.Issuer, Subject: d.Actor.Subject, ClientID: d.Actor.ClientID, Kind: identity.Kind(d.Actor.Kind)},
		Target: authorization.Target{ClusterID: d.Target.ClusterID, NamespaceUID: d.Target.NamespaceUID, WorkloadUID: d.Target.WorkloadUID, PodUID: d.Target.PodUID}, ScopeDigest: digestValue(d.ScopeDigest), ExpectationDigest: digestValue(d.ExpectationDigest), IntentDigest: digestValue(d.IntentDigest), BudgetDigest: digestValue(d.BudgetDigest),
		Capability: identity.Revision{UID: d.Capability.UID, Generation: d.Capability.Generation, Digest: digestValue(d.Capability.Digest)}, ProjectionDigest: digestValue(d.ProjectionDigest), IssuedAt: issued, NotAfter: notAfter}
	if !w.Matches(r, now) {
		return fleet.APIContextWork{}, fleet.ErrDenied
	}
	return w, nil
}

func encodeHistoryWork(w app.HistoryWork, now time.Time) ([]byte, error) {
	if !w.Valid(now) {
		return nil, fleet.ErrInvalid
	}
	a, err := json.Marshal(w.Authority)
	if err != nil {
		return nil, fleet.ErrInvalid
	}
	return contracts.EncodeHistoryWork(contracts.HistoryWork{Format: contracts.HistoryWorkFormat, Channel: channelWire(w.Channel), Authority: a})
}
func decodeHistoryWork(b []byte, r fleet.APIContextReceiver, now time.Time) (app.HistoryWork, error) {
	d, err := contracts.DecodeHistoryWork(b)
	if err != nil {
		return app.HistoryWork{}, fleet.ErrInvalid
	}
	var a capture.HistoryOperationAuthority
	if json.NewDecoder(bytes.NewReader(d.Authority)).Decode(&a) != nil {
		return app.HistoryWork{}, fleet.ErrInvalid
	}
	w := app.HistoryWork{Channel: channelValue(d.Channel), Authority: a}
	if !w.Matches(r, now) || a.ExecutorEpoch != r.Channel.Executor.ProcessEpoch {
		return app.HistoryWork{}, fleet.ErrDenied
	}
	return w, nil
}

func encodeSourceWork(w app.SourceWork, now time.Time) ([]byte, error) {
	if !w.Valid(now) {
		return nil, fleet.ErrInvalid
	}
	if !w.Stop && w.StopSnapshot == nil && w.StopProfile == nil && w.StopRecording == nil && deliveryapp.SourceResourcesDigest(w.Source.Resources) != w.Source.Permit.Binding.ResourceDigest {
		return nil, fleet.ErrInvalid
	}
	program := make([]byte, 8*len(w.Source.Program))
	for i, ins := range w.Source.Program {
		at := program[i*8:]
		binary.LittleEndian.PutUint16(at, ins.Code)
		at[2], at[3] = ins.Jt, ins.Jf
		binary.LittleEndian.PutUint32(at[4:], ins.K)
	}
	if len(program) > 0 && sha256.Sum256(program) != w.Source.Permit.Binding.ProgramDigest {
		return nil, fleet.ErrInvalid
	}
	out := contracts.SourceWork{Format: contracts.SourceWorkFormat, Channel: channelWire(w.Channel), ProgramLE: program, NotAfter: w.NotAfter, Stop: w.Stop, StopIssuedAt: w.StopIssuedAt}
	metadata := w.Source
	metadata.Program = nil
	if w.StopProfile == nil && w.StopRecording == nil {
		out.Target, _ = json.Marshal(w.Target)
		out.Node, _ = json.Marshal(w.Node)
		out.Source, _ = json.Marshal(metadata)
	}
	if w.StopSnapshot != nil {
		out.StopSnapshot, _ = json.Marshal(w.StopSnapshot)
	}
	if w.StopProfile != nil {
		out.StopProfile, _ = json.Marshal(w.StopProfile)
	}
	if w.StopRecording != nil {
		out.StopRecording, _ = json.Marshal(w.StopRecording)
	}
	return contracts.EncodeSourceWork(out)
}
func decodeSourceWork(b []byte, r fleet.APIContextReceiver, now time.Time) (app.SourceWork, error) {
	d, err := contracts.DecodeSourceWork(b)
	if err != nil || len(d.ProgramLE)%8 != 0 || len(d.ProgramLE)/8 > planning.MaxFilterInstructions {
		return app.SourceWork{}, fleet.ErrInvalid
	}
	w := app.SourceWork{Channel: channelValue(d.Channel), NotAfter: d.NotAfter, Stop: d.Stop, StopIssuedAt: d.StopIssuedAt}
	decode := func(raw []byte, v any) bool {
		return len(raw) == 0 || json.NewDecoder(bytes.NewReader(raw)).Decode(v) == nil
	}
	if !decode(d.Target, &w.Target) || !decode(d.Node, &w.Node) || !decode(d.Source, &w.Source) || len(w.Source.Program) != 0 {
		return app.SourceWork{}, fleet.ErrInvalid
	}
	if len(d.StopSnapshot) > 0 {
		w.StopSnapshot = &collector.SourceSnapshot{}
		if !decode(d.StopSnapshot, w.StopSnapshot) {
			return app.SourceWork{}, fleet.ErrInvalid
		}
	}
	if len(d.StopProfile) > 0 {
		w.StopProfile = &collector.ProfileStop{}
		if !decode(d.StopProfile, w.StopProfile) {
			return app.SourceWork{}, fleet.ErrInvalid
		}
	}
	if len(d.StopRecording) > 0 {
		w.StopRecording = &collector.RecordingStop{}
		if !decode(d.StopRecording, w.StopRecording) {
			return app.SourceWork{}, fleet.ErrInvalid
		}
	}
	if len(d.ProgramLE) > 0 {
		w.Source.Program = make([]planning.BPFInstruction, len(d.ProgramLE)/8)
		for i := range w.Source.Program {
			at := d.ProgramLE[i*8:]
			w.Source.Program[i] = planning.BPFInstruction{Code: binary.LittleEndian.Uint16(at), Jt: at[2], Jf: at[3], K: binary.LittleEndian.Uint32(at[4:])}
		}
	}
	if !w.Matches(r, now) {
		return app.SourceWork{}, fleet.ErrDenied
	}
	return w, nil
}
