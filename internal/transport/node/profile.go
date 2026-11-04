package node

import (
	"encoding/hex"
	"net/netip"
	"time"

	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
)

func WireProfile(p collector.ProfileCapture) contracts.NodeProfileCapture {
	r := p.Request
	var material contracts.NodeProfileTLS
	if !p.TLS.IsZero() {
		material = contracts.NodeProfileTLS{RootsPEM: p.TLS.RootsPEM, RootsDigest: hex.EncodeToString(p.TLS.RootsDigest[:]), ServerName: p.TLS.ServerName}
	}
	return contracts.NodeProfileCapture{CaptureID: p.CaptureID, ClusterID: r.Binding.ClusterID, ArtifactID: r.Binding.ArtifactID, AttemptID: r.Binding.AttemptID, Namespace: r.Pin.Namespace, NamespaceUID: r.Pin.NamespaceUID, PodName: r.Pin.Name, PodUID: r.Pin.UID, ControllerUID: r.Pin.ControllerUID, NodeName: r.Pin.NodeName, NodeUID: r.NodeUID, BootID: r.NodeBootID, CollectorEpoch: p.CollectorEpoch, ExpectationDigest: hex.EncodeToString(p.ExpectationDigest[:]), EndpointDigest: hex.EncodeToString(r.EndpointDigest[:]), DefinitionDigest: hex.EncodeToString(p.DefinitionDigest[:]), SourceRef: r.SourceRef, Type: r.Parameters.Type, Mode: r.Parameters.Mode, DurationMillis: r.Parameters.Duration.Milliseconds(), ForceGC: r.Parameters.ForceGC, NativeLimit: r.NativeLimit, NotBefore: r.NotBefore, Deadline: r.Deadline, AddressMode: p.AddressMode, Address: p.Address.String(), Port: p.Port, Host: p.Host, TLS: material, AuthorizationRequired: p.AuthorizationRequired}
}

func DomainProfile(p contracts.NodeProfileCapture) (collector.ProfileCapture, bool) {
	expected, ok := digestHex(p.ExpectationDigest)
	endpoint, ok2 := digestHex(p.EndpointDigest)
	definition, ok3 := digestHex(p.DefinitionDigest)
	address, err := netip.ParseAddr(p.Address)
	if !ok || !ok2 || !ok3 || err != nil || address.String() != p.Address || p.DurationMillis < 0 || p.DurationMillis > 60000 {
		return collector.ProfileCapture{}, false
	}
	r := execution.GoProfileRequest{Binding: artifact.Binding{ClusterID: p.ClusterID, ArtifactID: p.ArtifactID, AttemptID: p.AttemptID, MediaType: artifact.ProfileMediaType}, Pin: artifact.PinnedPod{Namespace: p.Namespace, NamespaceUID: p.NamespaceUID, Name: p.PodName, UID: p.PodUID, ControllerUID: p.ControllerUID, NodeName: p.NodeName}, NodeUID: p.NodeUID, NodeBootID: p.BootID, SourceRef: p.SourceRef, EndpointDigest: artifact.Digest(endpoint), Parameters: execution.GoProfileParameters{Type: p.Type, Mode: p.Mode, Duration: time.Duration(p.DurationMillis) * time.Millisecond, ForceGC: p.ForceGC}, NativeLimit: p.NativeLimit, NotBefore: p.NotBefore, Deadline: p.Deadline}
	var material execution.GoProfileTLSMaterial
	if p.TLS != (contracts.NodeProfileTLS{}) {
		digest, ok := digestHex(p.TLS.RootsDigest)
		if !ok {
			return collector.ProfileCapture{}, false
		}
		material = execution.GoProfileTLSMaterial{RootsPEM: p.TLS.RootsPEM, RootsDigest: artifact.Digest(digest), ServerName: p.TLS.ServerName}
	}
	out := collector.ProfileCapture{CaptureID: p.CaptureID, CollectorEpoch: p.CollectorEpoch, ExpectationDigest: artifact.Digest(expected), DefinitionDigest: artifact.Digest(definition), Request: r, AddressMode: p.AddressMode, Address: address, Port: p.Port, Host: p.Host, TLS: material, AuthorizationRequired: p.AuthorizationRequired}
	return out, out.Valid()
}

func WireProfileResult(epoch string, r collector.ProfileResult) contracts.NodeProfileResult {
	o := r.Outcome
	return contracts.NodeProfileResult{Format: contracts.NodeProfileCaptureFormat, Epoch: epoch, WorkID: r.WorkID, CaptureID: r.CaptureID, ExpectationDigest: hex.EncodeToString(r.ExpectationDigest[:]), EndpointDigest: hex.EncodeToString(r.EndpointDigest[:]), NativeFormat: o.Format, StartedAt: o.StartedAt, CompletedAt: o.CompletedAt, MayHaveStarted: o.MayHaveStarted, ResponseComplete: o.ResponseComplete, NativeBytes: o.NativeBytes, Failure: string(r.Failure)}
}
func DomainProfileResult(r contracts.NodeProfileResult) (collector.ProfileResult, bool) {
	e, ok := digestHex(r.ExpectationDigest)
	d, ok2 := digestHex(r.EndpointDigest)
	if !ok || !ok2 || r.Format != contracts.NodeProfileCaptureFormat {
		return collector.ProfileResult{}, false
	}
	out := collector.ProfileResult{WorkID: r.WorkID, CaptureID: r.CaptureID, ExpectationDigest: artifact.Digest(e), EndpointDigest: artifact.Digest(d), Failure: collector.Reason(r.Failure), Outcome: execution.GoProfileOutcome{Format: r.NativeFormat, StartedAt: r.StartedAt, CompletedAt: r.CompletedAt, MayHaveStarted: r.MayHaveStarted, ResponseComplete: r.ResponseComplete, NativeBytes: r.NativeBytes}}
	return out, out.Valid()
}
