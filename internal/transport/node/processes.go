package node

import (
	"asservat.local/asservat/internal/contracts"
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/collector"
	"asservat.local/asservat/internal/domain/execution"
	"encoding/hex"
)

func WireProcesses(p collector.ProcessCapture) contracts.NodeProcessCapture {
	r := p.Request
	return contracts.NodeProcessCapture{CaptureID: p.CaptureID, CollectorEpoch: p.CollectorEpoch, ExpectationDigest: hex.EncodeToString(p.ExpectationDigest[:]), Namespace: r.Pin.Namespace, NamespaceUID: r.Pin.NamespaceUID, PodName: r.Pin.Name, PodUID: r.Pin.UID, ControllerUID: r.Pin.ControllerUID, NodeName: r.Pin.NodeName, NodeUID: r.NodeUID, BootID: r.NodeBootID, Mode: r.Mode, NativeLimit: r.NativeLimit, NotBefore: r.NotBefore, Deadline: r.Deadline}
}
func DomainProcesses(p contracts.NodeProcessCapture) (collector.ProcessCapture, bool) {
	d, ok := digestHex(p.ExpectationDigest)
	out := collector.ProcessCapture{CaptureID: p.CaptureID, CollectorEpoch: p.CollectorEpoch, ExpectationDigest: d, Request: execution.ProcessSnapshotRequest{Pin: artifact.PinnedPod{Namespace: p.Namespace, NamespaceUID: p.NamespaceUID, Name: p.PodName, UID: p.PodUID, ControllerUID: p.ControllerUID, NodeName: p.NodeName}, NodeUID: p.NodeUID, NodeBootID: p.BootID, Mode: p.Mode, NativeLimit: p.NativeLimit, NotBefore: p.NotBefore, Deadline: p.Deadline}}
	return out, ok && out.Valid()
}
func WireProcessResult(epoch string, p collector.ProcessResult) contracts.NodeProcessResult {
	return contracts.NodeProcessResult{Format: contracts.NodeProcessesFormat, Epoch: epoch, WorkID: p.WorkID, CaptureID: p.CaptureID, ExpectationDigest: hex.EncodeToString(p.ExpectationDigest[:]), PodUID: p.PodUID, NodeUID: p.NodeUID, BootID: p.NodeBootID, StartedAt: p.StartedAt, CompletedAt: p.CompletedAt, NativeBytes: p.NativeBytes, Failure: string(p.Failure)}
}
func DomainProcessResult(p contracts.NodeProcessResult) (collector.ProcessResult, bool) {
	d, ok := digestHex(p.ExpectationDigest)
	out := collector.ProcessResult{WorkID: p.WorkID, CaptureID: p.CaptureID, ExpectationDigest: d, PodUID: p.PodUID, NodeUID: p.NodeUID, NodeBootID: p.BootID, StartedAt: p.StartedAt, CompletedAt: p.CompletedAt, NativeBytes: p.NativeBytes, Failure: collector.Reason(p.Failure)}
	return out, ok && p.Format == contracts.NodeProcessesFormat && out.Valid()
}
