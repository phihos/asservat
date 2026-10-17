package integration

import (
	app "asservat.local/asservat/internal/application/capacity"
	"asservat.local/asservat/internal/application/planning"
	"asservat.local/asservat/internal/domain/artifact"
	cfg "asservat.local/asservat/internal/domain/configuration"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
	"time"
)

// These builders are shared by the real SQL fixture and its offline preflight.
// They describe explicitly synthetic observations, never production authority.
func capacityNativeProcessingPolicy(q app.CapacityQualification, epoch string) privacy.DownloadPolicy {
	path := syntheticDownloadPlacement(artifact.Registration{Location: artifact.Location{ClusterID: q.NamespaceGuards[0].ClusterID}, StoreID: q.Backends[0].EvidenceStoreID})
	return privacy.DownloadPolicy{RootID: q.RootBacking.RootID, InstallationID: q.RootBacking.InstallationID, RecoveryEpoch: epoch, Revision: identity.Revision{UID: q.RootBacking.ProcessingSourceUID, Generation: 1, Digest: artifact.Digest{15}}, ProtectionDigest: q.RootBacking.ProcessingProtectionDigest, PermittedRegions: []string{"synthetic-region"}, Paths: []privacy.DownloadPath{path}, Clients: []privacy.DownloadClient{{Issuer: "https://id.example.test", ID: "console", Kind: identity.Human, DataClasses: []string{"metadata"}, PrivacyClasses: []string{"potentialPersonalData"}, EvidenceTypes: []string{"context"}, Purposes: []string{"diagnostics"}, PathIDs: []string{path.ID}}}, Operators: []privacy.ProcessingOperator{{Issuer: "https://id.example.test", ClientID: "console", Kind: "Group", ID: "operators"}}}
}

func capacityNativeWorkload(cluster string, namespace cfg.NamespaceRef, workload cfg.WorkloadRef, n, until time.Time) app.CapacityWorkloadObservation {
	return app.CapacityWorkloadObservation{Namespace: cfg.NamespaceMetadata{ClusterID: cluster, Namespace: namespace, Labels: map[string]string{"team": "synthetic"}, ResourceVersion: "synthetic-ns-1", ObservedAt: n, FreshUntil: until}, Workload: workload, WorkloadResourceVersion: "synthetic-workload-1", ObservedAt: n, FreshUntil: until}
}

func capacityNativeTarget(cluster string, namespace cfg.NamespaceRef, workload cfg.WorkloadRef, n time.Time) targets.PodResolution {
	target := targets.PodResolution{Request: targets.Request{ClusterID: cluster, Namespace: namespace, Workload: workload, PodName: "first-synthetic", PodUID: custodyID()}, Pin: artifact.PinnedPod{Namespace: namespace.Name, NamespaceUID: namespace.UID, Name: "first-synthetic", UID: "", NodeName: "synthetic-node", ControllerUID: custodyID()}, NodeUID: custodyID(), NodeBootID: custodyID(), PodResourceVersion: "synthetic-1", WorkloadResourceVersion: "synthetic-workload-1", ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}
	target.Pin.UID = target.Request.PodUID
	return target
}

func capacityNativeContextInput(target targets.PodResolution, retained privacy.Resolution, actor identity.Principal, captureID string, n time.Time) planvalue.ContextInput {
	return planvalue.ContextInput{CaptureID: captureID, Executor: actor, Deadline: n.Add(8 * time.Second), Target: target, Retention: retained, Capability: planvalue.ContextCapability{ExecutionClass: target.ExecutionClass, Revision: identity.Revision{UID: "synthetic-capability", Generation: 1, Digest: artifact.Digest{22}}, Enabled: true, CollectorVersion: "synthetic", CollectorImageDigest: artifact.Digest{23}, ProjectionDigest: planning.ProjectionDigest(), ObservedAt: n, FreshUntil: n.Add(5 * time.Second)}}
}

func capacityNativeSession(scope artifact.DownloadScope, allocationID, sessionID string, n, plannedUntil time.Time) artifact.DownloadSession {
	return artifact.DownloadSession{ID: sessionID, AllocationID: allocationID, Scope: scope, RequestDigest: artifact.Digest{26}, State: artifact.DownloadPreparing, CreatedAt: n, Deadline: identity.Earlier(n.Add(30*time.Second), plannedUntil), OutputLimit: 8192, ReadLimit: 8 << 20, RequestLimit: 3, StopProtocol: artifact.DownloadStopProtocol}
}
