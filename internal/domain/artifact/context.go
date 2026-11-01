package artifact

import "time"

const ContextFormat = "asservat-pod-status/v1"
const MaxContextBytes = 4096

// This definition is immutable and hashed by adapters. It describes a projection,
// not permission to acquire it or to publish its result as metadata.
const ContextProjectionDefinition = `{"format":"asservat-pod-status/v1","fields":["namespaceUID","podUID","resourceVersion","observedAt","phase","ready","initialized","scheduled","runtimeInstances","running","waiting","terminated","restarts"],"exclude":["labels","annotations","spec","messages","reasons","environment","logs","addresses","containerNames"]}`

// PinnedPod is resolved by the application from a currently authorized target.
// It is not a selector, proof of authorization, or public acquisition API.
type PinnedPod struct {
	Namespace, NamespaceUID, Name, UID, NodeName, ControllerUID string
}

type AudienceAssignment struct {
	Kind, Issuer, SubjectID, Role, BasisKind, BasisUID, AssignmentID string
	BasisDigest                                                      Digest
}
type RetentionRule struct {
	UID        string
	Generation int64
	Digest     Digest
}

// ContextExpectation is constructed from accepted execution/provenance and
// retention facts, independently of the writer's manifest. It confers no rights.
// NativeType selects a registered native artifact type (ADR-244); the empty
// historical value is pod status, whose serialized form and digest are
// unchanged. Lifecycle is set only for a save from an ongoing source.
type ContextExpectation struct {
	SourceSnapshotManifest                                            *SourceSnapshotManifest `json:",omitempty"`
	Snapshot                                                          *SourceSnapshotRequest  `json:",omitempty"`
	ExecutionClass                                                    ContextExecutionClass   `json:",omitempty"`
	NativeType                                                        string                  `json:",omitempty"`
	Lifecycle                                                         *OngoingLifecycle       `json:",omitempty"`
	Recording                                                         *Recording              `json:",omitempty"`
	Registration                                                      Registration
	CaseID, OccurrenceID                                              string
	NodeUID, NodeBootID, PodUID, Namespace, NamespaceUID, WorkloadUID string
	CollectorVersion                                                  string
	CollectorImageDigest, RecipeDigest, PlanDigest                    Digest
	CaptureUID, ActionID, DataClass, PurposeRef                       string
	Audience                                                          []AudienceAssignment
	RequestedAgeSeconds, MaximumAgeSeconds, DeletionBudgetSeconds     int64
	RetentionRules                                                    []RetentionRule
	TriggeredAt                                                       time.Time
}

// Type returns the registered native type; Validate rejects unknown names.
func (e ContextExpectation) Type() NativeType {
	t, _ := LookupNativeType(e.NativeType)
	return t
}

func (e ContextExpectation) Binding() Binding {
	l := e.Registration.Location
	return Binding{ClusterID: l.ClusterID, ArtifactID: l.ArtifactID, AttemptID: l.AttemptID, MediaType: e.Type().MediaType}
}

func (e ContextExpectation) Validate() error {
	r := e.Registration
	t, known := LookupNativeType(e.NativeType)
	if !known || r.Validate() != nil || r.NativeLimit > t.MaxBytes || !uuid(e.CaseID) || !uuid(e.OccurrenceID) || !e.ExecutionClass.ValidNodeIdentity(e.NodeUID, e.NodeBootID) || !uuid(e.CaptureUID) || e.TriggeredAt.IsZero() || e.TriggeredAt.After(r.WriteUntil) {
		return ErrInvalid
	}
	if !t.AllowsClass(e.DataClass) {
		return ErrInvalid
	}
	// The API class runs pod status, or (ADR-248) a manual networkHeaders
	// recording on the target's node collector, delivered through the connector.
	podStatus := e.NativeType == PodStatusArtifact && e.ActionID == "pod-status" && e.DataClass == "metadata" && r.NativeLimit == MaxContextBytes && e.Recording == nil
	recording := e.NativeType == PCAPNGArtifact && recorderActionID(e.ActionID) && e.DataClass == "metadata" && r.NativeLimit == RecordingNativeLimit && e.Recording.Valid() && e.Lifecycle == nil
	snapshot := e.NativeType == PCAPNGArtifact && recorderActionID(e.ActionID) && e.DataClass == "metadata" && e.Recording == nil && e.Snapshot != nil && e.Snapshot.Valid() && e.SourceSnapshotManifest.Valid() && e.Snapshot.MaxBytes == r.NativeLimit && !e.Snapshot.ProcessingUntil.After(r.WriteUntil) && e.Snapshot.T0.Equal(e.TriggeredAt) && SourceSnapshotAnchor(*e.Snapshot).Equal(r.AnchorAt) && e.Lifecycle != nil && e.Lifecycle.SourceSessionID == e.Snapshot.SourceID && e.Lifecycle.SnapshotID == e.Snapshot.SnapshotID && e.Lifecycle.SourceStartedAt.Equal(e.Snapshot.SourceStartedAt) && e.Lifecycle.RequestedBefore == e.Snapshot.Before && e.Lifecycle.After == e.Snapshot.After
	if e.ExecutionClass == ContextAPIExecution && !podStatus && !recording && !snapshot || e.Recording != nil && !recording || e.Snapshot != nil && !snapshot || e.SourceSnapshotManifest != nil && !snapshot {
		return ErrInvalid
	}
	// Pod status is an onTrigger snapshot; only recorder types save from an
	// ongoing source, whose window and coverage are checked against t0.
	if e.Lifecycle != nil && (e.NativeType == PodStatusArtifact || e.Lifecycle.Validate(e.TriggeredAt) != nil) {
		return ErrInvalid
	}
	for _, s := range []string{e.PodUID, e.NamespaceUID, e.WorkloadUID, e.CollectorVersion} {
		if len(s) < 1 || len(s) > 64 {
			return ErrInvalid
		}
	}
	if len(e.Namespace) < 1 || len(e.Namespace) > 63 || len(e.ActionID) < 1 || len(e.ActionID) > 63 || len(e.PurposeRef) < 1 || len(e.PurposeRef) > 128 {
		return ErrInvalid
	}
	if e.CollectorImageDigest == (Digest{}) || e.RecipeDigest == (Digest{}) || e.PlanDigest == (Digest{}) || len(e.Audience) < 1 || len(e.Audience) > 32 || len(e.RetentionRules) < 1 || len(e.RetentionRules) > 64 {
		return ErrInvalid
	}
	for _, a := range e.Audience {
		if !uuid(a.AssignmentID) || len(a.Kind) > 16 || len(a.Issuer) < 1 || len(a.Issuer) > 2048 || len(a.SubjectID) < 1 || len(a.SubjectID) > 256 || len(a.Role) > 32 || len(a.BasisKind) > 32 || len(a.BasisUID) < 1 || len(a.BasisUID) > 64 || a.BasisDigest == (Digest{}) {
			return ErrInvalid
		}
	}
	for _, p := range e.RetentionRules {
		if len(p.UID) < 1 || len(p.UID) > 64 || p.Generation < 1 || p.Generation > 2147483647 || p.Digest == (Digest{}) {
			return ErrInvalid
		}
	}
	if e.RequestedAgeSeconds < 1 || e.RequestedAgeSeconds > 315360000 || e.MaximumAgeSeconds < 1 || e.MaximumAgeSeconds > 315360000 || e.DeletionBudgetSeconds < 1 || e.DeletionBudgetSeconds > 86400 || e.DeletionBudgetSeconds >= e.MaximumAgeSeconds {
		return ErrInvalid
	}
	expires := r.AnchorAt.Add(time.Duration(min(e.RequestedAgeSeconds, e.MaximumAgeSeconds-e.DeletionBudgetSeconds)) * time.Second)
	deleteBy := expires.Add(time.Duration(e.DeletionBudgetSeconds) * time.Second)
	if !r.ExpiresAt.Equal(expires) || !r.DeleteBy.Equal(deleteBy) {
		return ErrInvalid
	}
	return nil
}
