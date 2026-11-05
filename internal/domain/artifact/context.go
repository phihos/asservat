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
	Processes *ProcessCapture `json:",omitempty"`
	// Logs binds a finite raw whole-Pod logs action; nil preserves old digests.
	Logs *LogCapture `json:",omitempty"`
	// Profile is a Go endpoint profile's accepted request (ADR-284); nil
	// otherwise, so other digests are unchanged.
	Profile *GoProfileAcquisition `json:",omitempty"`
	// CompositionGroup binds one recording of a manual composition group
	// (ADR-276) to its parent; nil otherwise, so other digests are unchanged.
	CompositionGroup                                                  *CompositionGroupBinding `json:",omitempty"`
	SourceSnapshotManifest                                            *SourceSnapshotManifest  `json:",omitempty"`
	Snapshot                                                          *SourceSnapshotRequest   `json:",omitempty"`
	ExecutionClass                                                    ContextExecutionClass    `json:",omitempty"`
	NativeType                                                        string                   `json:",omitempty"`
	Lifecycle                                                         *OngoingLifecycle        `json:",omitempty"`
	Recording                                                         *Recording               `json:",omitempty"`
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

// ServedClass reports a class the installed publication and download path
// carries: metadata, raw packet captures and Go profiles, and extract only
// as an HTTP header projection. It is not access: a raw
// disclosure still needs its approved grant child.
func (e ContextExpectation) ServedClass() bool {
	return e.DataClass == "metadata" || e.DataClass == "raw" && (e.NativeType == RawPCAPNGArtifact || e.NativeType == SyscallArgumentsArtifact || e.NativeType == PprofArtifact || e.NativeType == GoTraceArtifact || e.NativeType == LogsArtifact) || e.DataClass == "extract" && e.NativeType == HTTPHeadersArtifact
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
	// ADR-279: the raw profile, raw native type and raw class come together;
	// ADR-282: so do the httpHeaders profile, its JSON type and extract.
	raw := e.Recording != nil && e.Recording.Profile == "rawPackets"
	http := e.Recording != nil && e.Recording.Profile == "httpHeaders"
	recording := (e.NativeType == PCAPNGArtifact && e.Recording != nil && e.Recording.Kind == "packetCapture" && !raw && !http && e.DataClass == "metadata" || e.NativeType == RawPCAPNGArtifact && raw && e.DataClass == "raw" || e.NativeType == HTTPHeadersArtifact && http && e.DataClass == "extract" || e.NativeType == SyscallRecordsArtifact && e.Recording != nil && e.Recording.Kind == "syscallTrace" && e.Recording.Profile == "metadata" && e.DataClass == "metadata" || e.NativeType == SyscallArgumentsArtifact && e.Recording != nil && e.Recording.Kind == "syscallTrace" && e.Recording.Profile == "arguments" && e.DataClass == "raw") && recorderActionID(e.ActionID) && r.NativeLimit == RecordingNativeLimit && e.Recording.Valid() && e.Lifecycle == nil
	snapshot := (e.NativeType == PCAPNGArtifact || e.NativeType == SyscallRecordsArtifact) && recorderActionID(e.ActionID) && e.DataClass == "metadata" && e.Recording == nil && e.Snapshot != nil && e.Snapshot.Valid() && e.SourceSnapshotManifest.Valid() && e.Snapshot.MaxBytes == r.NativeLimit && !e.Snapshot.ProcessingUntil.After(r.WriteUntil) && e.Snapshot.T0.Equal(e.TriggeredAt) && SourceSnapshotAnchor(*e.Snapshot).Equal(r.AnchorAt) && e.Lifecycle != nil && e.Lifecycle.SourceSessionID == e.Snapshot.SourceID && e.Lifecycle.SnapshotID == e.Snapshot.SnapshotID && e.Lifecycle.SourceStartedAt.Equal(e.Snapshot.SourceStartedAt) && e.Lifecycle.RequestedBefore == e.Snapshot.Before && e.Lifecycle.After == e.Snapshot.After
	// ADR-284: a Go endpoint profile is a finite onTrigger raw artifact whose
	// native type follows its accepted profile type.
	profile := e.Profile.Valid() && e.Profile.NativeType() == e.NativeType && e.DataClass == "raw" && recorderActionID(e.ActionID) && e.Recording == nil && e.Snapshot == nil && e.Lifecycle == nil && e.CompositionGroup == nil
	logs := e.Logs.Valid() && e.NativeType == LogsArtifact && e.DataClass == "raw" && e.ExecutionClass == ContextAPIExecution && e.Logs.ActionID == e.ActionID && e.Logs.MaxNativeBytes == r.NativeLimit && e.Recording == nil && e.Profile == nil && e.Snapshot == nil && e.SourceSnapshotManifest == nil && e.Lifecycle == nil
	processes := e.Processes.Valid() && e.NativeType == ProcessesArtifact && e.DataClass == "metadata" && e.ExecutionClass == ContextAPIExecution && e.Processes.ActionID == e.ActionID && e.Processes.MaxNativeBytes == r.NativeLimit && e.Recording == nil && e.Profile == nil && e.Logs == nil && e.Snapshot == nil && e.SourceSnapshotManifest == nil && e.Lifecycle == nil && e.CompositionGroup == nil
	if logs {
		_, end, err := e.Logs.Window(e.TriggeredAt)
		logs = err == nil && end.Before(r.WriteUntil)
	}
	isProfile := e.NativeType == PprofArtifact || e.NativeType == GoTraceArtifact
	if (e.NativeType == ProcessesArtifact || e.Processes != nil) && !processes || e.Processes != nil && !processes || (e.NativeType == LogsArtifact || e.Logs != nil) && !logs || e.CompositionGroup != nil && (!e.CompositionGroup.Valid() || !recording && !logs) || (e.NativeType == HTTPHeadersArtifact || e.NativeType == SyscallArgumentsArtifact) && !recording || (isProfile || e.Profile != nil) && !profile ||
		e.ExecutionClass == ContextAPIExecution && !podStatus && !recording && !snapshot && !profile && !logs && !processes || e.Recording != nil && !recording || e.Snapshot != nil && !snapshot || e.SourceSnapshotManifest != nil && !snapshot {
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

// CompositionGroupBinding is a composition child's place in its group
// (ADR-276).
type CompositionGroupBinding struct {
	ParentCaptureID        string
	ChildIndex, ChildCount int
}

// Valid checks the binding's own bounds.
func (b *CompositionGroupBinding) Valid() bool {
	return b != nil && len(b.ParentCaptureID) == 36 && b.ChildCount >= 2 && b.ChildCount <= 16 && b.ChildIndex >= 0 && b.ChildIndex < b.ChildCount
}
