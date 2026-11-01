package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"time"

	"asservat.local/asservat/internal/adapters/objectstore/framed"
	"asservat.local/asservat/internal/application/evidence"
	"asservat.local/asservat/internal/domain/artifact"
)

// Explicit DTOs describe the supported context profile, not all future evidence
// mechanisms. The full canonical schema runs first; unsupported optional fields
// are then rejected, never silently discarded by a partial struct decoder.
type targetDTO struct {
	ExecutionClass artifact.ContextExecutionClass `json:"executionClass,omitempty"`
	ClusterID      string                         `json:"clusterID"`
	NodeUID        string                         `json:"nodeUID,omitempty"`
	NodeBootID     string                         `json:"nodeBootID,omitempty"`
	PodUID         string                         `json:"podUID"`
	Namespace      string                         `json:"namespace"`
	WorkloadUID    string                         `json:"workloadUID"`
	Scope          string                         `json:"scope"`
}
type collectorDTO struct {
	Version      string `json:"version"`
	ImageDigest  string `json:"imageDigest"`
	RecipeDigest string `json:"recipeDigest"`
}
type subjectDTO struct {
	Kind   string `json:"kind"`
	Issuer string `json:"issuer"`
	ID     string `json:"id"`
}
type assignmentDTO struct {
	Subject      subjectDTO `json:"subject"`
	Role         string     `json:"role"`
	BasisKind    string     `json:"basisKind"`
	BasisUID     string     `json:"basisUID"`
	BasisDigest  string     `json:"basisDigest"`
	AssignmentID string     `json:"assignmentID"`
}
type accessDTO struct {
	NamespaceUID string          `json:"namespaceUID"`
	Assignments  []assignmentDTO `json:"assignments"`
}
type ruleDTO struct {
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
	Digest     string `json:"digest"`
}
type retentionDTO struct {
	AnchorAt              time.Time `json:"anchorAt"`
	AnchorBasis           string    `json:"anchorBasis"`
	RequestedAgeSeconds   int64     `json:"requestedAgeSeconds"`
	ResolvedMaxAgeSeconds int64     `json:"resolvedMaxAgeSeconds"`
	DeletionBudgetSeconds int64     `json:"deletionBudgetSeconds"`
	DeleteBy              time.Time `json:"deleteBy"`
	PolicyRefs            []ruleDTO `json:"policyRefs"`
}
type privacyDTO struct {
	Classification       string `json:"classification"`
	EvidenceType         string `json:"evidenceType"`
	PurposeRef           string `json:"purposeRef"`
	ClassificationSource string `json:"classificationSource"`
}
type completenessDTO struct {
	Source     string   `json:"source"`
	Ciphertext string   `json:"ciphertext"`
	Analyzable string   `json:"analyzable"`
	Gaps       []string `json:"gaps"`
}
type sizesDTO struct {
	PlaintextBytes  int64 `json:"plaintextBytes"`
	CiphertextBytes int64 `json:"ciphertextBytes"`
}
type hashesDTO struct {
	PlaintextSHA256  string `json:"plaintextSHA256"`
	CiphertextSHA256 string `json:"ciphertextSHA256"`
}
type provenanceDTO struct {
	ParentArtifacts  []json.RawMessage `json:"parentArtifacts"`
	ToolDigests      []string          `json:"toolDigests"`
	BuildIDs         []string          `json:"buildIDs"`
	ProjectionDigest string            `json:"projectionDigest,omitempty"`
}
type originDTO struct {
	CaptureUID string `json:"captureUID"`
	ActionID   string `json:"actionID"`
	PlanDigest string `json:"planDigest"`
}
type originRefDTO struct {
	PolicyUID             string `json:"policyUID"`
	PolicyExecutionDigest string `json:"policyExecutionDigest"`
}

// The ongoing fields are present exactly for a save from an ongoing source
// (action-lifecycle.schema.json#/$defs/acquisition); gapReasons is then
// present even when empty.
type lifecycleDTO struct {
	ExecutionMode       string        `json:"executionMode"`
	TriggeredAt         time.Time     `json:"triggeredAt"`
	TriggerKind         string        `json:"triggerKind"`
	SourceSessionID     string        `json:"sourceSessionID,omitempty"`
	SourceStartedAt     time.Time     `json:"sourceStartedAt,omitzero"`
	SnapshotID          string        `json:"snapshotID,omitempty"`
	RequestedBefore     string        `json:"requestedBefore,omitempty"`
	After               string        `json:"after,omitempty"`
	HistoryCoverage     string        `json:"historyCoverage,omitempty"`
	GapReasons          *[]string     `json:"gapReasons,omitempty"`
	SourceClosedAt      time.Time     `json:"sourceClosedAt,omitzero"`
	SourceStoppedAt     time.Time     `json:"sourceStoppedAt,omitzero"`
	WindowCoverage      string        `json:"windowCoverage,omitempty"`
	RecordingSaveOrigin *originRefDTO `json:"recordingSaveOrigin,omitempty"`
}

func lifecycle(e artifact.ContextExpectation) lifecycleDTO {
	l := e.Lifecycle
	if l == nil {
		return lifecycleDTO{ExecutionMode: "onTrigger", TriggeredAt: e.TriggeredAt.UTC(), TriggerKind: "manual"}
	}
	gaps := append([]string{}, l.GapReasons...)
	d := lifecycleDTO{ExecutionMode: "ongoing", TriggeredAt: e.TriggeredAt.UTC(), TriggerKind: l.TriggerKind, SourceSessionID: l.SourceSessionID, SourceStartedAt: l.SourceStartedAt.UTC(), SnapshotID: l.SnapshotID, RequestedBefore: artifact.LifecycleDuration(l.RequestedBefore), After: artifact.LifecycleDuration(l.After), HistoryCoverage: l.HistoryCoverage, GapReasons: &gaps, WindowCoverage: l.WindowCoverage}
	if !l.SourceClosedAt.IsZero() {
		d.SourceClosedAt = l.SourceClosedAt.UTC()
	}
	if !l.SourceStoppedAt.IsZero() {
		d.SourceStoppedAt = l.SourceStoppedAt.UTC()
	}
	if l.Origin != nil {
		d.RecordingSaveOrigin = &originRefDTO{l.Origin.PolicyUID, hash(l.Origin.PolicyExecutionDigest)}
	}
	return d
}

// completeness reports a save's source coverage truthfully: only a fully
// covered window is complete; its gap reasons are the recorded gaps.
func completeness(e artifact.ContextExpectation) completenessDTO {
	l := e.Lifecycle
	if l == nil {
		return completenessDTO{"complete", "complete", "true", []string{}}
	}
	source := map[string]string{"full": "complete", "partial": "partial", "none": "partial", "unknown": "unknown"}[l.WindowCoverage]
	return completenessDTO{source, "complete", "true", append([]string{}, l.GapReasons...)}
}

type identityDTO struct {
	ETag      string  `json:"etag"`
	VersionID *string `json:"versionID"`
}
type storageDTO struct {
	Data  identityDTO `json:"data"`
	Index identityDTO `json:"index"`
}
type contextDTO struct {
	SourceSnapshotManifest *sourceSnapshotManifestDTO `json:"sourceSnapshotManifest,omitempty"`
	SchemaVersion          string                     `json:"schemaVersion"`
	ArtifactID             string                     `json:"artifactID"`
	CaseID                 string                     `json:"caseID"`
	OccurrenceID           string                     `json:"occurrenceID"`
	Target                 targetDTO                  `json:"target"`
	Kind                   string                     `json:"kind"`
	MediaType              string                     `json:"mediaType"`
	Format                 string                     `json:"format"`
	DataClass              string                     `json:"dataClass"`
	Collector              collectorDTO               `json:"collector"`
	StartedAt              time.Time                  `json:"startedAt"`
	CompletedAt            time.Time                  `json:"completedAt"`
	ExpiresAt              time.Time                  `json:"expiresAt"`
	Completeness           completenessDTO            `json:"completeness"`
	Sizes                  sizesDTO                   `json:"sizes"`
	Hashes                 hashesDTO                  `json:"hashes"`
	Encryption             json.RawMessage            `json:"encryption"`
	Provenance             provenanceDTO              `json:"provenance"`
	AccessProvenance       accessDTO                  `json:"accessProvenance"`
	Privacy                privacyDTO                 `json:"privacy"`
	Retention              retentionDTO               `json:"retention"`
	CollectionProvenance   originDTO                  `json:"collectionProvenance"`
	ActionLifecycle        lifecycleDTO               `json:"actionLifecycle"`
	StorageObjects         storageDTO                 `json:"storageObjects"`
}

func hash(h artifact.Digest) string { return hex.EncodeToString(h[:]) }
func identity(r artifact.CopyReceipt) identityDTO {
	var v *string
	if r.VersionID != "" {
		s := r.VersionID
		v = &s
	}
	return identityDTO{r.ETag, v}
}
func decode(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return artifact.ErrInvalid
	}
	return nil
}

func contextDocument(e artifact.ContextExpectation, l artifact.Layout, c artifact.Copies, started, completed time.Time) (contextDTO, error) {
	t := e.Type()
	if e.Validate() != nil || !evidence.ValidSourceSnapshotManifest(e) || l.Validate() != nil || l.Binding != e.Binding() || l.NativeBytes > e.Registration.NativeLimit || l.NativeBytes > t.MaxBytes {
		return contextDTO{}, artifact.ErrInvalid
	}
	for i := 0; i < 2; i++ {
		if c[i].Bytes < 1 || c[i].Bytes > e.Registration.Limits()[i] || c[i].ETag == "" || len(c[i].ETag) > 1024 || len(c[i].VersionID) > 1024 {
			return contextDTO{}, artifact.ErrInvalid
		}
	}
	if l.DataBytes != c[0].Bytes || l.IndexBytes != c[1].Bytes || l.DataSHA256 != c[0].SHA256 || l.IndexSHA256 != c[1].SHA256 {
		return contextDTO{}, artifact.ErrIntegrity
	}
	r := e.Registration
	if started.IsZero() || completed.IsZero() || started.Before(r.AnchorAt) || completed.Before(started) || !completed.Before(r.WriteUntil) {
		return contextDTO{}, artifact.ErrInvalid
	}
	// An onTrigger acquisition starts at or after its trigger. A save from an
	// ongoing source may start before t0 (its prehistory), never before the
	// source itself started recording.
	if e.Lifecycle == nil && e.TriggeredAt.After(started) || e.Lifecycle != nil && started.Before(e.Lifecycle.SourceStartedAt) {
		return contextDTO{}, artifact.ErrInvalid
	}
	if e.Snapshot != nil {
		a, b := artifact.SourceSnapshotAcquisition(artifact.SourceSnapshotCoverage{Request: *e.Snapshot, SourceStoppedAt: e.Lifecycle.SourceStoppedAt, SourceClosedAt: e.Lifecycle.SourceClosedAt})
		if !started.Equal(a) || !completed.Equal(b) {
			return contextDTO{}, artifact.ErrInvalid
		}
	}
	encryption, err := framed.MarshalLayout(l)
	if err != nil {
		return contextDTO{}, err
	}
	assignments := make([]assignmentDTO, len(e.Audience))
	for i, a := range e.Audience {
		assignments[i] = assignmentDTO{Subject: subjectDTO{a.Kind, a.Issuer, a.SubjectID}, Role: a.Role, BasisKind: a.BasisKind, BasisUID: a.BasisUID, BasisDigest: hash(a.BasisDigest), AssignmentID: a.AssignmentID}
	}
	rules := make([]ruleDTO, len(e.RetentionRules))
	for i, p := range e.RetentionRules {
		rules[i] = ruleDTO{p.UID, p.Generation, hash(p.Digest)}
	}
	// Only pod status has a fixed projection definition; recorder projections
	// (packet sanitizer, HTTP field set) are bound by their producing increments.
	projection := ""
	if e.NativeType == artifact.PodStatusArtifact {
		projection = hash(artifact.Digest(sha256.Sum256([]byte(artifact.ContextProjectionDefinition))))
	}
	return contextDTO{
		SourceSnapshotManifest: snapshotManifest(e),
		SchemaVersion:          "artifact/v1", ArtifactID: r.Location.ArtifactID, CaseID: e.CaseID, OccurrenceID: e.OccurrenceID,
		Target: targetDTO{ExecutionClass: e.ExecutionClass, ClusterID: r.Location.ClusterID, NodeUID: e.NodeUID, NodeBootID: e.NodeBootID, PodUID: e.PodUID, Namespace: e.Namespace, WorkloadUID: e.WorkloadUID, Scope: "pod"},
		Kind:   t.Kind, MediaType: t.MediaType, Format: t.Format, DataClass: e.DataClass,
		Collector: collectorDTO{e.CollectorVersion, hash(e.CollectorImageDigest), hash(e.RecipeDigest)}, StartedAt: started.UTC(), CompletedAt: completed.UTC(), ExpiresAt: r.ExpiresAt.UTC(),
		Completeness: completeness(e), Sizes: sizesDTO{l.NativeBytes, l.DataBytes}, Hashes: hashesDTO{hash(l.NativeSHA256), hash(l.DataSHA256)}, Encryption: encryption,
		Provenance:       provenanceDTO{[]json.RawMessage{}, []string{hash(e.CollectorImageDigest)}, []string{}, projection},
		AccessProvenance: accessDTO{e.NamespaceUID, assignments}, Privacy: privacyDTO{"potentialPersonalData", t.EvidenceType, e.PurposeRef, "default"},
		Retention:            retentionDTO{r.AnchorAt.UTC(), "acquisition", e.RequestedAgeSeconds, e.MaximumAgeSeconds, e.DeletionBudgetSeconds, r.DeleteBy.UTC(), rules},
		CollectionProvenance: originDTO{e.CaptureUID, e.ActionID, hash(e.PlanDigest)}, ActionLifecycle: lifecycle(e), StorageObjects: storageDTO{identity(c[0]), identity(c[1])},
	}, nil
}

func (v *Validator) MarshalContext(e artifact.ContextExpectation, l artifact.Layout, c artifact.Copies, started, completed time.Time) ([]byte, error) {
	d, err := contextDocument(e, l, c, started, completed)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(d)
	if e.SourceSnapshotManifest != nil {
		var out bytes.Buffer
		encoder := json.NewEncoder(&out)
		encoder.SetEscapeHTML(false)
		err = encoder.Encode(d)
		b = bytes.TrimSuffix(out.Bytes(), []byte("\n"))
	}
	if err != nil {
		return nil, artifact.ErrInvalid
	}
	if err = validate(v.manifest, b, artifact.MaxRootBytes); err != nil {
		return nil, err
	}
	return b, nil
}

type ContextManifest struct {
	Layout                 artifact.Layout
	StartedAt, CompletedAt time.Time
}

func (v *Validator) ParseContext(b []byte, e artifact.ContextExpectation, c artifact.Copies) (ContextManifest, error) {
	var result ContextManifest
	if e.Validate() != nil || c.Validate(e.Registration) != nil {
		return result, artifact.ErrInvalid
	}
	if err := validate(v.manifest, b, artifact.MaxRootBytes); err != nil {
		return result, err
	}
	var actual contextDTO
	if err := decode(b, &actual); err != nil {
		return result, err
	}
	l, err := framed.ParseLayout(actual.Encryption, e.Binding())
	if err != nil {
		return result, err
	}
	expected, err := contextDocument(e, l, c, actual.StartedAt, actual.CompletedAt)
	if err != nil {
		return result, err
	}
	// All control metadata is checked against independently accepted facts.
	// Layout already underwent its strict binding/range validation above.
	actual.Encryption = nil
	expected.Encryption = nil
	actual.StartedAt = actual.StartedAt.UTC()
	actual.CompletedAt = actual.CompletedAt.UTC()
	actual.ExpiresAt = actual.ExpiresAt.UTC()
	actual.Retention.AnchorAt = actual.Retention.AnchorAt.UTC()
	actual.Retention.DeleteBy = actual.Retention.DeleteBy.UTC()
	actual.ActionLifecycle.TriggeredAt = actual.ActionLifecycle.TriggeredAt.UTC()
	actual.ActionLifecycle.SourceStartedAt = actual.ActionLifecycle.SourceStartedAt.UTC()
	actual.ActionLifecycle.SourceClosedAt = actual.ActionLifecycle.SourceClosedAt.UTC()
	actual.ActionLifecycle.SourceStoppedAt = actual.ActionLifecycle.SourceStoppedAt.UTC()
	if !reflect.DeepEqual(actual, expected) {
		return result, artifact.ErrIntegrity
	}
	return ContextManifest{l, actual.StartedAt, actual.CompletedAt}, nil
}

type podDTO struct {
	Format           string    `json:"format"`
	NamespaceUID     string    `json:"namespaceUID"`
	PodUID           string    `json:"podUID"`
	ResourceVersion  string    `json:"resourceVersion"`
	ObservedAt       time.Time `json:"observedAt"`
	Phase            string    `json:"phase"`
	Ready            string    `json:"ready"`
	Initialized      string    `json:"initialized"`
	Scheduled        string    `json:"scheduled"`
	RuntimeInstances int       `json:"runtimeInstances"`
	Running          int       `json:"running"`
	Waiting          int       `json:"waiting"`
	Terminated       int       `json:"terminated"`
	Restarts         int64     `json:"restarts"`
}

func (v *Validator) ValidateNative(b []byte, e artifact.ContextExpectation, m ContextManifest) error {
	if e.Validate() != nil || e.NativeType != artifact.PodStatusArtifact {
		return artifact.ErrInvalid
	}
	if err := validate(v.pod, b, artifact.MaxContextBytes); err != nil {
		return err
	}
	var pod podDTO
	if err := decode(b, &pod); err != nil {
		return err
	}
	if pod.NamespaceUID != e.NamespaceUID || pod.PodUID != e.PodUID || pod.ObservedAt.Before(m.StartedAt) || pod.ObservedAt.After(m.CompletedAt) || pod.Running+pod.Waiting+pod.Terminated > pod.RuntimeInstances {
		return artifact.ErrIntegrity
	}
	return nil
}

type sourceSnapshotManifestDTO struct {
	CanonicalScope json.RawMessage `json:"canonicalScope"`
	Binding        json.RawMessage `json:"binding"`
}

func snapshotManifest(e artifact.ContextExpectation) *sourceSnapshotManifestDTO {
	if e.SourceSnapshotManifest == nil {
		return nil
	}
	return &sourceSnapshotManifestDTO{json.RawMessage(e.SourceSnapshotManifest.CanonicalScope), json.RawMessage(e.SourceSnapshotManifest.Binding)}
}
