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
	ProjectionDigest string            `json:"projectionDigest"`
}
type originDTO struct {
	CaptureUID string `json:"captureUID"`
	ActionID   string `json:"actionID"`
	PlanDigest string `json:"planDigest"`
}
type lifecycleDTO struct {
	ExecutionMode string    `json:"executionMode"`
	TriggeredAt   time.Time `json:"triggeredAt"`
	TriggerKind   string    `json:"triggerKind"`
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
	SchemaVersion        string          `json:"schemaVersion"`
	ArtifactID           string          `json:"artifactID"`
	CaseID               string          `json:"caseID"`
	OccurrenceID         string          `json:"occurrenceID"`
	Target               targetDTO       `json:"target"`
	Kind                 string          `json:"kind"`
	MediaType            string          `json:"mediaType"`
	Format               string          `json:"format"`
	DataClass            string          `json:"dataClass"`
	Collector            collectorDTO    `json:"collector"`
	StartedAt            time.Time       `json:"startedAt"`
	CompletedAt          time.Time       `json:"completedAt"`
	ExpiresAt            time.Time       `json:"expiresAt"`
	Completeness         completenessDTO `json:"completeness"`
	Sizes                sizesDTO        `json:"sizes"`
	Hashes               hashesDTO       `json:"hashes"`
	Encryption           json.RawMessage `json:"encryption"`
	Provenance           provenanceDTO   `json:"provenance"`
	AccessProvenance     accessDTO       `json:"accessProvenance"`
	Privacy              privacyDTO      `json:"privacy"`
	Retention            retentionDTO    `json:"retention"`
	CollectionProvenance originDTO       `json:"collectionProvenance"`
	ActionLifecycle      lifecycleDTO    `json:"actionLifecycle"`
	StorageObjects       storageDTO      `json:"storageObjects"`
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
	if e.Validate() != nil || l.Validate() != nil || l.Binding != e.Binding() || l.NativeBytes > e.Registration.NativeLimit || l.NativeBytes > artifact.MaxContextBytes {
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
	if started.IsZero() || completed.IsZero() || started.Before(r.AnchorAt) || completed.Before(started) || !completed.Before(r.WriteUntil) || e.TriggeredAt.After(started) {
		return contextDTO{}, artifact.ErrInvalid
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
	projection := artifact.Digest(sha256.Sum256([]byte(artifact.ContextProjectionDefinition)))
	return contextDTO{
		SchemaVersion: "artifact/v1", ArtifactID: r.Location.ArtifactID, CaseID: e.CaseID, OccurrenceID: e.OccurrenceID,
		Target: targetDTO{ExecutionClass: e.ExecutionClass, ClusterID: r.Location.ClusterID, NodeUID: e.NodeUID, NodeBootID: e.NodeBootID, PodUID: e.PodUID, Namespace: e.Namespace, WorkloadUID: e.WorkloadUID, Scope: "pod"},
		Kind:   "kubernetesSnapshot", MediaType: "application/json", Format: artifact.ContextFormat, DataClass: e.DataClass,
		Collector: collectorDTO{e.CollectorVersion, hash(e.CollectorImageDigest), hash(e.RecipeDigest)}, StartedAt: started.UTC(), CompletedAt: completed.UTC(), ExpiresAt: r.ExpiresAt.UTC(),
		Completeness: completenessDTO{"complete", "complete", "true", []string{}}, Sizes: sizesDTO{l.NativeBytes, l.DataBytes}, Hashes: hashesDTO{hash(l.NativeSHA256), hash(l.DataSHA256)}, Encryption: encryption,
		Provenance:       provenanceDTO{[]json.RawMessage{}, []string{hash(e.CollectorImageDigest)}, []string{}, hash(projection)},
		AccessProvenance: accessDTO{e.NamespaceUID, assignments}, Privacy: privacyDTO{"potentialPersonalData", "context", e.PurposeRef, "default"},
		Retention:            retentionDTO{r.AnchorAt.UTC(), "acquisition", e.RequestedAgeSeconds, e.MaximumAgeSeconds, e.DeletionBudgetSeconds, r.DeleteBy.UTC(), rules},
		CollectionProvenance: originDTO{e.CaptureUID, e.ActionID, hash(e.PlanDigest)}, ActionLifecycle: lifecycleDTO{"onTrigger", e.TriggeredAt.UTC(), "manual"}, StorageObjects: storageDTO{identity(c[0]), identity(c[1])},
	}, nil
}

func (v *Validator) MarshalContext(e artifact.ContextExpectation, l artifact.Layout, c artifact.Copies, started, completed time.Time) ([]byte, error) {
	d, err := contextDocument(e, l, c, started, completed)
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(d)
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
	if e.Validate() != nil {
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
