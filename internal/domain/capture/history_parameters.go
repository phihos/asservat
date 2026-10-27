package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"io"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

const (
	HistoryParametersFormat      = "capture-parameters/v1"
	HistoryParametersMedia       = "application/vnd.asservat.capture-parameters+json"
	MaxHistoryParameters         = 128 << 10
	MaxHistoryManifest           = 64 << 10
	MaxHistoryPerSelector        = 1000
	MaxHistoryPerInstallation    = 100000
	MaxHistoryDataCiphertext     = MaxHistoryParameters + artifact.CipherOverhead
	MaxHistoryIndexCiphertext    = 4 << 10
	MaxHistoryManifestCiphertext = MaxHistoryManifest + artifact.CipherOverhead
	MaxHistoryCommitCiphertext   = 32 << 10
	// Array brackets, three commas and eight quotes, then exact base64 sizes.
	HistoryBundleMaxBytes = int(13 + 4*((MaxHistoryDataCiphertext+2)/3+(MaxHistoryIndexCiphertext+2)/3+(MaxHistoryManifestCiphertext+2)/3+(MaxHistoryCommitCiphertext+2)/3))
)

// HistoryCiphertextLimits derive the finite transport bound without reducing
// the generic custody reservation. One snapshot occupies one index page.
func HistoryCiphertextLimits() [4]int64 {
	return [4]int64{MaxHistoryDataCiphertext, MaxHistoryIndexCiphertext, MaxHistoryManifestCiphertext, MaxHistoryCommitCiphertext}
}

type HistoryCiphertexts [4][]byte

func (b HistoryCiphertexts) Valid() bool {
	limits := HistoryCiphertextLimits()
	for i, v := range b {
		if len(v) == 0 || int64(len(v)) > limits[i] {
			return false
		}
	}
	return true
}
func (b HistoryCiphertexts) Clear() {
	for _, v := range b {
		clear(v)
	}
}
func (b HistoryCiphertexts) PhysicalBytes() int64 {
	var n int64
	for _, v := range b {
		n += int64(len(v))
	}
	return n
}

var (
	ErrSettingsUnavailable      = errors.New("saved capture settings unavailable")
	ErrSettingsTooLarge         = errors.New("saved capture settings exceed the response limit")
	ErrHistoryUnavailable       = errors.New("capture history projection unavailable")
	ErrHistorySelectionRequired = errors.New("choose a current manual Pod selection")
	ErrProfileChanged           = errors.New("saved dependency version is unavailable or changed")
)

// HistorySelector groups the authored selector, not the Pods it resolved to.
// MatchLabels and WorkloadUID are exclusive; current transports may support a
// narrower target vocabulary without changing this canonical identity.
type HistorySelector struct {
	ClusterID, NamespaceUID   string
	WorkloadKind, WorkloadUID string            `json:",omitempty"`
	MatchLabels               map[string]string `json:",omitempty"`
}

func (s HistorySelector) Valid() bool {
	if !authorization.UUID(s.ClusterID) || !identity.Text(s.NamespaceUID, 64) {
		return false
	}
	if len(s.MatchLabels) != 0 {
		if s.WorkloadKind != "" || s.WorkloadUID != "" || len(s.MatchLabels) > 32 {
			return false
		}
		for k, v := range s.MatchLabels {
			if !identity.Text(k, 253) || len(v) > 63 {
				return false
			}
		}
		return true
	}
	return (s.WorkloadKind == "Deployment" || s.WorkloadKind == "StatefulSet" || s.WorkloadKind == "Pod") && identity.Text(s.WorkloadUID, 64)
}

// HistoryParameters contains user-authored control data, never sampled output
// or transferable authority. It exists only in bounded memory or encrypted
// objects; SQL stores its keyed identity and ciphertext receipts.
type HistoryParameters struct {
	ExplicitPodUID                             string `json:",omitempty"`
	Format                                     string
	Target                                     targets.WorkloadRequest
	NamespaceUID, WorkloadUID                  string
	Diagnostic                                 string                       `json:",omitempty"`
	Composition                                *planning.ProfileComposition `json:",omitempty"`
	RecipeJSON, DependencyJSON                 json.RawMessage
	FrozenFilters                              json.RawMessage  `json:",omitempty"`
	AuthoredTargetJSON, CompositionJSON        json.RawMessage  `json:",omitempty"`
	SelectorIdentity                           *HistorySelector `json:",omitempty"`
	RequestedSeconds, OriginalEffectiveSeconds int64
	PolicyOrigins                              []HistoryPolicyOrigin `json:",omitempty"`
	Selection                                  string                `json:",omitempty"`
	OriginalExecutionDigest                    artifact.Digest
}

func (p HistoryParameters) Valid() bool {
	if (p.Target.Kind == "Pod" && !identity.Text(p.ExplicitPodUID, 64)) || (p.Target.Kind != "Pod" && p.ExplicitPodUID != "") || p.Format != HistoryParametersFormat || !p.Target.Valid() || !identity.Text(p.NamespaceUID, 64) || !identity.Text(p.WorkloadUID, 64) ||
		p.RequestedSeconds < 0 || p.RequestedSeconds > privacy.MaxAgeSeconds || p.OriginalEffectiveSeconds < 1 || p.OriginalEffectiveSeconds > privacy.MaxAgeSeconds || p.OriginalExecutionDigest == (artifact.Digest{}) ||
		!json.Valid(p.RecipeJSON) || !json.Valid(p.DependencyJSON) || len(p.RecipeJSON) == 0 || len(p.DependencyJSON) == 0 {
		return false
	}
	if (len(p.FrozenFilters) > 0 && !json.Valid(p.FrozenFilters)) || len(p.PolicyOrigins) > 16 || (p.Selection != "" && p.Selection != "triggeringPod" && p.Selection != "allWithinLimit" && p.Selection != "explicitPod") {
		return false
	}
	for _, origin := range p.PolicyOrigins {
		if !origin.Valid() {
			return false
		}
	}
	if (len(p.AuthoredTargetJSON) > 0 && !json.Valid(p.AuthoredTargetJSON)) || (len(p.CompositionJSON) > 0 && !json.Valid(p.CompositionJSON)) || (p.SelectorIdentity != nil && (!p.SelectorIdentity.Valid() || p.SelectorIdentity.ClusterID != p.Target.ClusterID || p.SelectorIdentity.NamespaceUID != p.NamespaceUID)) {
		return false
	}
	if p.Composition != nil {
		return p.Diagnostic == "" && p.Composition.Valid()
	}
	return p.Diagnostic == ContextDiagnosticName
}

func (p HistoryParameters) Selector() HistorySelector {
	if p.Target.Kind == "Pod" {
		return HistorySelector{ClusterID: p.Target.ClusterID, NamespaceUID: p.NamespaceUID, WorkloadKind: "Pod", WorkloadUID: p.ExplicitPodUID}
	}
	if p.SelectorIdentity != nil {
		return *p.SelectorIdentity
	}
	return HistorySelector{ClusterID: p.Target.ClusterID, NamespaceUID: p.NamespaceUID, WorkloadKind: p.Target.Kind, WorkloadUID: p.WorkloadUID}
}

func CanonicalHistoryParameters(p HistoryParameters) ([]byte, error) {
	if !p.Valid() {
		return nil, ErrInvalid
	}
	b, e := json.Marshal(p)
	if e != nil || len(b) > MaxHistoryParameters {
		clear(b)
		return nil, ErrSettingsTooLarge
	}
	c := jsontext.Value(b)
	if c.Canonicalize() != nil {
		clear(b)
		return nil, ErrInvalid
	}
	return c, nil
}

func ParseHistoryParameters(b []byte) (HistoryParameters, error) {
	var p HistoryParameters
	if len(b) == 0 || len(b) > MaxHistoryParameters {
		return p, ErrSettingsTooLarge
	}
	c := jsontext.Value(bytes.Clone(b))
	defer clear(c)
	if c.Canonicalize() != nil || !bytes.Equal(c, b) {
		return p, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || !p.Valid() {
		return HistoryParameters{}, ErrInvalid
	}
	return p, nil
}

// HistoryExpectation is independently obtained from accepted capture and
// protected storage facts. It is not an evidence expectation or catalog entry.
type HistoryExpectation struct {
	RootID, CaptureID        string
	Registration             artifact.Registration
	SelectorKey, SettingsKey artifact.Digest
	MACVersion               string
	OriginalExecutionDigest  artifact.Digest
}

func (e HistoryExpectation) Valid() bool {
	return authorization.UUID(e.RootID) && authorization.UUID(e.CaptureID) && e.Registration.Validate() == nil && e.Registration.NativeLimit == MaxHistoryParameters &&
		e.SelectorKey != (artifact.Digest{}) && e.SettingsKey != (artifact.Digest{}) && identity.Text(e.MACVersion, 64) && e.OriginalExecutionDigest != (artifact.Digest{})
}

func (e HistoryExpectation) Binding() artifact.Binding {
	r := e.Registration.Location
	return artifact.Binding{ClusterID: r.ClusterID, ArtifactID: r.ArtifactID, AttemptID: r.AttemptID, MediaType: HistoryParametersMedia}
}

func (e HistoryExpectation) Matches(p HistoryParameters) bool {
	return e.Valid() && p.Valid() && p.Target.ClusterID == e.Registration.Location.ClusterID && p.OriginalExecutionDigest == e.OriginalExecutionDigest
}

func HistoryExpectationDigest(e HistoryExpectation) artifact.Digest {
	b, _ := json.Marshal(e)
	return sha256.Sum256(b)
}

// HistoryOperationAuthority is a finite SQL-issued operation binding, not a
// transferable human credential. The transport signs it only after the current
// accepted-history checks and binds it to the actual hub/connector channel.
type HistoryOperationAuthority struct {
	Expectation                HistoryExpectation
	Operation, RequestID       string
	ExecutorEpoch              string
	StartedAt, NotAfter        time.Time
	BundleDigest, CopiesDigest artifact.Digest
	DeletionFence              int64
}

func (a HistoryOperationAuthority) Valid(now time.Time) bool {
	if !a.Expectation.Valid() || !authorization.UUID(a.RequestID) || !authorization.UUID(a.ExecutorEpoch) || a.StartedAt.After(now) || !now.Before(a.NotAfter) || !a.NotAfter.After(a.StartedAt) || a.NotAfter.After(a.StartedAt.Add(30*time.Second)) {
		return false
	}
	switch a.Operation {
	case "write":
		return a.BundleDigest != (artifact.Digest{}) && a.CopiesDigest == (artifact.Digest{}) && a.DeletionFence == 0 && !a.NotAfter.After(a.Expectation.Registration.WriteUntil)
	case "read":
		return a.CopiesDigest != (artifact.Digest{}) && a.BundleDigest == (artifact.Digest{}) && a.DeletionFence == 0 && !a.NotAfter.After(a.Expectation.Registration.ExpiresAt)
	case "purge":
		return a.CopiesDigest != (artifact.Digest{}) && a.BundleDigest == (artifact.Digest{}) && a.DeletionFence > 0
	}
	return false
}

// HistoryWriterCompletion is produced only after all four acknowledged PUTs
// have returned and the regional operation has joined. It is authenticated by
// the live signed-work channel; the SQL facet binds the original claim and
// process. It cannot be manufactured from an idle timer or object lookup.
type HistoryWriterCompletion struct {
	RootID, CaptureID, AttemptID, OperationID, ProcessEpoch string
	ExpectationDigest, CopiesDigest                         artifact.Digest
	CompletedAt, NotAfter                                   time.Time
}

func (c HistoryWriterCompletion) Valid(e HistoryExpectation) bool {
	return e.Valid() && c.RootID == e.RootID && c.CaptureID == e.CaptureID && c.AttemptID == e.Registration.Location.AttemptID && authorization.UUID(c.OperationID) && authorization.UUID(c.ProcessEpoch) && c.ExpectationDigest == HistoryExpectationDigest(e) && c.CopiesDigest != (artifact.Digest{}) && !c.CompletedAt.IsZero() && !c.CompletedAt.After(c.NotAfter) && !c.NotAfter.After(e.Registration.WriteUntil)
}

// HistoryLineage is opaque provenance, independently expiring and never a read
// grant. Its source cut-off also bounds previews restoring protected content.
type HistoryLineage struct {
	CaptureID string
	ExpiresAt time.Time
}

func (l HistoryLineage) Valid(now time.Time) bool {
	return authorization.UUID(l.CaptureID) && !l.ExpiresAt.IsZero() && now.Before(l.ExpiresAt)
}
