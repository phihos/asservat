package contracts

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
)

// ADR-227 release record: one ConfigMap per installation in the hub
// namespace, written only by the installer runner with resourceVersion
// preconditions. It names the original revision-1 image, which every
// install-time pin was computed from, and the current and previous image the
// hub Deployments may run. Verifiers map a named live image back to the
// original before their unchanged checks.
const (
	ReleaseRecordFormat       = "asservat-release/v1"
	ReleaseRecordFile         = "state.json"
	ReleaseRecordMaxBytes     = 16 << 10
	ReleaseRecordHistoryLimit = 16
)

var ErrReleaseRecord = errors.New("invalid release record")

// The installer-upgrade Pod names itself through the downward API, so the
// command can require that it runs the image it changes to.
const (
	InstallerUpgradePodNameEnvironment      = "ASSERVAT_UPGRADE_POD_NAME"
	InstallerUpgradePodNamespaceEnvironment = "ASSERVAT_UPGRADE_POD_NAMESPACE"
)

// ReleaseRecordName is the record's fixed ConfigMap name.
func ReleaseRecordName(installationID string) string {
	return "asservat-release-" + strings.ReplaceAll(installationID, "-", "")
}

// ReleaseWorkload holds one hub Deployment's generations. Launch is the
// generation the installer launched it at (the value every install-time pin
// holds); Generation is the one the current image was applied at, and
// PreviousGeneration the one of the previous image while a change is not yet
// settled. All three are zero at revision 1, whose image is the original.
type ReleaseWorkload struct {
	Launch             int64 `json:"launch"`
	Generation         int64 `json:"generation"`
	PreviousGeneration int64 `json:"previousGeneration"`
}

type ReleaseWorkloads struct {
	HubAPI    ReleaseWorkload `json:"hubAPI"`
	HubWorker ReleaseWorkload `json:"hubWorker"`
}

type ReleaseHistoryEntry struct {
	Revision int64  `json:"revision"`
	Image    string `json:"image"`
	Schema   int64  `json:"schema"`
}

type ReleaseRecord struct {
	Format         string                `json:"format"`
	InstallationID string                `json:"installationID"`
	Revision       int64                 `json:"revision"`
	Original       string                `json:"original"`
	Image          string                `json:"image"`
	Previous       string                `json:"previous"`
	Schema         int64                 `json:"schema"`
	Workloads      ReleaseWorkloads      `json:"workloads"`
	History        []ReleaseHistoryEntry `json:"history"`
}

var releaseImage = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*(?::[0-9]+/[a-z0-9][a-z0-9._/-]*)?@sha256:[0-9a-f]{64}$`)

// ReleaseImageValid accepts only a digest-pinned image reference.
func ReleaseImageValid(image string) bool {
	return len(image) <= 456 && releaseImage.MatchString(image)
}

// ReleaseImageDigest returns the hex digest of a valid image reference.
func ReleaseImageDigest(image string) ([32]byte, bool) {
	var out [32]byte
	_, text, ok := strings.Cut(image, "@sha256:")
	if !ok || !ReleaseImageValid(image) {
		return out, false
	}
	b, err := hex.DecodeString(text)
	if err != nil || len(b) != 32 {
		return out, false
	}
	copy(out[:], b)
	return out, true
}

// NewReleaseRecord is revision 1: the original image and the binary schema the
// installation was created with.
func NewReleaseRecord(installationID, image string, schema int64) (ReleaseRecord, error) {
	r := ReleaseRecord{Format: ReleaseRecordFormat, InstallationID: installationID, Revision: 1, Original: image, Image: image, Schema: schema, History: []ReleaseHistoryEntry{{Revision: 1, Image: image, Schema: schema}}}
	return r, r.Validate()
}

func (w ReleaseWorkload) valid(revision int64, previous bool) bool {
	if revision == 1 {
		return w == ReleaseWorkload{}
	}
	// Each change updates the Deployment's image once, so its generation
	// advances by exactly one per revision.
	if w.Launch < 1 || w.Generation != w.Launch+revision-1 || w.Generation > 1<<40 {
		return false
	}
	if previous {
		return w.PreviousGeneration == w.Generation-1
	}
	return w.PreviousGeneration == 0
}

// Validate checks the record's internal consistency: a monotonic revision,
// contiguous history ending at the current image, and generations that follow
// the revision.
func (r ReleaseRecord) Validate() error {
	if r.Format != ReleaseRecordFormat || r.InstallationID == "" || len(r.InstallationID) > 64 || r.Revision < 1 || r.Revision > 1<<40 || r.Schema < 1 || r.Schema > 1<<31 ||
		!ReleaseImageValid(r.Original) || !ReleaseImageValid(r.Image) || (r.Previous != "" && (!ReleaseImageValid(r.Previous) || r.Previous == r.Image)) {
		return ErrReleaseRecord
	}
	if r.Revision == 1 && (r.Image != r.Original || r.Previous != "") {
		return ErrReleaseRecord
	}
	previous := r.Previous != ""
	if !r.Workloads.HubAPI.valid(r.Revision, previous) || !r.Workloads.HubWorker.valid(r.Revision, previous) {
		return ErrReleaseRecord
	}
	n := len(r.History)
	if n < 1 || n > ReleaseRecordHistoryLimit || int64(n) > r.Revision {
		return ErrReleaseRecord
	}
	for i, e := range r.History {
		if e.Revision != r.Revision-int64(n-1-i) || !ReleaseImageValid(e.Image) || e.Schema < 1 || e.Schema > 1<<31 || (i > 0 && e.Image == r.History[i-1].Image) {
			return ErrReleaseRecord
		}
		if e.Revision == 1 && e.Image != r.Original {
			return ErrReleaseRecord
		}
	}
	last := r.History[n-1]
	if last.Image != r.Image || last.Schema != r.Schema {
		return ErrReleaseRecord
	}
	if previous && (n < 2 || r.History[n-2].Image != r.Previous) {
		return ErrReleaseRecord
	}
	return nil
}

// HistoryEntry returns the newest history entry naming image.
func (r ReleaseRecord) HistoryEntry(image string) (ReleaseHistoryEntry, bool) {
	for i := len(r.History) - 1; i >= 0; i-- {
		if r.History[i].Image == image {
			return r.History[i], true
		}
	}
	return ReleaseHistoryEntry{}, false
}

// Next is the record after changing to image at schema: the next revision,
// the old image as previous and each generation advanced by one. launch holds
// the verified launch generations, used only when leaving revision 1.
func (r ReleaseRecord) Next(image string, schema int64, launch ReleaseWorkloads) (ReleaseRecord, error) {
	if r.Validate() != nil || image == r.Image || r.Previous != "" {
		return ReleaseRecord{}, ErrReleaseRecord
	}
	out := r
	out.Revision, out.Previous, out.Image, out.Schema = r.Revision+1, r.Image, image, schema
	step := func(w, l ReleaseWorkload) ReleaseWorkload {
		if r.Revision == 1 {
			return ReleaseWorkload{Launch: l.Launch, Generation: l.Launch + 1, PreviousGeneration: l.Launch}
		}
		return ReleaseWorkload{Launch: w.Launch, Generation: w.Generation + 1, PreviousGeneration: w.Generation}
	}
	out.Workloads = ReleaseWorkloads{HubAPI: step(r.Workloads.HubAPI, launch.HubAPI), HubWorker: step(r.Workloads.HubWorker, launch.HubWorker)}
	out.History = append(append([]ReleaseHistoryEntry(nil), r.History...), ReleaseHistoryEntry{Revision: out.Revision, Image: image, Schema: schema})
	if len(out.History) > ReleaseRecordHistoryLimit {
		out.History = out.History[len(out.History)-ReleaseRecordHistoryLimit:]
	}
	return out, out.Validate()
}

// Settled is the same revision once both Deployments run the current image.
func (r ReleaseRecord) Settled() (ReleaseRecord, error) {
	if r.Validate() != nil || r.Previous == "" {
		return ReleaseRecord{}, ErrReleaseRecord
	}
	out := r
	out.Previous = ""
	out.Workloads.HubAPI.PreviousGeneration, out.Workloads.HubWorker.PreviousGeneration = 0, 0
	out.History = append([]ReleaseHistoryEntry(nil), r.History...)
	return out, out.Validate()
}

// DecodeReleaseRecord accepts exactly one canonical, known-field record.
func DecodeReleaseRecord(r io.Reader) (ReleaseRecord, error) {
	var out ReleaseRecord
	raw, err := io.ReadAll(io.LimitReader(r, ReleaseRecordMaxBytes+1))
	if err != nil || len(raw) > ReleaseRecordMaxBytes {
		return ReleaseRecord{}, ErrReleaseRecord
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.Validate() != nil {
		return ReleaseRecord{}, ErrReleaseRecord
	}
	normal, err := EncodeReleaseRecord(out)
	if err != nil || !bytes.Equal(bytes.TrimSpace(raw), normal) {
		return ReleaseRecord{}, ErrReleaseRecord
	}
	return out, nil
}

func EncodeReleaseRecord(r ReleaseRecord) ([]byte, error) {
	if r.Validate() != nil {
		return nil, ErrReleaseRecord
	}
	if r.History == nil {
		return nil, ErrReleaseRecord
	}
	return json.Marshal(r)
}
