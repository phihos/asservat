package analysis

import (
	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const TargetDiscoveryDisplayVersion = "approved-processes/v1"
const TargetDiscoveryPageBytes = ContextResultBytes - 4096
const TargetDiscoveryWorkerBytes int64 = 256 << 20

type TargetDiscoveryRequest struct {
	CaptureID, Section, Cursor string
	Limit                      int
}

func (r TargetDiscoveryRequest) Valid() bool {
	return authorization.UUID(r.CaptureID) && (r.Section == "summary" || r.Section == "processes") && len(r.Cursor) <= 4096 && r.Limit >= 0 && r.Limit <= 100
}

type TargetDiscoveryWindow struct {
	Section      string
	Start, Limit int
	Binding      string
}

func (w TargetDiscoveryWindow) Valid() bool {
	return (w.Section == "summary" || w.Section == "processes") && w.Start >= 0 && w.Start <= artifact.ProcessMaxRecords && w.Limit >= 1 && w.Limit <= 100 && (w.Start == 0 && w.Binding == "" || w.Start > 0 && lowerHex(w.Binding, 32)) && (w.Section != "summary" || w.Start == 0)
}

func NormalizeTargetDiscoveryWindow(r TargetDiscoveryRequest) (TargetDiscoveryWindow, error) {
	if !r.Valid() {
		return TargetDiscoveryWindow{}, ErrInvalid
	}
	w := TargetDiscoveryWindow{Section: r.Section, Limit: r.Limit}
	if w.Limit == 0 {
		w.Limit = 20
	}
	if r.Cursor != "" {
		index, binding, ok := strings.Cut(r.Cursor, ":")
		n, e := strconv.Atoi(index)
		if !ok || e != nil || index != strconv.Itoa(n) || n < 1 || n >= artifact.ProcessMaxRecords || !lowerHex(binding, 32) {
			return TargetDiscoveryWindow{}, ErrInvalidCursor
		}
		w.Start, w.Binding = n, binding
	}
	if !w.Valid() {
		return TargetDiscoveryWindow{}, ErrInvalid
	}
	return w, nil
}

func targetDiscoveryBinding(capture, artifactID, section string, version artifact.Digest) string {
	h := sha256.New()
	h.Write([]byte(TargetDiscoveryDisplayVersion + "\x00" + capture + artifactID + section + "\x00"))
	h.Write(version[:])
	return fmt.Sprintf("%x", h.Sum(nil)[:16])
}
func (w TargetDiscoveryWindow) Matches(capture, artifactID string, version artifact.Digest) bool {
	return w.Valid() && authorization.UUID(capture) && authorization.UUID(artifactID) && version != (artifact.Digest{}) && (w.Start == 0 || w.Binding == targetDiscoveryBinding(capture, artifactID, w.Section, version))
}

type TargetDiscoveryProcess struct {
	ProcessRef, PodUID        string
	DisplayPID                uint32
	ExecutablePath, ParentRef string
	RSSBytes                  uint64
	ObservedAt                time.Time
}

// TargetDiscoveryPage contains only the fixed approved metadata projection.
// ProcessRef is source-bound identity, not authority or a live lookup handle.
type TargetDiscoveryPage struct {
	CaptureID, ArtifactID       string
	PodUID, Section, StopReason string
	CoveredPods                 int
	Version                     artifact.Digest
	StartedAt, EndedAt          time.Time
	RetainedBytes               int64
	InventoryComplete           bool
	Start, Total                int
	Processes                   []TargetDiscoveryProcess
	Gaps                        []string
}

func (p TargetDiscoveryPage) Next(count int) string {
	next := p.Start + count
	if p.Section != "processes" || count < 1 || count > len(p.Processes) || next >= p.Total || p.Version == (artifact.Digest{}) || !authorization.UUID(p.CaptureID) || !authorization.UUID(p.ArtifactID) {
		return ""
	}
	return strconv.Itoa(next) + ":" + targetDiscoveryBinding(p.CaptureID, p.ArtifactID, p.Section, p.Version)
}
func (p TargetDiscoveryPage) EncodedSize() int {
	b, e := json.Marshal(p)
	if e != nil {
		return TargetDiscoveryPageBytes + 1
	}
	return len(b)
}
func (p TargetDiscoveryPage) Valid(w TargetDiscoveryWindow) bool {
	if !w.Matches(p.CaptureID, p.ArtifactID, p.Version) || p.Section != w.Section || !identity.Text(p.PodUID, 64) || p.CoveredPods < 0 || p.CoveredPods > 1 || p.InventoryComplete && p.CoveredPods != 1 || p.StopReason != "completed" && p.StopReason != "outputLimit" && p.StopReason != "capabilityGap" || p.Start != w.Start || p.Total < 0 || p.Total > artifact.ProcessMaxRecords || p.Start > p.Total || len(p.Processes) > w.Limit || p.Start+len(p.Processes) > p.Total || p.StartedAt.IsZero() || p.EndedAt.Before(p.StartedAt) || p.EndedAt.Sub(p.StartedAt) > 5*time.Second || p.RetainedBytes < 1 || p.RetainedBytes > artifact.ProcessNativeLimit || p.Processes == nil || p.Gaps == nil || len(p.Gaps) > 32 || p.EncodedSize() > TargetDiscoveryPageBytes {
		return false
	}
	if w.Section == "summary" && len(p.Processes) != 0 {
		return false
	}
	seen := map[string]bool{}
	for _, r := range p.Processes {
		if !identity.Text(r.ProcessRef, 128) || seen[r.ProcessRef] || r.PodUID != p.PodUID || r.DisplayPID == 0 || r.DisplayPID > 4194304 || r.RSSBytes > 109951162777600 || !r.ObservedAt.Before(p.EndedAt.Add(time.Nanosecond)) || r.ObservedAt.Before(p.StartedAt) || r.ExecutablePath != "" && !identity.Text(r.ExecutablePath, 4096) || r.ParentRef != "" && !identity.Text(r.ParentRef, 128) {
			return false
		}
		seen[r.ProcessRef] = true
	}
	for _, g := range p.Gaps {
		if !identity.Text(g, 256) {
			return false
		}
	}
	return w.Section == "summary" || len(p.Processes) > 0 || p.Start == p.Total
}

func CloneTargetDiscoveryPage(p *TargetDiscoveryPage) *TargetDiscoveryPage {
	if p == nil {
		return nil
	}
	v := *p
	v.Processes = append([]TargetDiscoveryProcess{}, p.Processes...)
	v.Gaps = append([]string{}, p.Gaps...)
	return &v
}
