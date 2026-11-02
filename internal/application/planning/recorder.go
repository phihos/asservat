package planning

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	"asservat.local/asservat/internal/domain/identity"
	value "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/targets"
)

// Builtin capture profiles are embedded in the release binary (S6, ADR-243):
// immutable, digest-pinned and versioned with the release. They are the
// examples/capture-profile-*.yaml definitions; a test keeps both identical.
//
//go:embed profiles/*.json
var builtinFiles embed.FS

// ExpandedRecipeDescription is the fixed description of an expanded composition.
const ExpandedRecipeDescription = "Expanded capture profile composition."

type ring struct {
	MaxAge            string `json:"maxAge"`
	MaxBytes          int64  `json:"maxBytes"`
	SegmentBytes      int64  `json:"segmentBytes"`
	MaxSegments       int    `json:"maxSegments"`
	Medium            string `json:"medium"`
	StorageProfileRef string `json:"storageProfileRef,omitempty"`
}

type packetParameters struct {
	Profile                json.RawMessage `json:"profile"`
	Before                 string          `json:"before"`
	After                  string          `json:"after"`
	Filter                 string          `json:"filter,omitempty"`
	Ring                   ring            `json:"ring"`
	Peers                  json.RawMessage `json:"peers"`
	MaxFrozenBytes         int64           `json:"maxFrozenBytes"`
	MaxConcurrentSnapshots int             `json:"maxConcurrentSnapshots"`
}

type syscallSelection struct {
	Mode  string   `json:"mode"`
	Names []string `json:"names,omitempty"`
}

type syscallParameters struct {
	Processes              string           `json:"processes"`
	Mode                   string           `json:"mode"`
	Before                 string           `json:"before"`
	After                  string           `json:"after"`
	Syscalls               syscallSelection `json:"syscalls"`
	Result                 string           `json:"result"`
	Ring                   ring             `json:"ring"`
	MaxFrozenBytes         int64            `json:"maxFrozenBytes"`
	MaxConcurrentSnapshots int              `json:"maxConcurrentSnapshots"`
	MaxEvents              int64            `json:"maxEvents"`
	MaxEventsPerSecond     int64            `json:"maxEventsPerSecond"`
	MaxTrackedThreads      int64            `json:"maxTrackedThreads"`
	Arguments              json.RawMessage  `json:"arguments,omitempty"`
}

type actionLimits struct {
	MaxBytes int64  `json:"maxBytes"`
	Timeout  string `json:"timeout"`
}

type recipeAction struct {
	ID            string          `json:"id"`
	Kind          string          `json:"kind"`
	Parameters    json.RawMessage `json:"parameters"`
	DependsOn     []string        `json:"dependsOn,omitempty"`
	Required      bool            `json:"required"`
	Impact        string          `json:"impact"`
	Limits        actionLimits    `json:"limits"`
	ExecutionMode string          `json:"executionMode,omitempty"`
}

type recipeSpec struct {
	Description   string         `json:"description"`
	Actions       []recipeAction `json:"actions"`
	MaxTotalBytes int64          `json:"maxTotalBytes"`
	MaxDuration   string         `json:"maxDuration"`
}

type editableField struct {
	ActionID    string `json:"actionID"`
	Field       string `json:"field"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

type profileDefinition struct {
	DisplayName    string          `json:"displayName"`
	Description    string          `json:"description"`
	Recipe         recipeSpec      `json:"recipe"`
	EditableFields []editableField `json:"editableFields"`
	// Origins are non-executable attribution of a derived profile (≤8).
	Origins []wireResolved `json:"origins,omitempty"`
}

// resolvedProfile is one verified profile version: an embedded builtin, or a
// published catalog version with its source identity (REQ-CPR-001).
type resolvedProfile struct {
	Ref                                            value.ProfileRef
	Name, Version                                  string
	Definition                                     profileDefinition
	RawDefinition                                  json.RawMessage
	Digest                                         artifact.Digest
	SourceClusterID, SourceNamespaceUID, SourceUID string
	Deprecated                                     bool
}

// wire is the pinned provenance entry of this profile for componentID.
func (p resolvedProfile) wire(componentID string) wireResolved {
	return wireResolved{ComponentID: componentID, ProfileRef: wireRef{p.Ref.Catalog, p.Name, p.Version}, DefinitionDigest: hexDigest(p.Digest),
		SourceUID: p.SourceUID, SourceClusterID: p.SourceClusterID, SourceNamespaceUID: p.SourceNamespaceUID}
}

// Builtin evidence kinds available as composition components in this release.
// process-context, http-headers and go-cpu stay unavailable until their
// recorders or action kinds exist (plan §2.2).
var builtinNames = []string{"network-connections", "syscall-activity"}

func strict(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.More() {
		return value.ErrInvalid
	}
	return nil
}

func loadBuiltin(name string) (resolvedProfile, error) {
	b, err := builtinFiles.ReadFile("profiles/" + name + "-v1.json")
	if err != nil {
		return resolvedProfile{}, err
	}
	p, err := parseProfileDocument(b)
	if err != nil || p.Name != name || p.Version != "v1" {
		return resolvedProfile{}, value.ErrInvalid
	}
	p.Ref = value.ProfileRef{Catalog: "builtin", Name: name, Version: "v1"}
	return p, nil
}

// parseProfileDocument strictly decodes one {name, version, definition}
// document and pins its definition digest (SHA-256 of the canonical object).
func parseProfileDocument(b []byte) (resolvedProfile, error) {
	var doc struct {
		Name       string          `json:"name"`
		Version    string          `json:"version"`
		Definition json.RawMessage `json:"definition"`
	}
	if err := strict(b, &doc); err != nil {
		return resolvedProfile{}, err
	}
	var def profileDefinition
	if err := strict(doc.Definition, &def); err != nil {
		return resolvedProfile{}, err
	}
	if len(def.Origins) > 8 || def.DisplayName == "" || len(def.DisplayName) > 128 || len(def.Description) > 2048 {
		return resolvedProfile{}, value.ErrInvalid
	}
	_, digest, err := canonical(b)
	if err != nil || !(value.ProfileRef{Catalog: "builtin", Name: doc.Name, Version: doc.Version}).Valid() {
		return resolvedProfile{}, value.ErrInvalid
	}
	return resolvedProfile{Name: doc.Name, Version: doc.Version, Definition: def, RawDefinition: doc.Definition, Digest: digest}, nil
}

// BuiltinProfileDigest returns the definition digest of one embedded builtin
// (SHA-256 of the canonical {name, version, definition}).
func BuiltinProfileDigest(name string) (artifact.Digest, bool) {
	p, err := loadBuiltin(name)
	return p.Digest, err == nil
}

func pathf(format string, a ...any) string { return fmt.Sprintf(format, a...) }

func refuse(code, path, reason string) error {
	return value.CompositionError{Code: code, Path: path, Reason: reason}
}

// resolveProfile resolves one reference without precedence or shadowing:
// builtins from the release binary, organization and namespace versions only
// from the caller's current read of that exact catalog (c.Resolved).
func resolveProfile(i int, ref value.ProfileRef, resolved []value.CatalogProfile) (resolvedProfile, error) {
	if ref.Catalog == "builtin" {
		return resolveBuiltin(i, ref)
	}
	path := pathf("profile_composition.components[%d].profileRef", i)
	var found *value.CatalogProfile
	for n := range resolved {
		if resolved[n].Ref == ref {
			if found != nil {
				return resolvedProfile{}, value.ErrInvalid
			}
			found = &resolved[n]
		}
	}
	name := ref.Catalog + " profile " + strconv.Quote(ref.Name) + " " + ref.Version
	if found == nil {
		return resolvedProfile{}, refuse(value.CompositionProfileMissing, path, name+" is not published in the "+ref.Catalog+" catalog")
	}
	if !found.Enabled {
		return resolvedProfile{}, refuse(value.CompositionProfileMissing, path, name+" is disabled; select another version")
	}
	p, err := parseProfileDocument(found.Document)
	if err != nil {
		return resolvedProfile{}, refuse(value.CompositionProfileMissing, path, name+" has an invalid definition")
	}
	if p.Name != ref.Name || p.Version != ref.Version || found.SourceUID == "" || len(found.SourceUID) > 64 || found.SourceNamespaceUID == "" || len(found.SourceNamespaceUID) > 64 || found.SourceClusterID == "" {
		return resolvedProfile{}, value.ErrInvalid
	}
	p.Ref, p.Deprecated = ref, found.Deprecated
	p.SourceClusterID, p.SourceNamespaceUID, p.SourceUID = found.SourceClusterID, found.SourceNamespaceUID, found.SourceUID
	return p, nil
}

func resolveBuiltin(i int, ref value.ProfileRef) (resolvedProfile, error) {
	path := pathf("profile_composition.components[%d].profileRef", i)
	if !slices.Contains(builtinNames, ref.Name) {
		return resolvedProfile{}, refuse(value.CompositionProfileMissing, path, "builtin profile "+strconv.Quote(ref.Name)+" is not available in this release; available: network-connections/v1, syscall-activity/v1")
	}
	if ref.Version != "v1" {
		return resolvedProfile{}, refuse(value.CompositionProfileMissing, path, "version "+strconv.Quote(ref.Version)+" of builtin "+ref.Name+" does not exist; available: v1")
	}
	p, err := loadBuiltin(ref.Name)
	if err != nil {
		return resolvedProfile{}, value.ErrInvalid
	}
	return p, nil
}

func evidenceType(kind string) string {
	switch kind {
	case "packetCapture":
		return "packetCapture"
	case "syscallTrace":
		return "syscallTrace"
	}
	return ""
}

// RecorderEvidenceType resolves the one evidence type of a manual
// composition, so the caller can resolve its retention before compilation.
// A manual capture is one artifact: mixing packet and syscall components is
// refused until manual captures can become a group (slice B3).
func RecorderEvidenceType(c value.ProfileComposition) (string, error) {
	if err := compositionShape(c); err != nil {
		return "", err
	}
	kind := ""
	for i, component := range c.Components {
		p, err := resolveProfile(i, component.Profile, c.Resolved)
		if err != nil {
			return "", err
		}
		for _, a := range p.Definition.Recipe.Actions {
			if evidenceType(a.Kind) == "" {
				return "", value.ErrInvalid
			}
			if kind != "" && a.Kind != kind {
				return "", refuse(value.CompositionRecorderUnavailable, "profile_composition.components", "a manual capture records one evidence type; capture packets and syscalls separately, or record both with a policy")
			}
			kind = a.Kind
		}
	}
	return evidenceType(kind), nil
}

func compositionShape(c value.ProfileComposition) error {
	if !c.Valid() {
		return refuse(value.CompositionInvalid, "profile_composition", "the composition is malformed")
	}
	return nil
}

// durationValue parses ^(0s|[1-9][0-9]*(ms|s|m|h|d))$.
func durationValue(s string, zero bool) (time.Duration, bool) {
	if s == "0s" {
		return 0, zero
	}
	if len(s) < 2 || len(s) > 16 || s[0] < '1' || s[0] > '9' {
		return 0, false
	}
	for _, u := range []struct {
		suffix string
		unit   time.Duration
	}{{"ms", time.Millisecond}, {"s", time.Second}, {"m", time.Minute}, {"h", time.Hour}, {"d", 24 * time.Hour}} {
		if number, ok := strings.CutSuffix(s, u.suffix); ok {
			n, err := strconv.ParseInt(number, 10, 64)
			if err != nil || n > int64(30*24*time.Hour/u.unit) {
				return 0, false
			}
			return time.Duration(n) * u.unit, true
		}
	}
	return 0, false
}

// Portable bounds of the packet and syscall contracts (specs/packets.md
// REQ-NET-003, specs/syscalls.md REQ-SYS-002). Administrators may lower them;
// no administrator ceiling source exists in this release.
const (
	maxRingAge         = time.Hour
	maxRingBytes       = 256 << 20
	maxSegmentBytes    = 64 << 20
	maxFrozenBytes     = 256 << 20
	maxSyscallAfter    = 60 * time.Second
	finalizationMargin = 5 * time.Second
)

// editBinding maps a registered field to its action kinds (capture-composition x-field-bindings).
var editBinding = map[string][]string{
	"packetPeers": {"packetCapture"}, "packetFilter": {"packetCapture"}, "packetBefore": {"packetCapture"}, "packetAfter": {"packetCapture"}, "packetRing": {"packetCapture"},
	"processSelector": {"liveCore"}, "processBatch": {"liveCore"}, "profileDuration": {"profile"},
	"syscallFilter": {"syscallTrace"}, "syscallMode": {"syscallTrace"}, "syscallBefore": {"syscallTrace"}, "syscallAfter": {"syscallTrace"}, "syscallRing": {"syscallTrace"},
	"syscallArguments": {"syscallTrace"}, "syscallMaxEvents": {"syscallTrace"}, "syscallRate": {"syscallTrace"},
	"filePath": {"fileRead"}, "commandArgv": {"command"},
	"actionMaxBytes": {"*"}, "actionTimeout": {"*"}, "actionExecutionMode": {"packetCapture", "syscallTrace"},
}

type expandedAction struct {
	action  recipeAction
	packet  *packetParameters
	syscall *syscallParameters
	filter  *value.CompiledFilter
	// peers is the canonical CIDR selection (ADR-283); nil selects all pod
	// traffic. expression is the compiled effective filter: the peer
	// expression intersected with the authored filter.
	peers      *peerSet
	expression string
	localID    string
	// componentID is the authoring component of this action.
	componentID string
	// sensitive names why this action needs individual approval (ADR-249).
	sensitive []string
}

func editRing(r *value.RingSettings) ring {
	return ring{MaxAge: r.MaxAge, MaxBytes: r.MaxBytes, SegmentBytes: r.SegmentBytes, MaxSegments: r.MaxSegments, Medium: r.Medium, StorageProfileRef: r.StorageProfileRef}
}

// applyEdit applies one typed literal value. Only the registered value member
// may be set; the profile version must expose the field for this action.
func applyEdit(path string, e value.ProfileEdit, a *expandedAction) error {
	kinds, known := editBinding[e.Field]
	if !known {
		return refuse(value.CompositionInvalid, path, "unknown field "+strconv.Quote(e.Field))
	}
	if kinds[0] != "*" && !slices.Contains(kinds, a.action.Kind) {
		return refuse(value.CompositionInvalid, path, e.Field+" does not apply to a "+a.action.Kind+" action")
	}
	if e.Unmodeled {
		reason := e.Field + " cannot be edited in this release"
		if e.Field == "packetPeers" {
			reason = kubernetesPeersRemedy
		}
		return refuse(value.CompositionInvalid, path, reason)
	}
	text := func() (string, error) {
		if e.Text == "" && e.TextSet && e.Field == "packetFilter" {
			return "", ScreenFilter(path, "")
		}
		if e.Text == "" && e.TextSet {
			return "", refuse(value.CompositionInvalid, path, e.Field+" is empty; omit the edit to keep the profile's value")
		}
		if e.Text == "" || e.Number != 0 || e.Ring != nil || e.Syscalls != nil {
			return "", refuse(value.CompositionInvalid, path, e.Field+" takes a string value")
		}
		return e.Text, nil
	}
	ringValue := func() (ring, error) {
		if e.Ring == nil {
			return ring{}, refuse(value.CompositionInvalid, path, e.Field+" takes a ring object")
		}
		return editRing(e.Ring), nil
	}
	number := func() (int64, error) {
		if e.Number < 1 || e.Text != "" || e.Ring != nil || e.Syscalls != nil {
			return 0, refuse(value.CompositionInvalid, path, e.Field+" takes a positive integer")
		}
		return e.Number, nil
	}
	var err error
	switch e.Field {
	case "packetFilter":
		a.packet.Filter, err = text()
	case "packetPeers":
		if e.Peers == nil {
			return refuse(value.CompositionInvalid, path, "packetPeers takes a peers object")
		}
		a.packet.Peers, err = json.Marshal(peersEditWire(e.Peers))
	case "packetBefore":
		a.packet.Before, err = text()
	case "packetAfter":
		a.packet.After, err = text()
	case "packetRing":
		a.packet.Ring, err = ringValue()
	case "syscallBefore":
		a.syscall.Before, err = text()
	case "syscallAfter":
		a.syscall.After, err = text()
	case "syscallRing":
		a.syscall.Ring, err = ringValue()
	case "syscallMode":
		a.syscall.Mode, err = text()
	case "syscallFilter":
		if e.Syscalls == nil {
			return refuse(value.CompositionInvalid, path, "syscallFilter takes {mode: all} or {mode: include, names: [...]}")
		}
		a.syscall.Syscalls = syscallSelection{Mode: e.Syscalls.Mode, Names: slices.Clone(e.Syscalls.Names)}
	case "syscallMaxEvents":
		a.syscall.MaxEvents, err = number()
	case "syscallRate":
		a.syscall.MaxEventsPerSecond, err = number()
	case "actionMaxBytes":
		a.action.Limits.MaxBytes, err = number()
	case "actionTimeout":
		a.action.Limits.Timeout, err = text()
	case "actionExecutionMode":
		a.action.ExecutionMode, err = text()
	default:
		return refuse(value.CompositionInvalid, path, e.Field+" cannot be edited in this release")
	}
	return err
}

// wholePodPeers reports whether peers select all pod traffic: one frozen
// entry of exactly 0.0.0.0/0 and ::/0 for any protocol. The recorder applies
// no peer selection yet, so any narrower selection must fail closed rather
// than be silently ignored (it would capture more than was reviewed).
func wholePodPeers(raw json.RawMessage) bool {
	var p struct {
		Entries []struct {
			CIDRs []string `json:"cidrs"`
		} `json:"entries"`
		Protocol     string `json:"protocol"`
		Resolution   string `json:"resolution"`
		MaxEndpoints int    `json:"maxEndpoints"`
		MaxStaleness string `json:"maxStaleness"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) == 0 || d.Decode(&p) != nil || len(p.Entries) != 1 || p.Protocol != "any" || p.Resolution != "frozen" {
		return false
	}
	c := slices.Sorted(slices.Values(p.Entries[0].CIDRs))
	return slices.Equal(c, []string{"0.0.0.0/0", "::/0"})
}

// maxRawAfter bounds a finite raw recording (ADR-261/279).
const maxRawAfter = 15 * time.Second

// RawProfile is a rawPackets profile's default prefix and per-transport caps.
type RawProfile struct {
	Snaplen         int `json:"snaplen"`
	ProtocolSnaplen []struct {
		Protocol string `json:"protocol"`
		Bytes    int    `json:"bytes"`
	} `json:"protocolSnaplen,omitempty"`
}

// validRawProfile checks the default snaplen and at most one cap per
// transport against the engine maximum; larger values are refused with a
// remedy, never narrowed silently (ADR-279).
// minRawSnaplen is Ethernet (14) plus the fixed IPv6 header (40).
const minRawSnaplen = 54

func validRawProfile(path string, raw json.RawMessage) error {
	var p RawProfile
	if json.Unmarshal(raw, &p) != nil {
		return refuse(value.CompositionInvalid, path, "rawPackets needs snaplen and optional protocolSnaplen")
	}
	// A cap below the Ethernet and fixed IPv6 headers could not name its
	// transport, so the verifier could not recheck it (ADR-279).
	if p.Snaplen < minRawSnaplen || p.Snaplen > artifact.MaxRawSnaplen {
		return refuse(value.CompositionInvalid, path+".snaplen", fmt.Sprintf("this recorder keeps %d to %d bytes per packet", minRawSnaplen, artifact.MaxRawSnaplen))
	}
	seen := map[string]bool{}
	for i, c := range p.ProtocolSnaplen {
		if c.Protocol != "tcp" && c.Protocol != "udp" && c.Protocol != "icmp" || seen[c.Protocol] {
			return refuse(value.CompositionInvalid, pathf("%s.protocolSnaplen[%d].protocol", path, i), "one cap each for tcp, udp and icmp")
		}
		seen[c.Protocol] = true
		if c.Bytes < minRawSnaplen || c.Bytes > artifact.MaxRawSnaplen {
			return refuse(value.CompositionInvalid, pathf("%s.protocolSnaplen[%d].bytes", path, i), fmt.Sprintf("a cap is %d to %d bytes", minRawSnaplen, artifact.MaxRawSnaplen))
		}
	}
	return nil
}

// HTTPProfile is an httpHeaders profile (packet-capture.schema.json): the
// reviewed projection and the parser bounds (ADR-282).
type HTTPProfile struct {
	Kind          string `json:"kind"`
	Protocol      string `json:"protocol"`
	ProjectionRef struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"projectionRef"`
	MaxFlows                  int    `json:"maxFlows"`
	MaxHeaderBytes            int    `json:"maxHeaderBytes"`
	MaxReassemblyBytesPerFlow int    `json:"maxReassemblyBytesPerFlow"`
	MaxReassemblyBytes        int    `json:"maxReassemblyBytes"`
	IdleTimeout               string `json:"idleTimeout"`
}

// The projector's buffer floors (ADR-282; httpheaders.Limits.Validate in
// internal/adapters/httpheaders): a 4 KiB bufio buffer per direction,
// gopacket's 1,900-byte reassembly page and a one-second idle minimum. They
// are replicated here so planning refuses what the node would refuse.
const (
	httpReadBuffer     = 4 << 10
	httpPageBytes      = 1900
	minHTTPIdleTimeout = time.Second
)

// httpFloors reports whether the bounds leave the parser at least one
// out-of-order page per direction and in total, and reader state for one
// flow, exactly as the projector derives them.
func httpFloors(header, flow, total int) (perFlow, shared bool) {
	readers := 2 * (header + 2*httpReadBuffer)
	pagesPerHalf := (flow-readers)/(2*httpPageBytes) - 1
	pagesTotal := (total/2)/httpPageBytes - 1
	readerBudget := total - (pagesTotal+1)*httpPageBytes
	return pagesPerHalf >= 1, pagesTotal >= 1 && readerBudget >= 2*httpReadBuffer
}

// validHTTPProfile checks the reviewed projection and the parser bounds
// against the specified maxima and the projector's floors; values out of
// range are refused with a remedy, never narrowed (ADR-282).
func validHTTPProfile(path string, raw json.RawMessage) (artifact.RecordingHTTP, error) {
	var p HTTPProfile
	if strict(raw, &p) != nil || p.Kind != "httpHeaders" {
		return artifact.RecordingHTTP{}, refuse(value.CompositionInvalid, path, "httpHeaders needs protocol, projectionRef, maxFlows, maxHeaderBytes, maxReassemblyBytesPerFlow, maxReassemblyBytes and idleTimeout")
	}
	idle, ok := durationValue(p.IdleTimeout, false)
	switch {
	case p.Protocol != "http1":
		return artifact.RecordingHTTP{}, refuse(value.CompositionInvalid, path+".protocol", "the HTTP projection reads plain HTTP/1 only: set protocol http1")
	case p.ProjectionRef.Name != "http-response-headers" || p.ProjectionRef.Version != "v1":
		return artifact.RecordingHTTP{}, refuse(value.CompositionInvalid, path+".projectionRef", "the reviewed projection is http-response-headers v1")
	case p.MaxFlows < 1 || p.MaxFlows > artifact.MaxHTTPFlows:
		return artifact.RecordingHTTP{}, refuse(value.CompositionInvalid, path+".maxFlows", fmt.Sprintf("track 1 to %d flows", artifact.MaxHTTPFlows))
	case p.MaxHeaderBytes < 1 || p.MaxHeaderBytes > artifact.MaxHTTPHeaderBytes:
		return artifact.RecordingHTTP{}, refuse(value.CompositionInvalid, path+".maxHeaderBytes", "a header block is 1 byte to 32 KiB")
	case p.MaxReassemblyBytesPerFlow < 1 || p.MaxReassemblyBytesPerFlow > artifact.MaxHTTPFlowBytes:
		return artifact.RecordingHTTP{}, refuse(value.CompositionInvalid, path+".maxReassemblyBytesPerFlow", "reassembly per flow is 1 byte to 256 KiB")
	case p.MaxReassemblyBytes < p.MaxReassemblyBytesPerFlow || p.MaxReassemblyBytes > artifact.MaxHTTPTotalBytes:
		return artifact.RecordingHTTP{}, refuse(value.CompositionInvalid, path+".maxReassemblyBytes", "total reassembly covers at least one flow's bound and is at most 16 MiB")
	case !ok || idle < minHTTPIdleTimeout || idle > time.Duration(artifact.MaxHTTPIdleMillis)*time.Millisecond:
		return artifact.RecordingHTTP{}, refuse(value.CompositionInvalid, path+".idleTimeout", "the idle timeout is 1s to 30s")
	}
	perFlow, shared := httpFloors(p.MaxHeaderBytes, p.MaxReassemblyBytesPerFlow, p.MaxReassemblyBytes)
	if !perFlow {
		minimum := 2*(p.MaxHeaderBytes+2*httpReadBuffer) + 4*httpPageBytes
		return artifact.RecordingHTTP{}, refuse(value.CompositionInvalid, path+".maxReassemblyBytesPerFlow", fmt.Sprintf("too small for this header block's read buffers and one reassembly page per direction: raise it to at least %d bytes or lower maxHeaderBytes", minimum))
	}
	if !shared {
		return artifact.RecordingHTTP{}, refuse(value.CompositionInvalid, path+".maxReassemblyBytes", "too small for shared reassembly pages and reader buffers: raise it to at least 24 KiB")
	}
	return artifact.RecordingHTTP{MaxFlows: p.MaxFlows, MaxHeaderBytes: p.MaxHeaderBytes, MaxFlowBytes: p.MaxReassemblyBytesPerFlow, MaxTotalBytes: p.MaxReassemblyBytes, IdleMillis: idle.Milliseconds()}, nil
}

func validRing(path string, r ring, before time.Duration) error {
	age, ok := durationValue(r.MaxAge, false)
	switch {
	case !ok || age > maxRingAge:
		return refuse(value.CompositionInvalid, path+".maxAge", "the ring age must be a duration of at most 1h")
	case r.StorageProfileRef != "":
		return refuse(value.CompositionInvalid, path+".storageProfileRef", "ring storage profiles are not available in this release; use medium encryptedDisk, which uses the administrator's node ring volume")
	case r.Medium != "memory" && r.Medium != "encryptedDisk":
		return refuse(value.CompositionInvalid, path+".medium", "the ring medium is memory or encryptedDisk")
	case r.MaxSegments < 2 || r.MaxSegments > 64:
		return refuse(value.CompositionInvalid, path+".maxSegments", "a ring has 2 to 64 segments")
	case r.MaxBytes < 1 || r.MaxBytes > maxRingBytes:
		return refuse(value.CompositionInvalid, path+".maxBytes", "a ring holds 1 byte to 256 MiB")
	case r.SegmentBytes < 1 || r.SegmentBytes > maxSegmentBytes || r.SegmentBytes*int64(r.MaxSegments) > r.MaxBytes:
		return refuse(value.CompositionInvalid, path+".segmentBytes", "segmentBytes × maxSegments must fit in maxBytes, with segments of at most 64 MiB")
	case before > age:
		return refuse(value.CompositionInvalid, path+".maxAge", "the requested history (before) cannot exceed the ring age; raise maxAge or shorten before")
	}
	return nil
}

// normalize resolves the execution mode and validates one expanded action
// against the action-lifecycle and mechanism rules as a whole.
func normalize(path string, a *expandedAction, compiler FilterCompiler, pc *peerContext) error {
	if a.action.ExecutionMode == "" {
		a.action.ExecutionMode = "ongoing" // action.schema.json x-execution-modes default
	}
	mode := a.action.ExecutionMode
	if mode != "ongoing" && mode != "onTrigger" {
		return refuse(value.CompositionInvalid, path+".executionMode", "the execution mode is ongoing or onTrigger")
	}
	if len(a.action.DependsOn) != 0 {
		return refuse(value.CompositionInvalid, path+".dependsOn", "a recorder cannot depend on another action")
	}
	raw, http := false, false
	if a.packet != nil {
		var kind struct {
			Kind string `json:"kind"`
		}
		_ = json.Unmarshal(a.packet.Profile, &kind)
		raw, http = kind.Kind == "rawPackets", kind.Kind == "httpHeaders"
	}
	if raw && a.action.Impact != "sensitiveRead" {
		return refuse(value.CompositionInvalid, path+".impact", "raw packet recordings read payload and have impact sensitiveRead")
	}
	// ADR-282: projecting headers reads payload, even though the output is
	// an extract.
	if http && a.action.Impact != "sensitiveRead" {
		return refuse(value.CompositionInvalid, path+".impact", "HTTP header recordings read payload and have impact sensitiveRead")
	}
	if !raw && !http && a.action.Impact != "observe" {
		return refuse(value.CompositionInvalid, path+".impact", "metadata recordings have impact observe")
	}
	var beforeText, afterText string
	var r ring
	var frozen int64
	snapshots := 0
	if a.packet != nil {
		var kind struct {
			Kind string `json:"kind"`
		}
		if json.Unmarshal(a.packet.Profile, &kind) != nil || kind.Kind != "networkHeaders" && kind.Kind != "rawPackets" && kind.Kind != "httpHeaders" {
			return refuse(value.CompositionInvalid, path+".parameters.profile.kind", "the packet profile is networkHeaders, rawPackets or httpHeaders")
		}
		peers, err := packetPeers(path+".parameters.peers", a.packet.Peers, pc)
		if err != nil {
			return err
		}
		a.peers = peers
		if http {
			if _, err := validHTTPProfile(path+".parameters.profile", a.packet.Profile); err != nil {
				return err
			}
			// The finite observation binding pins a compiled program, as
			// for raw packets (ADR-279/282).
			if a.packet.Filter == "" && peers == nil {
				return refuse(value.CompositionInvalid, path+".parameters.filter", "httpHeaders reads payload; narrow it with packetFilter (for example tcp port 8080) or CIDR peers")
			}
			a.sensitive = append(a.sensitive, value.ReasonHTTPHeaders)
		}
		if raw {
			if err := validRawProfile(path+".parameters.profile", a.packet.Profile); err != nil {
				return err
			}
			// The finite observation binding pins a compiled program (ADR-279).
			if a.packet.Filter == "" && peers == nil {
				return refuse(value.CompositionInvalid, path+".parameters.filter", "rawPackets keeps payload; narrow it with packetFilter (for example tcp port 8080) or CIDR peers")
			}
			a.sensitive = append(a.sensitive, value.ReasonRawPackets)
		}
		beforeText, afterText, r, frozen, snapshots = a.packet.Before, a.packet.After, a.packet.Ring, a.packet.MaxFrozenBytes, a.packet.MaxConcurrentSnapshots
	} else {
		s := a.syscall
		if s.Mode != "metadata" || len(s.Arguments) != 0 {
			return refuse(value.CompositionApproval, path+".parameters.mode", "syscall argument tracing needs sensitive observation approval and a recorder that this release does not have; use metadata")
		}
		if s.Processes != "allPodProcesses" {
			return refuse(value.CompositionInvalid, path+".parameters.processes", "syscall tracing covers all pod processes")
		}
		switch s.Syscalls.Mode {
		case "all":
			if len(s.Syscalls.Names) != 0 {
				return refuse(value.CompositionInvalid, path+".parameters.syscalls", "mode all takes no names")
			}
		case "include":
			if len(s.Syscalls.Names) < 1 || len(s.Syscalls.Names) > 128 {
				return refuse(value.CompositionInvalid, path+".parameters.syscalls.names", "name 1 to 128 syscalls")
			}
			seen := map[string]bool{}
			for _, n := range s.Syscalls.Names {
				if !syscallName(n) || seen[n] {
					return refuse(value.CompositionInvalid, path+".parameters.syscalls.names", "syscall names are unique identifiers of 1 to 64 letters, digits or underscores")
				}
				seen[n] = true
			}
		default:
			return refuse(value.CompositionInvalid, path+".parameters.syscalls.mode", "the syscall selection is all or include")
		}
		if s.Result != "all" && s.Result != "errors" {
			return refuse(value.CompositionInvalid, path+".parameters.result", "result is all or errors")
		}
		if s.MaxEvents < 1 || s.MaxEvents > 1000000 {
			return refuse(value.CompositionInvalid, path+".parameters.maxEvents", "retain 1 to 1,000,000 events")
		}
		if s.MaxEventsPerSecond < 1 || s.MaxEventsPerSecond > 100000 {
			return refuse(value.CompositionInvalid, path+".parameters.maxEventsPerSecond", "the observed event rate limit is 1 to 100,000 per second")
		}
		if s.MaxTrackedThreads < 1 || s.MaxTrackedThreads > 16384 {
			return refuse(value.CompositionInvalid, path+".parameters.maxTrackedThreads", "track 1 to 16,384 threads")
		}
		beforeText, afterText, r, frozen, snapshots = s.Before, s.After, s.Ring, s.MaxFrozenBytes, s.MaxConcurrentSnapshots
	}
	before, okBefore := durationValue(beforeText, true)
	after, okAfter := durationValue(afterText, true)
	if !okBefore {
		return refuse(value.CompositionInvalid, path+".parameters.before", "before is 0s or a positive duration")
	}
	if !okAfter {
		return refuse(value.CompositionInvalid, path+".parameters.after", "after is 0s or a positive duration")
	}
	// ADR-279: raw packets are finite for now; rings, Saves and longer
	// recordings follow in later slices.
	if raw && (mode != "onTrigger" || after > maxRawAfter) {
		return refuse(value.CompositionRecorderUnavailable, path+".executionMode", "raw packets are recorded finitely for now: set actionExecutionMode onTrigger, before 0s and after at most 15s")
	}
	// ADR-282: HTTP header projections are manual and finite like raw packets.
	if http && (mode != "onTrigger" || after > maxRawAfter) {
		return refuse(value.CompositionRecorderUnavailable, path+".executionMode", "HTTP headers are recorded finitely for now: set actionExecutionMode onTrigger, before 0s and after at most 15s")
	}
	if mode == "onTrigger" && before != 0 {
		return refuse(value.CompositionInvalid, path+".parameters.before", "an onTrigger recording captures only the next interval: also set before to 0s (no history before the trigger)")
	}
	if mode == "onTrigger" && after == 0 {
		return refuse(value.CompositionInvalid, path+".parameters.after", "an onTrigger recording needs a positive after interval")
	}
	if before == 0 && after == 0 {
		return refuse(value.CompositionInvalid, path+".parameters", "before or after must be positive")
	}
	if a.syscall != nil && after > maxSyscallAfter {
		return refuse(value.CompositionInvalid, path+".parameters.after", "a syscall post-trigger window is at most 60s")
	}
	if err := validRing(path+".parameters.ring", r, before); err != nil {
		return err
	}
	if snapshots < 1 || snapshots > 4 {
		return refuse(value.CompositionInvalid, path+".parameters.maxConcurrentSnapshots", "1 to 4 concurrent snapshots")
	}
	if frozen < 1 || frozen > maxFrozenBytes || frozen > a.action.Limits.MaxBytes {
		return refuse(value.CompositionInvalid, path+".parameters.maxFrozenBytes", "frozen snapshot bytes must be positive, at most 256 MiB and within the action output limit (limits.maxBytes)")
	}
	timeout, ok := durationValue(a.action.Limits.Timeout, false)
	if !ok {
		return refuse(value.CompositionInvalid, path+".limits.timeout", "the action timeout is a positive duration")
	}
	if timeout < after+finalizationMargin {
		return refuse(value.CompositionInvalid, path+".limits.timeout", "the action timeout must cover the after interval plus 5s for finalization; raise actionTimeout")
	}
	if a.action.Limits.MaxBytes < 1 || a.action.Limits.MaxBytes > value.MaxCompositionBytes {
		return refuse(value.CompositionInvalid, path+".limits.maxBytes", "the output limit is 1 byte to 1 TiB")
	}
	if a.packet != nil && a.peers != nil {
		// ADR-283: the CIDR peers and the authored filter compile as one
		// program; the authored filter alone is screened first so its own
		// terms are refused at its path.
		filterPath, user := path+".parameters.filter", ""
		if a.packet.Filter != "" {
			if err := ScreenFilter(filterPath, a.packet.Filter); err != nil {
				return err
			}
			user = NormalizeFilter(a.packet.Filter)
			if !balancedFilter(user) {
				return refuse(value.CompositionFilterRejected, filterPath, "the filter's parentheses and brackets must balance")
			}
		} else {
			filterPath = path + ".parameters.peers"
		}
		expression := a.peers.expression(user)
		f, err := compileFilter(compiler, filterPath, expression, "; select fewer or broader peer prefixes or ports")
		if err != nil {
			return err
		}
		a.packet.Filter, a.expression, a.filter = user, expression, &f
		if RawBytePredicate(user) {
			a.sensitive = append(a.sensitive, value.ReasonRawBytePredicate)
		}
	} else if a.packet != nil && a.packet.Filter != "" {
		f, err := compileFilter(compiler, path+".parameters.filter", a.packet.Filter, "")
		if err != nil {
			return err
		}
		a.packet.Filter = NormalizeFilter(a.packet.Filter)
		a.expression, a.filter = a.packet.Filter, &f
		if RawBytePredicate(a.packet.Filter) {
			a.sensitive = append(a.sensitive, value.ReasonRawBytePredicate)
		}
	}
	return nil
}

func syscallName(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

func generatedID(prefix, component, local string) string {
	h := sha256.Sum256([]byte(component + "\x00" + local))
	return prefix + hex.EncodeToString(h[:])[:24]
}

// expand resolves every component's profile, applies its typed edits and
// normalizes every action (REQ-CPR-003). Edits are applied first; the plan
// is then validated as a whole: generated IDs are unique, at most 16 actions,
// aggregate bounds cover the sum of outputs and the longest timeout, and
// recorder sources do not overlap on one Pod.
func expand(c value.ProfileComposition, compiler FilterCompiler, pc *peerContext) ([]expandedAction, []resolvedProfile, error) {
	if err := compositionShape(c); err != nil {
		return nil, nil, err
	}
	var actions []expandedAction
	var profiles []resolvedProfile
	ids := map[string]string{}
	for ci, component := range c.Components {
		base := pathf("profile_composition.components[%d]", ci)
		p, err := resolveProfile(ci, component.Profile, c.Resolved)
		if err != nil {
			return nil, nil, err
		}
		profiles = append(profiles, p)
		first := len(actions)
		index := map[string]int{}
		for _, a := range p.Definition.Recipe.Actions {
			x := expandedAction{action: a, localID: a.ID, componentID: component.ID}
			switch a.Kind {
			case "packetCapture":
				x.packet = &packetParameters{}
				err = strict(a.Parameters, x.packet)
			case "syscallTrace":
				x.syscall = &syscallParameters{}
				err = strict(a.Parameters, x.syscall)
			default:
				err = value.ErrInvalid
			}
			if err != nil {
				return nil, nil, value.ErrInvalid
			}
			id := generatedID("a", component.ID, a.ID)
			if other, taken := ids[id]; taken {
				return nil, nil, refuse(value.CompositionInvalid, base+".id", "the generated action ID of "+component.ID+"/"+a.ID+" collides with "+other+"; rename the component")
			}
			ids[id] = component.ID + "/" + a.ID
			index[a.ID] = len(actions)
			actions = append(actions, x)
		}
		if len(actions) > 16 {
			return nil, nil, refuse(value.CompositionInvalid, "profile_composition.components", "the composition expands to more than 16 actions; remove a component")
		}
		exposed := map[[2]string]bool{}
		for _, f := range p.Definition.EditableFields {
			exposed[[2]string{f.ActionID, f.Field}] = true
		}
		seen := map[[2]string]bool{}
		for j, e := range component.Edits {
			path := pathf("%s.overrides[%d]", base, j)
			key := [2]string{e.ActionID, e.Field}
			at, found := index[e.ActionID]
			switch {
			case !found:
				return nil, nil, refuse(value.CompositionInvalid, path+".actionID", "profile "+p.Name+"/"+p.Version+" has no action "+strconv.Quote(e.ActionID))
			case seen[key]:
				return nil, nil, refuse(value.CompositionInvalid, path, "duplicate edit of "+e.Field+" for action "+e.ActionID)
			case !exposed[key]:
				if _, registered := editBinding[e.Field]; !registered {
					return nil, nil, refuse(value.CompositionInvalid, path+".field", "unknown field "+strconv.Quote(e.Field))
				}
				return nil, nil, refuse(value.CompositionInvalid, path+".field", p.Name+"/"+p.Version+" does not expose "+e.Field+" for action "+e.ActionID+"; choose Customize to author a new recipe")
			}
			seen[key] = true
			if err := applyEdit(path, e, &actions[at]); err != nil {
				return nil, nil, err
			}
		}
		for i := first; i < len(actions); i++ {
			if err := normalize(pathf("%s action %s", base, actions[i].localID), &actions[i], compiler, pc); err != nil {
				return nil, nil, err
			}
		}
	}
	var total int64
	var longest time.Duration
	kinds := map[string]string{}
	for _, x := range actions {
		total += x.action.Limits.MaxBytes
		t, _ := durationValue(x.action.Limits.Timeout, false)
		longest = max(longest, t)
		// One packet and one syscall source per Pod: no coexistence profile
		// qualifies two sources of one kind, and identical ones would acquire
		// the same evidence twice.
		alias := x.componentID + "/" + x.localID
		if other, dup := kinds[x.action.Kind]; dup {
			return nil, nil, refuse(value.CompositionConflict, "profile_composition.components", alias+" and "+other+" are both "+x.action.Kind+" recorders on the same Pods; keep one and adjust its filter or windows")
		}
		kinds[x.action.Kind] = alias
	}
	if total > c.MaxTotalBytes {
		return nil, nil, refuse(value.CompositionInvalid, "profile_composition.maxTotalBytes", "the actions may write "+strconv.FormatInt(total, 10)+" bytes; raise maxTotalBytes explicitly or lower the action output limit")
	}
	if d, ok := durationValue(c.MaxDuration, false); !ok || d < longest {
		return nil, nil, refuse(value.CompositionInvalid, "profile_composition.maxDuration", "maxDuration must cover the longest action timeout ("+longest.String()+")")
	}
	return actions, profiles, nil
}

// ValidateComposition compiles an authored composition without target facts,
// for callers that only need its field-level refusals.
func ValidateComposition(c value.ProfileComposition, compiler FilterCompiler) error {
	_, _, err := expand(c, compiler, nil)
	return err
}

type lifecycleRecord struct {
	ActionID        string `json:"actionID"`
	Kind            string `json:"kind"`
	ExecutionMode   string `json:"executionMode"`
	Activation      string `json:"activation,omitempty"`
	RequestedBefore string `json:"requestedBefore,omitempty"`
	After           string `json:"after,omitempty"`
}

type lifecyclePlan struct {
	SchemaVersion   string            `json:"schemaVersion"`
	RequestKind     string            `json:"requestKind"`
	Actions         []lifecycleRecord `json:"actions"`
	OngoingPodScope string            `json:"ongoingPodScope"`
}

type wireRef struct {
	Catalog string `json:"catalog"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type wireOverride struct {
	ActionID string `json:"actionID"`
	Field    string `json:"field"`
	Value    any    `json:"value"`
}

type wireComponent struct {
	ID         string         `json:"id"`
	ProfileRef wireRef        `json:"profileRef"`
	Overrides  []wireOverride `json:"overrides,omitempty"`
}

type wireComposition struct {
	Components    []wireComponent `json:"components"`
	MaxTotalBytes int64           `json:"maxTotalBytes"`
	MaxDuration   string          `json:"maxDuration"`
}

type wireResolved struct {
	ComponentID        string  `json:"componentID"`
	ProfileRef         wireRef `json:"profileRef"`
	DefinitionDigest   string  `json:"definitionDigest"`
	SourceUID          string  `json:"sourceUID,omitempty"`
	SourceClusterID    string  `json:"sourceClusterID,omitempty"`
	SourceNamespaceUID string  `json:"sourceNamespaceUID,omitempty"`
}

type wireAlias struct {
	ComponentID   string `json:"componentID"`
	LocalActionID string `json:"localActionID"`
	ActionID      string `json:"actionID"`
	Deduplicated  bool   `json:"deduplicated"`
}

type wireProvenance struct {
	Authored         wireComposition `json:"authored"`
	ResolvedProfiles []wireResolved  `json:"resolvedProfiles"`
	ActionMap        []wireAlias     `json:"actionMap"`
}

// editValue reconstructs the literal wire value of a typed edit.
func editValue(e value.ProfileEdit) any {
	switch {
	case e.Ring != nil:
		return editRing(e.Ring)
	case e.Syscalls != nil:
		return syscallSelection{Mode: e.Syscalls.Mode, Names: e.Syscalls.Names}
	case e.Peers != nil:
		return peersEditWire(e.Peers)
	case e.Number != 0:
		return e.Number
	}
	return e.Text
}

func authored(c value.ProfileComposition) wireComposition {
	out := wireComposition{MaxTotalBytes: c.MaxTotalBytes, MaxDuration: c.MaxDuration}
	for _, component := range c.Components {
		w := wireComponent{ID: component.ID, ProfileRef: wireRef{component.Profile.Catalog, component.Profile.Name, component.Profile.Version}}
		for _, e := range component.Edits {
			w.Overrides = append(w.Overrides, wireOverride{e.ActionID, e.Field, editValue(e)})
		}
		out.Components = append(out.Components, w)
	}
	return out
}

// CompositionProvenance is the capture-composition $defs/provenance document of
// a compiled plan, in canonical JSON. A builtin carries no source object (S6).
func CompositionProvenance(plan value.RecorderPlan) ([]byte, error) {
	var scope struct {
		Provenance json.RawMessage `json:"profileComposition"`
	}
	if json.Unmarshal(plan.CanonicalScope, &scope) != nil || len(scope.Provenance) == 0 {
		return nil, value.ErrInvalid
	}
	return bytes.Clone(scope.Provenance), nil
}

// LifecyclePlanJSON is the action-lifecycle/v1 plan of a compiled recorder plan.
func LifecyclePlanJSON(plan value.RecorderPlan) ([]byte, error) {
	var scope struct {
		Lifecycle json.RawMessage `json:"lifecycle"`
	}
	if json.Unmarshal(plan.CanonicalScope, &scope) != nil || len(scope.Lifecycle) == 0 {
		return nil, value.ErrInvalid
	}
	return bytes.Clone(scope.Lifecycle), nil
}

type compiledFilterRecord struct {
	ActionID      string      `json:"actionID"`
	Expression    string      `json:"expression"`
	LinkType      string      `json:"linkType"`
	Snaplen       int         `json:"snaplen"`
	Encoding      string      `json:"encoding"`
	Program       [][4]uint32 `json:"program"`
	ProgramDigest string      `json:"programDigest"`
	// Peers is the CIDR peer provenance (ADR-283): absent for whole-pod
	// plans, so their scopes and digests are unchanged.
	Peers *peerSetRecord `json:"peers,omitempty"`
}

type recorderTarget struct {
	Namespace string   `json:"namespace"`
	Workload  workload `json:"workloadRef"`
	PodUID    string   `json:"podUID"`
}

// approvalRecord is the plan's sensitive-acquisition requirement (ADR-249).
// It is part of the execution digest, so the approved grant binds it.
type approvalRecord struct {
	DataClass         string                   `json:"dataClass"`
	Reasons           []reasonRecord           `json:"reasons"`
	ObservationLimits *observationLimitsRecord `json:"observationLimits,omitempty"`
}

type reasonRecord struct {
	ActionID string `json:"actionID"`
	Code     string `json:"code"`
}

type observationLimitsRecord struct {
	MaxSessionSeconds     int64 `json:"maxSessionSeconds"`
	MaxObservedBytes      int64 `json:"maxObservedBytes"`
	MaxBytesPerSecond     int64 `json:"maxBytesPerSecond"`
	MaxConcurrentSessions int64 `json:"maxConcurrentSessions"`
}

type recorderScope struct {
	Version    string                 `json:"schemaVersion"`
	Source     source                 `json:"source"`
	Executor   principal              `json:"executor"`
	Target     recorderTarget         `json:"target"`
	RecipeRef  recipeRef              `json:"recipeRef"`
	Recipe     json.RawMessage        `json:"recipe"`
	Provenance wireProvenance         `json:"profileComposition"`
	Lifecycle  lifecyclePlan          `json:"lifecycle"`
	Filters    []compiledFilterRecord `json:"filters"`
	Retention  []effectiveRetention   `json:"effectiveRetention"`
	Deadline   string                 `json:"deadline"`
	Timing     string                 `json:"timing,omitempty"`
	Interim    string                 `json:"acceptance"`
	Approval   *approvalRecord        `json:"approval,omitempty"`
}

// normalizedRecorderAction is shared by manual and policy compilation. It
// resolves immutable profile edits and compiled filter bytes without inventing
// a capture identity, Pod, retention decision or caller authority.
func normalizedRecorderAction(x expandedAction, componentID string) (recipeAction, value.RecorderAction, *compiledFilterRecord, error) {
	var filter *compiledFilterRecord
	id := generatedID("a", componentID, x.localID)
	a := x.action
	a.ID = id
	var params any
	summary := value.RecorderAction{ID: id, ComponentID: componentID, LocalID: x.localID, Kind: a.Kind, ExecutionMode: a.ExecutionMode, EvidenceType: evidenceType(a.Kind), Timeout: a.Limits.Timeout, MaxBytes: a.Limits.MaxBytes}
	var rr ring
	if x.packet != nil {
		params = x.packet
		var kind struct {
			Kind string `json:"kind"`
		}
		_ = json.Unmarshal(x.packet.Profile, &kind)
		summary.Before, summary.After, summary.MaxFrozenBytes, summary.MaxConcurrentSnapshots, summary.PacketProfile, summary.Filter = x.packet.Before, x.packet.After, x.packet.MaxFrozenBytes, x.packet.MaxConcurrentSnapshots, kind.Kind, x.expression
		if x.peers != nil {
			summary.PeerPrefixes = len(x.peers.Prefixes)
			if k := x.peers.kubernetes; k != nil {
				summary.PeerEndpoints, summary.PeerMembersDigest = k.Endpoints, k.MembersDigest
			}
		}
		rr = x.packet.Ring
	} else {
		s := x.syscall
		params = s
		summary.Before, summary.After, summary.MaxFrozenBytes, summary.MaxConcurrentSnapshots = s.Before, s.After, s.MaxFrozenBytes, s.MaxConcurrentSnapshots
		summary.SyscallMode, summary.SyscallSelection, summary.SyscallNames, summary.Result = s.Mode, s.Syscalls.Mode, len(s.Syscalls.Names), s.Result
		summary.MaxEvents, summary.MaxEventsPerSecond, summary.MaxTrackedThreads = s.MaxEvents, s.MaxEventsPerSecond, s.MaxTrackedThreads
		rr = s.Ring
	}
	summary.RingMaxAge, summary.RingMaxBytes, summary.SegmentBytes, summary.MaxSegments = rr.MaxAge, rr.MaxBytes, rr.SegmentBytes, rr.MaxSegments
	if rr.Medium == "encryptedDisk" {
		summary.RingMedium = rr.Medium
	}
	if encoded, err := json.Marshal(params); err != nil {
		return recipeAction{}, value.RecorderAction{}, nil, value.ErrInvalid
	} else {
		a.Parameters = encoded
	}
	if x.filter != nil {
		program := make([][4]uint32, 0, len(x.filter.Program))
		for _, ins := range x.filter.Program {
			program = append(program, [4]uint32{uint32(ins.Code), uint32(ins.Jt), uint32(ins.Jf), ins.K})
		}
		d := FilterProgramDigest(x.filter.Program)
		summary.FilterInstructions, summary.FilterDigest = len(x.filter.Program), d
		filter = &compiledFilterRecord{ActionID: id, Expression: x.expression, LinkType: x.filter.LinkType, Snaplen: x.filter.Snaplen, Encoding: value.FilterProgramEncoding, Program: program, ProgramDigest: hexDigest(d)}
		if x.peers != nil {
			filter.Peers = x.peers.record(x.packet.Filter)
		}
	}
	return a, summary, filter, nil
}

// CompileRecorder compiles a one-component packet or syscall composition into
// the reviewable recorder-preview/v1 plan (ADR-243). Only independently
// resolved target, executor and retention facts enter it; reason, sharing and
// idempotency do not. The plan is never an accepted execution scope.
func CompileRecorder(in value.RecorderInput, filters FilterCompiler, now time.Time) (value.RecorderPlan, error) {
	bad := func() (value.RecorderPlan, error) { return value.RecorderPlan{}, value.ErrInvalid }
	if !authorization.UUID(in.CaptureID) || !in.Executor.Valid() || !in.Target.Valid(now) || in.Deadline.Nanosecond()%1000 != 0 || !now.Before(in.Deadline) || in.Deadline.After(now.Add(5*time.Minute)) {
		return bad()
	}
	pc := &peerContext{clusterID: in.Target.Request.ClusterID, namespace: in.Target.Request.Namespace, resolved: in.Peers, now: now, used: map[int]bool{}}
	actions, profiles, err := expand(in.Composition, filters, pc)
	if err != nil {
		return value.RecorderPlan{}, err
	}
	if len(pc.used) != len(in.Peers) {
		// Every supplied resolution answers one action's exact query.
		return bad()
	}
	r := in.Retention
	if r.Target != in.Target.Target() || !r.PolicyRevision.Valid() || !now.Before(r.ValidUntil) || r.ValidUntil.After(now.Add(60*time.Second)) || r.PrivacyClass != "potentialPersonalData" || !r.Deadlines.Valid() || r.AnchorAt.After(now) || !identity.Text(r.PurposeRef, 128) || len(r.Policies) < 1 || len(r.Policies) > 64 {
		return bad()
	}
	if r.RequestedSeconds < 1 || r.MaximumSeconds < 1 || r.DeletionBudgetSeconds < 1 || r.DeletionBudgetSeconds > 86400 || r.DeletionBudgetSeconds >= r.MaximumSeconds {
		return bad()
	}
	expected := r.AnchorAt.Add(time.Duration(min(r.RequestedSeconds, r.MaximumSeconds-r.DeletionBudgetSeconds)) * time.Second)
	if !r.ExpiresAt.Equal(expected) || !r.DeleteBy.Equal(expected.Add(time.Duration(r.DeletionBudgetSeconds)*time.Second)) {
		return bad()
	}
	approval := &approvalRecord{DataClass: "extract"}
	refs := make([]policyRef, 0, len(r.Policies))
	seen := map[string]bool{}
	for _, p := range r.Policies {
		if !identity.Text(p.UID, 64) || p.Generation < 1 || p.Digest == (artifact.Digest{}) || seen[p.UID] {
			return bad()
		}
		seen[p.UID] = true
		refs = append(refs, policyRef{p.UID, p.Generation, hexDigest(p.Digest)})
	}
	slices.SortFunc(refs, func(a, b policyRef) int { return strings.Compare(a.UID, b.UID) })

	expanded := recipeSpec{Description: ExpandedRecipeDescription, MaxTotalBytes: in.Composition.MaxTotalBytes, MaxDuration: in.Composition.MaxDuration}
	scope := recorderScope{Version: value.RecorderPlanVersion, Deadline: in.Deadline.UTC().Format(time.RFC3339Nano), Interim: "recorderUnavailable"}
	if in.NodeRecorder {
		scope.Interim = "nodeRecorder"
	}
	scope.Provenance = wireProvenance{Authored: authored(in.Composition)}
	scope.Lifecycle = lifecyclePlan{SchemaVersion: "action-lifecycle/v1", RequestKind: "DebugCapture", OngoingPodScope: "none"}
	scope.Filters = []compiledFilterRecord{}
	out := value.RecorderPlan{Input: in, CompiledAt: now}
	for i, profile := range profiles {
		component := in.Composition.Components[i]
		scope.Provenance.ResolvedProfiles = append(scope.Provenance.ResolvedProfiles, profile.wire(component.ID))
		out.Profiles = append(out.Profiles, value.ResolvedProfile{ComponentID: component.ID, Ref: component.Profile, DefinitionDigest: profile.Digest, SourceClusterID: profile.SourceClusterID, SourceNamespaceUID: profile.SourceNamespaceUID, SourceUID: profile.SourceUID, Deprecated: profile.Deprecated})
	}
	for _, x := range actions {
		a, summary, filter, err := normalizedRecorderAction(x, x.componentID)
		if err != nil {
			return bad()
		}
		id := a.ID
		if filter != nil {
			scope.Filters = append(scope.Filters, *filter)
		}
		if summary.EvidenceType != r.EvidenceType {
			return bad()
		}
		record := lifecycleRecord{ActionID: id, Kind: a.Kind, ExecutionMode: a.ExecutionMode, RequestedBefore: summary.Before, After: summary.After}
		if a.ExecutionMode == "ongoing" {
			record.Activation = "manualSession"
			scope.Lifecycle.OngoingPodScope = "acceptedCapturePods"
		}
		scope.Lifecycle.Actions = append(scope.Lifecycle.Actions, record)
		codes := slices.Clone(x.sensitive)
		if in.RequireApproval {
			codes = append(codes, value.ReasonRecordingApproval)
		}
		for _, code := range codes {
			approval.Reasons = append(approval.Reasons, reasonRecord{id, code})
			summary.Sensitive = append(summary.Sensitive, code)
		}
		if slices.Contains(x.sensitive, value.ReasonRawPackets) {
			approval.DataClass = "raw" // ADR-279: payload prefixes are raw output
		}
		if slices.Contains(x.sensitive, value.ReasonRawBytePredicate) || slices.Contains(x.sensitive, value.ReasonRawPackets) || slices.Contains(x.sensitive, value.ReasonHTTPHeaders) {
			// REQ-AUT-006: a payload-sensitive predicate, raw recording or
			// HTTP header projection (ADR-282, class extract) needs finite
			// observation limits before any byte reaches it.
			t, _ := durationValue(a.Limits.Timeout, false)
			limits := observationLimitsRecord{MaxSessionSeconds: int64(min(t, time.Hour) / time.Second), MaxObservedBytes: value.SensitiveMaxObservedBytes, MaxBytesPerSecond: value.SensitiveMaxBytesPerSecond, MaxConcurrentSessions: 1}
			if approval.ObservationLimits == nil {
				approval.ObservationLimits = &limits
			} else {
				approval.ObservationLimits.MaxSessionSeconds = max(approval.ObservationLimits.MaxSessionSeconds, limits.MaxSessionSeconds)
			}
		}
		scope.Provenance.ActionMap = append(scope.Provenance.ActionMap, wireAlias{x.componentID, x.localID, id, false})
		scope.Retention = append(scope.Retention, effectiveRetention{id, r.PurposeRef, r.PrivacyClass, r.EvidenceType, r.RequestedSeconds, r.MaximumSeconds, r.DeletionBudgetSeconds, refs})
		expanded.Actions = append(expanded.Actions, a)
		out.Actions = append(out.Actions, summary)
	}
	if len(approval.Reasons) > 0 {
		scope.Approval = approval
		// ADR-252: review expiry and execution time are independent.
		// The marked plan binds finite action durations; admission fixes its
		// one execution deadline under the current grant. Older plans retain
		// their original absolute deadline and cannot gain this interpretation.
		scope.Timing, scope.Deadline = "approvedAcceptance/v1", ""
		out.Approval = &value.RecorderApproval{DataClass: approval.DataClass}
		for _, r := range approval.Reasons {
			out.Approval.Reasons = append(out.Approval.Reasons, authorization.SensitiveReason{ActionID: r.ActionID, Code: r.Code})
		}
		if l := approval.ObservationLimits; l != nil {
			out.Approval.ObservationLimits = &value.ObservationLimits{MaxSessionSeconds: l.MaxSessionSeconds, MaxObservedBytes: l.MaxObservedBytes, MaxBytesPerSecond: l.MaxBytesPerSecond, MaxConcurrentSessions: l.MaxConcurrentSessions}
		}
	}
	recipeBytes, err := json.Marshal(expanded)
	if err != nil {
		return bad()
	}
	recipeBytes, recipeDigest, err := canonical(recipeBytes)
	if err != nil {
		return bad()
	}
	q := in.Target.Request
	api := "apps/v1"
	if q.Workload.Kind == "Pod" {
		api = "v1"
	}
	scope.Source = source{q.ClusterID, q.Namespace.UID, in.CaptureID}
	scope.Executor = principal{in.Executor.Issuer, in.Executor.Subject, in.Executor.ClientID, string(in.Executor.Kind)}
	scope.Target = recorderTarget{q.Namespace.Name, workload{api, q.Workload.Kind, q.Workload.Name, q.Workload.UID}, q.PodUID}
	scope.RecipeRef = recipeRef{"composition-" + hexDigest(recipeDigest)[:24], hexDigest(recipeDigest)}
	scope.Recipe = recipeBytes
	b, err := json.Marshal(scope)
	if err != nil {
		return bad()
	}
	b, d, err := canonical(b)
	if err != nil || len(b) > 64<<10 {
		return bad()
	}
	out.Input.Retention.Policies = slices.Clone(in.Retention.Policies)
	out.Input.Peers = clonePeerResolutions(in.Peers)
	out.Input.Composition = *in.Composition.Clone()
	out.RecipeDigest, out.CanonicalScope, out.ScopeDigest = recipeDigest, b, d
	out.ValidUntil = identity.Earlier(identity.Earlier(in.Target.FreshUntil, r.ValidUntil), in.Deadline)
	return out, nil
}

// VerifyRecorderPlan recompiles the plan's input and compares the result.
func VerifyRecorderPlan(plan value.RecorderPlan, filters FilterCompiler, now time.Time) bool {
	fresh, err := CompileRecorder(plan.Input, filters, now)
	return err == nil && fresh.ScopeDigest == plan.ScopeDigest && bytes.Equal(fresh.CanonicalScope, plan.CanonicalScope)
}

// RecorderScopeSummary reads the reviewable action summary and the approval
// requirement back from a persisted canonical recorder-preview/v1 scope
// (ADR-249). It presents the frozen plan; it never recompiles it, and the
// scope digest stays the authority.
func RecorderScopeSummary(scope []byte) ([]value.RecorderAction, *value.RecorderApproval, error) {
	var doc recorderScope
	if strict(scope, &doc) != nil || doc.Version != value.RecorderPlanVersion {
		return nil, nil, value.ErrInvalid
	}
	var recipe recipeSpec
	if strict(doc.Recipe, &recipe) != nil || len(recipe.Actions) < 1 || len(recipe.Actions) > 16 {
		return nil, nil, value.ErrInvalid
	}
	filters := map[string]compiledFilterRecord{}
	for _, f := range doc.Filters {
		filters[f.ActionID] = f
	}
	out := make([]value.RecorderAction, 0, len(recipe.Actions))
	for _, a := range recipe.Actions {
		s := value.RecorderAction{ID: a.ID, Kind: a.Kind, ExecutionMode: a.ExecutionMode, Timeout: a.Limits.Timeout, MaxBytes: a.Limits.MaxBytes, EvidenceType: evidenceType(a.Kind)}
		var r ring
		switch a.Kind {
		case "packetCapture":
			var p packetParameters
			if strict(a.Parameters, &p) != nil {
				return nil, nil, value.ErrInvalid
			}
			s.Before, s.After, s.Filter, r = p.Before, p.After, p.Filter, p.Ring
		case "syscallTrace":
			var p syscallParameters
			if strict(a.Parameters, &p) != nil {
				return nil, nil, value.ErrInvalid
			}
			s.Before, s.After, s.SyscallMode, r = p.Before, p.After, p.Mode, p.Ring
		default:
			return nil, nil, value.ErrInvalid
		}
		s.RingMaxAge, s.RingMaxBytes = r.MaxAge, r.MaxBytes
		if f, ok := filters[a.ID]; ok {
			b, err := hex.DecodeString(f.ProgramDigest)
			if err != nil || len(b) != len(s.FilterDigest) {
				return nil, nil, value.ErrInvalid
			}
			copy(s.FilterDigest[:], b)
			s.FilterInstructions, s.Filter = len(f.Program), f.Expression
			if f.Peers != nil {
				s.PeerPrefixes = len(f.Peers.Prefixes)
				if k := f.Peers.Kubernetes; k != nil {
					s.PeerEndpoints, s.PeerMembersDigest = k.Endpoints, k.MembersDigest
				}
			}
		}
		out = append(out, s)
	}
	if doc.Approval == nil {
		return out, nil, nil
	}
	approval := &value.RecorderApproval{DataClass: doc.Approval.DataClass}
	for _, r := range doc.Approval.Reasons {
		approval.Reasons = append(approval.Reasons, authorization.SensitiveReason{ActionID: r.ActionID, Code: r.Code})
		for i := range out {
			if out[i].ID == r.ActionID {
				out[i].Sensitive = append(out[i].Sensitive, r.Code)
			}
		}
	}
	if l := doc.Approval.ObservationLimits; l != nil {
		approval.ObservationLimits = &value.ObservationLimits{MaxSessionSeconds: l.MaxSessionSeconds, MaxObservedBytes: l.MaxObservedBytes, MaxBytesPerSecond: l.MaxBytesPerSecond, MaxConcurrentSessions: l.MaxConcurrentSessions}
	}
	if len(approval.Reasons) == 0 {
		return nil, nil, value.ErrInvalid
	}
	return out, approval, nil
}

func clonePeerResolutions(in []targets.PeerResolution) []targets.PeerResolution {
	if in == nil {
		return nil
	}
	out := make([]targets.PeerResolution, len(in))
	for i, r := range in {
		out[i] = r.Clone()
	}
	return out
}
