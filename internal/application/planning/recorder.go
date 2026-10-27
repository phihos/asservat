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
}

type builtinProfile struct {
	Name, Version string
	Definition    profileDefinition
	Digest        artifact.Digest
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

func loadBuiltin(name string) (builtinProfile, error) {
	b, err := builtinFiles.ReadFile("profiles/" + name + "-v1.json")
	if err != nil {
		return builtinProfile{}, err
	}
	var doc struct {
		Name       string          `json:"name"`
		Version    string          `json:"version"`
		Definition json.RawMessage `json:"definition"`
	}
	if err := strict(b, &doc); err != nil {
		return builtinProfile{}, err
	}
	var def profileDefinition
	if err := strict(doc.Definition, &def); err != nil {
		return builtinProfile{}, err
	}
	_, digest, err := canonical(b)
	if err != nil || doc.Name != name || doc.Version != "v1" {
		return builtinProfile{}, value.ErrInvalid
	}
	return builtinProfile{Name: doc.Name, Version: doc.Version, Definition: def, Digest: digest}, nil
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

func resolveBuiltin(i int, ref value.ProfileRef) (builtinProfile, error) {
	path := pathf("profile_composition.components[%d].profileRef", i)
	if ref.Catalog != "builtin" {
		return builtinProfile{}, refuse(value.CompositionProfileMissing, path, "organization and namespace capture profile catalogs are not available in this release; select a builtin profile")
	}
	if !slices.Contains(builtinNames, ref.Name) {
		return builtinProfile{}, refuse(value.CompositionProfileMissing, path, "builtin profile "+strconv.Quote(ref.Name)+" is not available in this release; available: network-connections/v1, syscall-activity/v1")
	}
	if ref.Version != "v1" {
		return builtinProfile{}, refuse(value.CompositionProfileMissing, path, "version "+strconv.Quote(ref.Version)+" of builtin "+ref.Name+" does not exist; available: v1")
	}
	p, err := loadBuiltin(ref.Name)
	if err != nil {
		return builtinProfile{}, value.ErrInvalid
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

// RecorderEvidenceType resolves the single evidence type of a one-component
// composition, so the caller can resolve its retention before compilation.
func RecorderEvidenceType(c value.ProfileComposition) (string, error) {
	if err := compositionShape(c); err != nil {
		return "", err
	}
	p, err := resolveBuiltin(0, c.Components[0].Profile)
	if err != nil {
		return "", err
	}
	kind := ""
	for _, a := range p.Definition.Recipe.Actions {
		if kind != "" && a.Kind != kind || evidenceType(a.Kind) == "" {
			return "", value.ErrInvalid
		}
		kind = a.Kind
	}
	return evidenceType(kind), nil
}

func compositionShape(c value.ProfileComposition) error {
	if !c.Valid() {
		return refuse(value.CompositionInvalid, "profile_composition", "the composition is malformed")
	}
	if len(c.Components) != 1 {
		return refuse(value.CompositionInvalid, "profile_composition.components", "this release previews exactly one capture profile; composing several profiles follows with the profile catalogs")
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
	localID string
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
			reason = "Kubernetes peer selection follows in a later release; narrow traffic with packetFilter host, net or port primitives"
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

func validRing(path string, r ring, before time.Duration) error {
	age, ok := durationValue(r.MaxAge, false)
	switch {
	case !ok || age > maxRingAge:
		return refuse(value.CompositionInvalid, path+".maxAge", "the ring age must be a duration of at most 1h")
	case r.Medium == "encryptedDisk":
		return refuse(value.CompositionInvalid, path+".medium", "the encrypted-disk ring medium is not available in this release; use memory")
	case r.Medium != "memory" || r.StorageProfileRef != "":
		return refuse(value.CompositionInvalid, path+".medium", "the ring medium must be memory")
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
func normalize(path string, a *expandedAction, compiler FilterCompiler) error {
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
	if a.action.Impact != "observe" {
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
		if json.Unmarshal(a.packet.Profile, &kind) != nil || kind.Kind != "networkHeaders" {
			return refuse(value.CompositionApproval, path+".parameters.profile.kind", "HTTP headers and raw packets need sensitive capture approval, which this release does not offer; use networkHeaders")
		}
		beforeText, afterText, r, frozen, snapshots = a.packet.Before, a.packet.After, a.packet.Ring, a.packet.MaxFrozenBytes, a.packet.MaxConcurrentSnapshots
	} else {
		s := a.syscall
		if s.Mode != "metadata" || len(s.Arguments) != 0 {
			return refuse(value.CompositionApproval, path+".parameters.mode", "syscall argument tracing needs sensitive observation approval, which this release does not offer; use metadata")
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
	if a.packet != nil && a.packet.Filter != "" {
		f, err := compileFilter(compiler, path+".parameters.filter", a.packet.Filter)
		if err != nil {
			return err
		}
		a.packet.Filter = NormalizeFilter(a.packet.Filter)
		a.filter = &f
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

// expand resolves the single builtin, applies the typed edits and normalizes
// every action. Edits are applied first; the plan is validated as a whole.
func expand(c value.ProfileComposition, compiler FilterCompiler) ([]expandedAction, builtinProfile, error) {
	if err := compositionShape(c); err != nil {
		return nil, builtinProfile{}, err
	}
	component := c.Components[0]
	p, err := resolveBuiltin(0, component.Profile)
	if err != nil {
		return nil, builtinProfile{}, err
	}
	actions := make([]expandedAction, 0, len(p.Definition.Recipe.Actions))
	index := map[string]int{}
	for _, a := range p.Definition.Recipe.Actions {
		x := expandedAction{action: a, localID: a.ID}
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
			return nil, builtinProfile{}, value.ErrInvalid
		}
		index[a.ID] = len(actions)
		actions = append(actions, x)
	}
	exposed := map[[2]string]bool{}
	for _, f := range p.Definition.EditableFields {
		exposed[[2]string{f.ActionID, f.Field}] = true
	}
	seen := map[[2]string]bool{}
	for j, e := range component.Edits {
		path := pathf("profile_composition.components[0].overrides[%d]", j)
		key := [2]string{e.ActionID, e.Field}
		at, found := index[e.ActionID]
		switch {
		case !found:
			return nil, builtinProfile{}, refuse(value.CompositionInvalid, path+".actionID", "profile "+p.Name+"/v1 has no action "+strconv.Quote(e.ActionID))
		case seen[key]:
			return nil, builtinProfile{}, refuse(value.CompositionInvalid, path, "duplicate edit of "+e.Field+" for action "+e.ActionID)
		case !exposed[key]:
			if _, registered := editBinding[e.Field]; !registered {
				return nil, builtinProfile{}, refuse(value.CompositionInvalid, path+".field", "unknown field "+strconv.Quote(e.Field))
			}
			return nil, builtinProfile{}, refuse(value.CompositionInvalid, path+".field", p.Name+"/v1 does not expose "+e.Field+" for action "+e.ActionID+"; choose Customize to author a new recipe")
		}
		seen[key] = true
		if err := applyEdit(path, e, &actions[at]); err != nil {
			return nil, builtinProfile{}, err
		}
	}
	var total int64
	var longest time.Duration
	for i := range actions {
		path := pathf("profile_composition.components[0] action %s", actions[i].localID)
		if err := normalize(path, &actions[i], compiler); err != nil {
			return nil, builtinProfile{}, err
		}
		total += actions[i].action.Limits.MaxBytes
		t, _ := durationValue(actions[i].action.Limits.Timeout, false)
		longest = max(longest, t)
	}
	if total > c.MaxTotalBytes {
		return nil, builtinProfile{}, refuse(value.CompositionInvalid, "profile_composition.maxTotalBytes", "the actions may write "+strconv.FormatInt(total, 10)+" bytes; raise maxTotalBytes explicitly or lower the action output limit")
	}
	if d, ok := durationValue(c.MaxDuration, false); !ok || d < longest {
		return nil, builtinProfile{}, refuse(value.CompositionInvalid, "profile_composition.maxDuration", "maxDuration must cover the longest action timeout ("+longest.String()+")")
	}
	return actions, p, nil
}

// ValidateComposition compiles an authored composition without target facts,
// for callers that only need its field-level refusals.
func ValidateComposition(c value.ProfileComposition, compiler FilterCompiler) error {
	_, _, err := expand(c, compiler)
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
	ComponentID      string  `json:"componentID"`
	ProfileRef       wireRef `json:"profileRef"`
	DefinitionDigest string  `json:"definitionDigest"`
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
}

type recorderTarget struct {
	Namespace string   `json:"namespace"`
	Workload  workload `json:"workloadRef"`
	PodUID    string   `json:"podUID"`
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
	Interim    string                 `json:"acceptance"`
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
	actions, profile, err := expand(in.Composition, filters)
	if err != nil {
		return value.RecorderPlan{}, err
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

	component := in.Composition.Components[0]
	expanded := recipeSpec{Description: ExpandedRecipeDescription, MaxTotalBytes: in.Composition.MaxTotalBytes, MaxDuration: in.Composition.MaxDuration}
	scope := recorderScope{Version: value.RecorderPlanVersion, Deadline: in.Deadline.UTC().Format(time.RFC3339Nano), Interim: "recorderUnavailable"}
	scope.Provenance = wireProvenance{Authored: authored(in.Composition), ResolvedProfiles: []wireResolved{{component.ID, wireRef{"builtin", profile.Name, profile.Version}, hexDigest(profile.Digest)}}}
	scope.Lifecycle = lifecyclePlan{SchemaVersion: "action-lifecycle/v1", RequestKind: "DebugCapture", OngoingPodScope: "none"}
	scope.Filters = []compiledFilterRecord{}
	out := value.RecorderPlan{Input: in, Profiles: []value.ResolvedProfile{{ComponentID: component.ID, Ref: component.Profile, DefinitionDigest: profile.Digest}}, CompiledAt: now}
	for _, x := range actions {
		id := generatedID("a", component.ID, x.localID)
		a := x.action
		a.ID = id
		var params any
		summary := value.RecorderAction{ID: id, ComponentID: component.ID, LocalID: x.localID, Kind: a.Kind, ExecutionMode: a.ExecutionMode, EvidenceType: evidenceType(a.Kind), Timeout: a.Limits.Timeout, MaxBytes: a.Limits.MaxBytes}
		var rr ring
		if x.packet != nil {
			params = x.packet
			var kind struct {
				Kind string `json:"kind"`
			}
			_ = json.Unmarshal(x.packet.Profile, &kind)
			summary.Before, summary.After, summary.MaxFrozenBytes, summary.MaxConcurrentSnapshots, summary.PacketProfile, summary.Filter = x.packet.Before, x.packet.After, x.packet.MaxFrozenBytes, x.packet.MaxConcurrentSnapshots, kind.Kind, x.packet.Filter
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
		if a.Parameters, err = json.Marshal(params); err != nil {
			return bad()
		}
		if x.filter != nil {
			program := make([][4]uint32, 0, len(x.filter.Program))
			for _, ins := range x.filter.Program {
				program = append(program, [4]uint32{uint32(ins.Code), uint32(ins.Jt), uint32(ins.Jf), ins.K})
			}
			d := FilterProgramDigest(x.filter.Program)
			summary.FilterInstructions, summary.FilterDigest = len(x.filter.Program), d
			scope.Filters = append(scope.Filters, compiledFilterRecord{id, x.packet.Filter, x.filter.LinkType, x.filter.Snaplen, value.FilterProgramEncoding, program, hexDigest(d)})
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
		scope.Provenance.ActionMap = append(scope.Provenance.ActionMap, wireAlias{component.ID, x.localID, id, false})
		scope.Retention = append(scope.Retention, effectiveRetention{id, r.PurposeRef, r.PrivacyClass, r.EvidenceType, r.RequestedSeconds, r.MaximumSeconds, r.DeletionBudgetSeconds, refs})
		expanded.Actions = append(expanded.Actions, a)
		out.Actions = append(out.Actions, summary)
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
