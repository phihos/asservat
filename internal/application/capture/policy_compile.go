package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strconv"
	"time"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// CompileRestartPolicy compiles a schema-valid DebugPolicy spec. The recipe
// is the installation's exact context recipe, supplied by the caller.
func CompileRestartPolicy(spec []byte, recipeName string, recipeDigest artifact.Digest) (value.RestartPolicy, error) {
	var out value.RestartPolicy
	reject := func(path, reason string) (value.RestartPolicy, error) {
		return value.RestartPolicy{}, value.PolicyFieldError{Path: "spec" + path, Reason: reason}
	}
	var s map[string]json.RawMessage
	if strict(spec, &s) != nil {
		return reject("", "not an object")
	}
	for key := range s {
		switch key {
		case "target", "detectors", "when", "recipeRef", "budgets", "retention", "suspended", "observation", "evaluation", "recordingSaves":
		default:
			return reject("."+key, "unsupported in this release (ADR-228)")
		}
	}
	// Target: one named workload in one cluster; the triggering Pod only.
	var target struct {
		Cluster, Namespace, Selection, Adoption string
		WorkloadRef                             *struct{ APIVersion, Kind, Name, UID string }
		PodSelector                             json.RawMessage
		MaxPods                                 int
		Ordinals                                json.RawMessage
	}
	if strict(s["target"], &target) != nil {
		return reject(".target", "invalid")
	}
	switch {
	case !authorization.UUID(target.Cluster):
		return reject(".target.cluster", "a workload cluster ID is required")
	case target.PodSelector != nil:
		return reject(".target.podSelector", "name a Deployment or StatefulSet")
	case target.Ordinals != nil:
		return reject(".target.ordinals", "unsupported in this release")
	case target.WorkloadRef == nil || target.WorkloadRef.Kind != "Deployment" && target.WorkloadRef.Kind != "StatefulSet":
		return reject(".target.workloadRef.kind", "name a Deployment or StatefulSet")
	case target.WorkloadRef.UID != "":
		return reject(".target.workloadRef.uid", "the hub resolves the workload UID")
	case target.MaxPods != 1:
		return reject(".target.maxPods", "must be 1: each occurrence captures its triggering Pod")
	case target.Selection != "triggeringPod":
		return reject(".target.selection", "must be triggeringPod")
	case target.Adoption != "pinUID":
		return reject(".target.adoption", "must be pinUID")
	}
	out.ClusterID, out.Namespace, out.WorkloadKind, out.WorkloadName = target.Cluster, target.Namespace, target.WorkloadRef.Kind, target.WorkloadRef.Name
	// Detector: exactly one exit (ADR-228) or probe (ADR-230) detector,
	// referenced directly by when.
	var detectors []json.RawMessage
	if strict(s["detectors"], &detectors) != nil || len(detectors) == 0 {
		return reject(".detectors", "invalid")
	}
	if len(detectors) != 1 {
		return reject(".detectors[1]", "exactly one exit or probe detector is supported")
	}
	var detector struct {
		ID, Kind    string
		Options     json.RawMessage
		EventWindow json.RawMessage
	}
	if strict(detectors[0], &detector) != nil {
		return reject(".detectors[0]", "invalid")
	}
	switch detector.Kind {
	case "exit":
		if err := compileExit(&out, detector.Options, detector.EventWindow); err != nil {
			return value.RestartPolicy{}, err
		}
	case "probe":
		if err := compileProbe(&out, detector.Options); err != nil {
			return value.RestartPolicy{}, err
		}
	case "log", "resource":
		// Paused by the ADR-230 complexity gate: a maintainer decision.
		return reject(".detectors[0].kind", "log and resource detectors are not available in this release (ADR-230); use exit or probe")
	default:
		return reject(".detectors[0].kind", "only exit and probe detectors are supported in this release")
	}
	var when struct{ Detector string }
	if strict(s["when"], &when) != nil || when.Detector == "" {
		return reject(".when", "must reference the detector directly")
	}
	if when.Detector != detector.ID {
		return reject(".when.detector", "names no detector")
	}
	var recipe struct{ Name, Digest string }
	if strict(s["recipeRef"], &recipe) != nil {
		return reject(".recipeRef", "invalid")
	}
	if recipe.Name != recipeName {
		return reject(".recipeRef.name", "only "+recipeName+" is supported in this release")
	}
	if recipe.Digest != hex.EncodeToString(recipeDigest[:]) {
		return reject(".recipeRef.digest", "does not match the installed recipe")
	}
	var budgets struct {
		Cooldown              string
		Burst                 int
		MaxOccurrencesPerHour int
		MaxConcurrentActions  int
	}
	if strict(s["budgets"], &budgets) != nil {
		return reject(".budgets", "invalid")
	}
	cooldown, ok := policyDuration(budgets.Cooldown)
	if !ok || cooldown > 24*time.Hour {
		return reject(".budgets.cooldown", "invalid duration")
	}
	if budgets.Burst < 1 || budgets.Burst > 10 || budgets.MaxOccurrencesPerHour < 1 || budgets.MaxConcurrentActions < 1 {
		return reject(".budgets", "invalid")
	}
	out.Interval, out.Burst = max(cooldown, time.Hour/time.Duration(budgets.MaxOccurrencesPerHour), time.Second), budgets.Burst
	var retentionText string
	if strict(s["retention"], &retentionText) != nil {
		return reject(".retention", "invalid duration")
	}
	retention, ok := policyDuration(retentionText)
	if !ok || retention%time.Second != 0 || retention < time.Second || int64(retention/time.Second) > privacy.MaxAgeSeconds {
		return reject(".retention", "invalid duration")
	}
	out.RetentionSeconds = int64(retention / time.Second)
	var observation struct {
		Mode    string
		MaxPods int
	}
	if strict(s["observation"], &observation) != nil || observation.Mode != "allAuthorized" {
		return reject(".observation", "invalid")
	}
	out.ObservedPods = targets.MaxRestartPods
	if observation.MaxPods != 0 {
		if observation.MaxPods > targets.MaxRestartPods {
			return reject(".observation.maxPods", "at most "+strconv.Itoa(targets.MaxRestartPods)+" Pods are observed")
		}
		out.ObservedPods = observation.MaxPods
	}
	if raw, present := s["evaluation"]; present {
		var evaluation struct {
			Scope            string
			FireOnActivation bool
			RearmFor         string
		}
		if strict(raw, &evaluation) != nil {
			return reject(".evaluation", "invalid")
		}
		if evaluation.Scope != "pod" {
			return reject(".evaluation.scope", "triggers are pod-scoped")
		}
		if evaluation.FireOnActivation {
			return reject(".evaluation.fireOnActivation", "activation only records a baseline; a trigger fires on a change after it")
		}
		if out.Detector == value.DetectorProbe && evaluation.RearmFor != "" {
			// A probe re-arms at a poll whose window is empty, which proves a
			// window without failure; a longer rearmFor cannot be proven.
			rearm, ok := policyDuration(evaluation.RearmFor)
			if !ok {
				return reject(".evaluation.rearmFor", "invalid duration")
			}
			if rearm > out.ProbeWindow {
				return reject(".evaluation.rearmFor", "must not exceed the probe window")
			}
		}
	}
	if raw, present := s["recordingSaves"]; present {
		var saves struct{ Enabled bool }
		if json.Unmarshal(raw, &saves) != nil || saves.Enabled {
			return reject(".recordingSaves", "no ongoing recording exists for a context diagnostic")
		}
	}
	if !out.Valid() {
		return reject("", "invalid")
	}
	return out, nil
}

// compileExit selects the ADR-228 exit detector options.
func compileExit(out *value.RestartPolicy, raw, eventWindow json.RawMessage) error {
	reject := func(path, reason string) error {
		return value.PolicyFieldError{Path: "spec.detectors[0]" + path, Reason: reason}
	}
	if eventWindow != nil {
		return reject(".eventWindow", "restart counters need no event window")
	}
	var options struct {
		ExitCodes []int32
		Signals   []int
		Reasons   []string
	}
	if strict(raw, &options) != nil {
		return reject(".options", "invalid")
	}
	if len(options.Signals) > 0 {
		return reject(".options.signals", "Kubernetes reports exit codes, not signals")
	}
	out.Reasons = slices.Clone(options.Reasons)
	if len(out.Reasons) == 0 {
		out.Reasons = []string{"CrashLoopBackOff", "Error", "OOMKilled"}
	}
	for i, r := range out.Reasons {
		if r != "CrashLoopBackOff" && r != "Error" && r != "OOMKilled" {
			return reject(".options.reasons["+strconv.Itoa(i)+"]", "use OOMKilled, Error or CrashLoopBackOff")
		}
	}
	slices.Sort(out.Reasons)
	out.Reasons = slices.Compact(out.Reasons)
	out.ExitCodes = slices.Clone(options.ExitCodes)
	slices.Sort(out.ExitCodes)
	out.ExitCodes = slices.Compact(out.ExitCodes)
	return nil
}

// compileProbe selects the ADR-230 probe detector: failures of one probe
// type from Kubernetes Events, a minimum count and a window of 30 s to 5 min.
func compileProbe(out *value.RestartPolicy, raw json.RawMessage) error {
	reject := func(path, reason string) error {
		return value.PolicyFieldError{Path: "spec.detectors[0].options" + path, Reason: reason}
	}
	var options struct {
		ProbeType       string
		MinimumFailures int
		Window, Source  string
	}
	if strict(raw, &options) != nil {
		return reject("", "invalid")
	}
	if !targets.ProbeType(options.ProbeType) {
		return reject(".probeType", "use Liveness, Readiness or Startup")
	}
	if options.MinimumFailures < 1 || options.MinimumFailures > 1000 {
		return reject(".minimumFailures", "must be 1 to 1000")
	}
	window, ok := policyDuration(options.Window)
	if !ok || window%time.Second != 0 || window < targets.MinProbeWindowSeconds*time.Second || window > targets.MaxProbeWindowSeconds*time.Second {
		return reject(".window", "must be 30s to 5m in whole seconds: a shorter window could miss a failure between two polls")
	}
	switch options.Source {
	case "auto", "events":
	case "kubeletMetrics":
		return reject(".source", "kubelet probe metrics need node access; use events")
	default:
		return reject(".source", "use auto or events")
	}
	out.Detector, out.ProbeType, out.MinimumFailures, out.ProbeWindow = value.DetectorProbe, options.ProbeType, options.MinimumFailures, window
	return nil
}

// DescribePolicyDetector reads only the detector of a DebugPolicy spec for
// status display; it is not a compilation and confers nothing.
func DescribePolicyDetector(spec []byte) (value.PolicyDetector, bool) {
	var s struct {
		Detectors []struct {
			Kind        string
			Options     json.RawMessage
			ID          string
			EventWindow json.RawMessage
		}
	}
	if json.Unmarshal(spec, &s) != nil || len(s.Detectors) != 1 {
		return value.PolicyDetector{}, false
	}
	var p value.RestartPolicy
	d := s.Detectors[0]
	var err error
	switch d.Kind {
	case "exit":
		err = compileExit(&p, d.Options, d.EventWindow)
	case "probe":
		err = compileProbe(&p, d.Options)
	default:
		return value.PolicyDetector{}, false
	}
	if err != nil {
		return value.PolicyDetector{}, false
	}
	return p.Describe(), true
}

// strict decodes a known shape and rejects unknown fields; the canonical
// schema already validated types, so this only selects the accepted subset.
func strict(raw json.RawMessage, out any) error {
	if raw == nil {
		return value.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.More() {
		return value.ErrInvalid
	}
	return nil
}

func policyDuration(s string) (time.Duration, bool) {
	for _, unit := range []struct {
		suffix string
		d      time.Duration
	}{{"ms", time.Millisecond}, {"s", time.Second}, {"m", time.Minute}, {"h", time.Hour}, {"d", 24 * time.Hour}} {
		if n, found := cutSuffix(s, unit.suffix); found {
			v, err := strconv.ParseInt(n, 10, 64)
			if err != nil || v < 1 || v > 1<<20 || n[0] == '0' {
				return 0, false
			}
			return time.Duration(v) * unit.d, true
		}
	}
	return 0, false
}

func cutSuffix(s, suffix string) (string, bool) {
	if len(s) <= len(suffix) || s[len(s)-len(suffix):] != suffix {
		return "", false
	}
	n := s[:len(s)-len(suffix)]
	for _, c := range n {
		if c < '0' || c > '9' {
			return "", false
		}
	}
	return n, true
}

// RestartScopeDigest binds the accepted scope: the exact source revision,
// its compiled intent, the resolved workload and the delegation and limits
// of the acceptance. Issue and expiry times are deliberately excluded, so an
// unchanged source revision can never be re-accepted to reset its spend.
func RestartScopeDigest(source identity.Revision, collection artifact.Digest, p value.RestartPolicy, namespaceUID, workloadUID string, delegation identity.Revision, owners []artifact.AudienceAssignment, actions []string, limits authorization.AutomationLimits) artifact.Digest {
	b, _ := json.Marshal(struct {
		Format                    string
		Source                    identity.Revision
		Collection                artifact.Digest
		Policy                    value.RestartPolicy
		NamespaceUID, WorkloadUID string
		Delegation                identity.Revision
		Owners                    []artifact.AudienceAssignment
		Actions                   []string
		Limits                    authorization.AutomationLimits
	}{"policy-scope/restart/v1", source, collection, p, namespaceUID, workloadUID, delegation, owners, actions, limits})
	return artifact.Digest(sha256.Sum256(b))
}
