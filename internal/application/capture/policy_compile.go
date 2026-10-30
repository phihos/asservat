package capture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"regexp/syntax"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/authorization"
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/identity"
	planvalue "asservat.local/asservat/internal/domain/planning"
	"asservat.local/asservat/internal/domain/privacy"
	"asservat.local/asservat/internal/domain/targets"
)

// PolicyRecorderCompiler converts/compiles a source composition at the
// composition root. Shared DTO decoding stays outside application/domain layers.
type PolicyRecorderCompiler func(json.RawMessage) (planvalue.PolicyRecorderConfiguration, error)

// CompileRestartPolicy compiles a schema-valid DebugPolicy spec. The recipe
// is the installation's exact context recipe, supplied by the caller.
func CompileRestartPolicy(spec []byte, recipeName string, recipeDigest artifact.Digest) (value.RestartPolicy, error) {
	return compilePolicy(spec, recipeName, recipeDigest, nil, false)
}

// CompilePolicyWithRecorders compiles finite recorders and ordinary ongoing
// source intent. Compilation grants no source or incident authority.
func CompilePolicyWithRecorders(spec []byte, recipeName string, recipeDigest artifact.Digest, compileRecorder PolicyRecorderCompiler) (value.RestartPolicy, error) {
	return compilePolicy(spec, recipeName, recipeDigest, compileRecorder, true)
}

func compilePolicy(spec []byte, recipeName string, recipeDigest artifact.Digest, compileRecorder PolicyRecorderCompiler, recorders bool) (value.RestartPolicy, error) {
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
		case "target", "detectors", "when", "recipeRef", "budgets", "retention", "suspended", "observation", "evaluation", "recordingSaves", "sharing":
		case "profileComposition":
			if !recorders {
				return reject(policyComposition(s[key]))
			}
		case "grantRef":
			if !recorders {
				return reject(".grantRef", "policy grants are unavailable on this path")
			}
			if strict(s[key], &out.GrantRef) != nil || !authorization.UUID(out.GrantRef) {
				return reject(".grantRef", "must name an exact grant UUID")
			}
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
	// Detector: exactly one exit (ADR-228), probe (ADR-230), alert
	// (ADR-231), log or resource (ADR-241) detector, referenced directly by
	// when.

	var detectors []json.RawMessage
	if strict(s["detectors"], &detectors) != nil || len(detectors) == 0 {
		return reject(".detectors", "invalid")
	}
	if len(detectors) != 1 {
		return reject(".detectors[1]", "exactly one detector is supported")
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
	case "alert":
		if err := compileAlert(&out, detector.Options, detector.EventWindow); err != nil {
			return value.RestartPolicy{}, err
		}
	case "log":
		if err := compileLog(&out, detector.Options, detector.EventWindow); err != nil {
			return value.RestartPolicy{}, err
		}
	case "resource":
		if err := compileResource(&out, detector.Options); err != nil {
			return value.RestartPolicy{}, err
		}
	default:
		return reject(".detectors[0].kind", "only exit, probe, alert, log and resource detectors are supported in this release")
	}
	var when struct{ Detector string }
	if strict(s["when"], &when) != nil || when.Detector == "" {
		return reject(".when", "must reference the detector directly")
	}
	if when.Detector != detector.ID {
		return reject(".when.detector", "names no detector")
	}
	if raw := s["profileComposition"]; raw != nil {
		if s["recipeRef"] != nil {
			return reject(".recipeRef", "select exactly one recipe or profile composition")
		}
		if compileRecorder == nil {
			return reject(".profileComposition", "recorder compiler unavailable")
		}
		compiled, err := compileRecorder(raw)
		if err != nil {
			return value.RestartPolicy{}, err
		}
		if !compiled.Valid() {
			return reject(".profileComposition", "invalid resolved recording")
		}

		out.Recorder = &compiled
	} else {
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
		if out.Detector == value.DetectorLog && evaluation.RearmFor != "" {
			// A log level re-arms at a poll whose eventWindow holds no matching
			// record, which proves a window without a match (ADR-241).
			rearm, ok := policyDuration(evaluation.RearmFor)
			if !ok {
				return reject(".evaluation.rearmFor", "invalid duration")
			}
			if rearm > time.Duration(out.Log.WindowSeconds)*time.Second {
				return reject(".evaluation.rearmFor", "must not exceed the detector's eventWindow")
			}
		}
		if out.Detector == value.DetectorResource && evaluation.RearmFor != "" {
			// A resource level re-arms at a poll whose fresh sample does not
			// satisfy the condition; the next occurrence can follow one poll
			// later (ADR-241).
			rearm, ok := policyDuration(evaluation.RearmFor)
			if !ok {
				return reject(".evaluation.rearmFor", "invalid duration")
			}
			if rearm > value.TriggerPollInterval {
				return reject(".evaluation.rearmFor", "a resource condition re-arms at the next poll (15s) whose sample no longer satisfies it")
			}
		}
		if out.Detector == value.DetectorAlert && evaluation.RearmFor != "" {
			// An alert re-arms at a poll on which Alertmanager reports no
			// matching alert; the next occurrence can follow one poll later,
			// so the poll interval bounds the re-arm interval (ADR-231).
			rearm, ok := policyDuration(evaluation.RearmFor)
			if !ok {
				return reject(".evaluation.rearmFor", "invalid duration")
			}
			if rearm > value.TriggerPollInterval {
				return reject(".evaluation.rearmFor", "an alert re-arms one poll (15s) after Alertmanager stops reporting it; use keep_firing_for in the alert rule for a longer hold")
			}
		}
	}
	if raw, present := s["recordingSaves"]; present {
		var saves struct{ Enabled bool }
		if json.Unmarshal(raw, &saves) != nil || saves.Enabled && (out.Recorder == nil || out.Recorder.Action.ExecutionMode != "ongoing") {
			return reject(".recordingSaves", "no ongoing recording exists for a context diagnostic")
		}
		out.RecordingSaves = saves.Enabled
	}
	if raw, present := s["sharing"]; present {
		sharing, err := compileSharing(raw)
		if err != nil {
			return value.RestartPolicy{}, err
		}
		out.Sharing = &sharing
	}
	if !out.Valid() {
		return reject("", "invalid")
	}
	return out, nil
}

// compileSharing selects the ADR-239 recurring sharing block: recipients
// (1–8 User/Group stable IDs of one issuer), futureCaptures.maxCaptures
// (1–100) and an absolute notAfter. Output selection, a reason override and
// explicit management are not available for the single-output pod-status
// capture; management is the policy's owner teams. Only the shape is checked
// here: the end and the activating human's authority are checked at
// activation, so a later poll never fails because the end has passed.
func compileSharing(raw json.RawMessage) (value.PolicySharing, error) {
	reject := func(path, reason string) (value.PolicySharing, error) {
		return value.PolicySharing{}, value.PolicyFieldError{Path: "spec.sharing" + path, Reason: reason}
	}
	var fields map[string]json.RawMessage
	if strict(raw, &fields) != nil {
		return reject("", "invalid")
	}
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		switch key {
		case "recipients", "notAfter", "futureCaptures":
		case "outputSelection", "maxArtifactsPerCapture":
			return reject("."+key, "a pod-status capture has one output, which is shared")
		case "management":
			return reject(".management", "management is the policy's owner teams: the automation AccessBinding's evidence-owner groups")
		case "reason":
			return reject(".reason", "unsupported in this release (ADR-239)")
		default:
			return reject("."+key, "unsupported")
		}
	}
	var out value.PolicySharing
	var recipients []struct{ Kind, Issuer, ID string }
	if strict(fields["recipients"], &recipients) != nil || len(recipients) < 1 {
		return reject(".recipients", "invalid")
	}
	if len(recipients) > authorization.ShareMaxRecipients {
		return reject(".recipients", "at most "+strconv.Itoa(authorization.ShareMaxRecipients)+" recipients")
	}
	for i, r := range recipients {
		x := authorization.ShareRecipient{Kind: r.Kind, Issuer: r.Issuer, ID: r.ID}
		if !x.Valid() {
			return reject(".recipients["+strconv.Itoa(i)+"]", "name a User or Group stable ID and its issuer")
		}
		if x.Issuer != recipients[0].Issuer {
			return reject(".recipients["+strconv.Itoa(i)+"].issuer", "all recipients must use one issuer")
		}
		if slices.Contains(out.Recipients, x) {
			return reject(".recipients["+strconv.Itoa(i)+"]", "duplicate recipient")
		}
		out.Recipients = append(out.Recipients, x)
	}
	var future struct {
		Enabled     bool
		MaxCaptures int
	}
	if strict(fields["futureCaptures"], &future) != nil || !future.Enabled {
		return reject(".futureCaptures", "invalid")
	}
	if future.MaxCaptures < 1 || future.MaxCaptures > value.PolicyShareMaxCaptures {
		return reject(".futureCaptures.maxCaptures", "must be 1 to "+strconv.Itoa(value.PolicyShareMaxCaptures))
	}
	out.MaxCaptures = future.MaxCaptures
	var end string
	if strict(fields["notAfter"], &end) != nil {
		return reject(".notAfter", "an absolute time is required")
	}
	at, err := time.Parse(time.RFC3339, end)
	if err != nil {
		return reject(".notAfter", "an absolute RFC 3339 time is required")
	}
	out.NotAfter = at.UTC().Truncate(time.Second)
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

// compileAlert selects the ADR-231 alert detector: active, unsilenced alerts
// of the target cluster's configured Alertmanager whose namespace and pod
// labels name a Pod of the workload and whose other labels equal
// matchLabels.
func compileAlert(out *value.RestartPolicy, raw, eventWindow json.RawMessage) error {
	reject := func(path, reason string) error {
		return value.PolicyFieldError{Path: "spec.detectors[0]" + path, Reason: reason}
	}
	if eventWindow != nil {
		return reject(".eventWindow", "an alert is a level while Alertmanager reports it active; no event window applies")
	}
	var options struct {
		ReceiverRef, Status string
		MatchLabels         map[string]string
	}
	if strict(raw, &options) != nil {
		return reject(".options", "invalid")
	}
	if options.ReceiverRef != value.AlertReceiver {
		return reject(".options.receiverRef", "use "+value.AlertReceiver+": the target cluster's configured Alertmanager")
	}
	if options.Status != "firing" {
		return reject(".options.status", "only firing alerts trigger a capture")
	}
	if len(options.MatchLabels) > targets.MaxAlertLabels {
		return reject(".options.matchLabels", "at most 16 labels")
	}
	for _, k := range slices.Sorted(maps.Keys(options.MatchLabels)) {
		switch v := options.MatchLabels[k]; {
		case k == "namespace" || k == "pod":
			return reject(".options.matchLabels."+k, "the policy's namespace and the alert's Pod are matched already")
		case !targets.AlertLabelName(k):
			return reject(".options.matchLabels", "label names must be Prometheus label names")
		case v == "" || len(v) > 256:
			return reject(".options.matchLabels."+k, "must be 1 to 256 characters")
		}
	}
	out.Detector = value.DetectorAlert
	if len(options.MatchLabels) > 0 {
		out.AlertLabels = options.MatchLabels
	}
	return nil
}

// compileLog selects the ADR-241 log detector: matching records of every
// container of the triggering Pod within eventWindow (30 s to 5 min, default
// 30 s), read through the Kubernetes log API. The pattern is a literal
// substring or an RE2 regular expression (Go's linear-time engine; no
// backreferences or look-around), bounded in compiled size.
func compileLog(out *value.RestartPolicy, raw, eventWindow json.RawMessage) error {
	reject := func(path, reason string) error {
		return value.PolicyFieldError{Path: "spec.detectors[0]" + path, Reason: reason}
	}
	var options struct {
		Stream, Pattern, Match, JSONField, Overlong string
		MaxRecordBytes                              int
	}
	if strict(raw, &options) != nil {
		return reject(".options", "invalid")
	}
	m := targets.LogMatch{Pattern: options.Pattern, JSONField: options.JSONField, MaxRecordBytes: targets.MaxLogRecordBytes, WindowSeconds: 30}
	switch options.Stream {
	case "both":
	case "stdout", "stderr":
		return reject(".options.stream", "the Kubernetes log API returns stdout and stderr together; use both")
	default:
		return reject(".options.stream", "use both")
	}
	if m.Pattern == "" || len(m.Pattern) > targets.MaxLogPattern || !utf8.ValidString(m.Pattern) {
		return reject(".options.pattern", "must be 1 to 1024 bytes of UTF-8")
	}
	switch options.Match {
	case "literal":
	case "regexp":
		if !LogRegexp(m.Pattern) {
			return reject(".options.pattern", "not a bounded RE2 regular expression (no backreferences or look-around; at most "+strconv.Itoa(MaxLogProgram)+" compiled instructions)")
		}
		m.Regexp = true
	default:
		return reject(".options.match", "use literal or regexp")
	}
	if options.MaxRecordBytes != 0 {
		if options.MaxRecordBytes < 1 || options.MaxRecordBytes > targets.MaxLogRecordBytes {
			return reject(".options.maxRecordBytes", "must be 1 to 65536")
		}
		m.MaxRecordBytes = options.MaxRecordBytes
	}
	switch options.Overlong {
	case "", "drop":
	case "matchPrefix":
		if m.JSONField != "" {
			return reject(".options.overlong", "a JSON field predicate never evaluates an incomplete record; use drop")
		}
		m.MatchPrefix = true
	default:
		return reject(".options.overlong", "use drop or matchPrefix")
	}
	if options.JSONField != "" {
		probe := m
		probe.MatchPrefix = false
		if !probe.Valid() {
			return reject(".options.jsonField", "a dotted path of at most 8 non-empty object keys, at most 128 bytes")
		}
	}
	if eventWindow != nil {
		var text string
		if strict(eventWindow, &text) != nil {
			return reject(".eventWindow", "invalid duration")
		}
		window, ok := policyDuration(text)
		if !ok || window%time.Second != 0 || window < targets.MinProbeWindowSeconds*time.Second || window > targets.MaxProbeWindowSeconds*time.Second {
			return reject(".eventWindow", "must be 30s to 5m in whole seconds: a shorter window could miss a record between two polls")
		}
		m.WindowSeconds = int64(window / time.Second)
	}
	if !m.Valid() {
		return reject(".options", "invalid")
	}
	out.Detector, out.Log = value.DetectorLog, &m
	return nil
}

// MaxLogProgram bounds a log regexp's compiled program (ADR-241), so a
// record's evaluation stays linear with a small constant.
const MaxLogProgram = 4096

// LogRegexp reports whether pattern is an RE2 (Perl-syntax) regular
// expression whose compiled program has at most MaxLogProgram instructions.
func LogRegexp(pattern string) bool {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return false
	}
	prog, err := syntax.Compile(re.Simplify())
	return err == nil && len(prog.Inst) <= MaxLogProgram
}

// compileResource selects the ADR-241 resource detector: one metrics API
// (metrics.k8s.io) metric of the triggering Pod compared with a threshold.
// The cgroup-only metrics of the specification (throttling, growth rate,
// PSI) need a node-local reader and are rejected with their path.
func compileResource(out *value.RestartPolicy, raw json.RawMessage) error {
	reject := func(path, reason string) error {
		return value.PolicyFieldError{Path: "spec.detectors[0].options" + path, Reason: reason}
	}
	var options struct {
		Metric, Operator, SampleInterval string
		Threshold                        float64
	}
	if strict(raw, &options) != nil {
		return reject("", "invalid")
	}
	c := targets.ResourceCondition{Metric: options.Metric, Operator: options.Operator, Threshold: options.Threshold}
	switch c.Metric {
	case targets.MetricCPUCores, targets.MetricCPUQuotaRatio, targets.MetricMemoryBytes, targets.MetricMemoryLimitRatio:
	case "cpuThrottledRatio", "memoryGrowthBytesPerSecond", "memoryPSI", "cpuPSI", "ioPSI":
		return reject(".metric", "needs the node-local cgroup reader; the metrics API provides cpuCores, cpuQuotaRatio, memoryBytes and memoryLimitRatio")
	default:
		return reject(".metric", "use cpuCores, cpuQuotaRatio, memoryBytes or memoryLimitRatio")
	}
	switch c.Operator {
	case "gt", "gte", "lt", "lte":
	default:
		return reject(".operator", "use gt, gte, lt or lte")
	}
	if !(c.Threshold >= 0 && c.Threshold <= 1e18) {
		return reject(".threshold", "must be 0 to 1e18")
	}
	interval, ok := policyDuration(options.SampleInterval)
	if !ok || interval%time.Second != 0 || interval < targets.MinResourceSampleSeconds*time.Second || interval > targets.MaxResourceSampleSeconds*time.Second {
		return reject(".sampleInterval", "must be 30s to 5m in whole seconds: the oldest metrics sample still evaluated")
	}
	c.MaxAgeSeconds = int64(interval / time.Second)
	out.Detector, out.Resource = value.DetectorResource, &c
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
	case "alert":
		err = compileAlert(&p, d.Options, d.EventWindow)
	case "log":
		err = compileLog(&p, d.Options, d.EventWindow)
	case "resource":
		err = compileResource(&p, d.Options)
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

// policyComposition names the refused part of a composed policy (ADR-243).
// Packet and syscall recordings are previewable manually but cannot be armed
// by a policy until policy-armed sources exist (S-04 increment 6).
func policyComposition(raw json.RawMessage) (string, string) {
	var c struct {
		Components []struct {
			ProfileRef struct{ Catalog, Name string }
		}
	}
	if json.Unmarshal(raw, &c) == nil {
		for i, component := range c.Components {
			if component.ProfileRef.Catalog == "builtin" && (component.ProfileRef.Name == "network-connections" || component.ProfileRef.Name == "syscall-activity") {
				return ".profileComposition.components[" + strconv.Itoa(i) + "].profileRef", "packet and syscall recordings cannot be armed by a policy in this release (ADR-243); preview them manually, or use recipeRef builtin-pod-status-v1"
			}
		}
	}
	return ".profileComposition", "capture profile compositions are not available in policies in this release (ADR-243); use recipeRef builtin-pod-status-v1"
}
