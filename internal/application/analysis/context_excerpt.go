package analysis

import (
	"encoding/json"
	"strconv"
	"time"

	value "asservat.local/asservat/internal/domain/analysis"
)

// FormatContextExcerpt renders only the fixed approved DTO. It confers no read
// authority; canonical-envelope validation, audit and final disclosure checks
// remain mandatory before either browser or MCP receives these transient lines.
func FormatContextExcerpt(p value.PodStatusProjection, selection value.LineSelection) (value.ContextExcerpt, error) {
	if !p.Valid() || !selection.Valid() {
		return value.ContextExcerpt{}, value.ErrInvalid
	}
	quote := func(s string) string {
		b, _ := json.Marshal(s) // valid UTF-8 strings only; no unsupported value types.
		quoted := string(b)
		clear(b)
		return quoted
	}
	lines := [14]string{
		"format: " + quote(p.Format),
		"namespaceUID: " + quote(p.NamespaceUID),
		"podUID: " + quote(p.PodUID),
		"resourceVersion: " + quote(p.ResourceVersion),
		"observedAt: " + quote(p.ObservedAt.UTC().Format(time.RFC3339Nano)),
		"phase: " + quote(p.Phase),
		"ready: " + quote(p.Ready),
		"initialized: " + quote(p.Initialized),
		"scheduled: " + quote(p.Scheduled),
		"runtimeInstances: " + strconv.Itoa(p.RuntimeInstances),
		"running: " + strconv.Itoa(p.Running),
		"waiting: " + strconv.Itoa(p.Waiting),
		"terminated: " + strconv.Itoa(p.Terminated),
		"restarts: " + strconv.FormatInt(p.Restarts, 10),
	}
	start := min(selection.LineStart-1, len(lines))
	end := min(start+selection.MaxLines, len(lines))
	out := value.ContextExcerpt{LogicalPath: value.ContextLogicalPath, LineStart: selection.LineStart, Lines: append([]string{}, lines[start:end]...)}
	encoded, err := json.Marshal(out)
	tooLarge := len(encoded) > value.ContextResultBytes
	clear(encoded)
	if err != nil || tooLarge {
		return value.ContextExcerpt{}, value.ErrInvalid
	}
	return out, nil
}
