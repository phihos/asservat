package analysis

import (
	"time"
	"unicode/utf8"

	"asservat.local/asservat/internal/domain/artifact"
	"asservat.local/asservat/internal/domain/identity"
)

// PodStatusProjection is transient evidence. Never persist it in SQL, audit
// metadata, logs or control messages. Its validity does not establish custody.
type PodStatusProjection struct {
	Format           string
	NamespaceUID     string
	PodUID           string
	ResourceVersion  string
	ObservedAt       time.Time
	Phase            string
	Ready            string
	Initialized      string
	Scheduled        string
	RuntimeInstances int
	Running          int
	Waiting          int
	Terminated       int
	Restarts         int64
}

func (p PodStatusProjection) Valid() bool {
	condition := func(s string) bool { return s == "True" || s == "False" || s == "Unknown" }
	count := func(n int) bool { return n >= 0 && n <= 64 }
	phase := p.Phase == "Pending" || p.Phase == "Running" || p.Phase == "Succeeded" || p.Phase == "Failed" || p.Phase == "Unknown"
	return p.Format == artifact.ContextFormat && identity.Text(p.NamespaceUID, 64) && identity.Text(p.PodUID, 64) &&
		len(p.ResourceVersion) > 0 && len(p.ResourceVersion) <= 128 && utf8.ValidString(p.ResourceVersion) &&
		!p.ObservedAt.IsZero() && p.ObservedAt.Year() >= 1 && p.ObservedAt.Year() <= 9999 &&
		phase && condition(p.Ready) && condition(p.Initialized) && condition(p.Scheduled) && count(p.RuntimeInstances) &&
		count(p.Running) && count(p.Waiting) && count(p.Terminated) && p.Restarts >= 0 && p.Restarts <= 137438953408
}

// ContextExcerpt is transient approved content, not a catalog descriptor or
// authority. The complete canonical envelope still needs output validation,
// audit acknowledgement and the final current-disclosure guard before writing.
type ContextExcerpt struct {
	LogicalPath string   `json:"logical_path"`
	LineStart   int      `json:"line_start"`
	Lines       []string `json:"lines"`
}
