package capture

import (
	value "asservat.local/asservat/internal/domain/capture"
	"asservat.local/asservat/internal/domain/planning"
	"time"
)

type RecordingSavePreviewMetadata struct {
	Assessments    []RecordingSaveActionAssessment
	Windows        []RecordingSaveWindow
	Selected       []RecordingRow
	Before         time.Duration
	IncidentPodCap int
}

// Incident Pod selection is separate from all-authorized source observation.
// The grouped backend admits at most16 distinct source windows per Save.
// IncidentPodCap is the most pods one recording save of p may select.
func IncidentPodCap(p value.RestartPolicy) int { return recordingSaveIncidentPodCap(p) }

func recordingSaveIncidentPodCap(p value.RestartPolicy) int {
	if !p.Valid() || p.Recorder == nil {
		return 0
	}
	if p.IncidentPods > 1 {
		return min(p.IncidentPods, value.MaxRecordingSaveGroupChildren)
	}
	return 1
}

type RecordingSaveWindow struct {
	Handle string
	Before time.Duration
}

type RecordingSaveActionAssessment struct {
	ActionID, PodUID string
	Assessment       planning.ContextAssessment
}
