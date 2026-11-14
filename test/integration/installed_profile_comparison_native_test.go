package integration

import (
	"time"
)

const installedProfileComparisonQueries = 2

func installedProfileFocus() bool {
	return installedJourneyFocus() == "manual-profile" || installedJourneyFocus() == "profile-comparison"
}

type installedProfileComparisonSource struct {
	CaseID, ArtifactID, Version string
	Native                      []byte
	Expires                     time.Time
	Retirement                  func()
}

type installedComparisonReply struct{ installedJourneyEnvelope }
