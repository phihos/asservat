package configuration

import "errors"

var ErrRetentionHistoryBehind = errors.New("retention watch has not reached the complete policy list")
var ErrRetentionObservationObsolete = errors.New("retention observation predates the accepted or changed source")
