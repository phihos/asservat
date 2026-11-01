package contracts

import "encoding/json"

// CaptureComposition is the shared capture-composition/v1 wire shape for
// manual previews and policy sources. It makes no authority decision.
type CaptureComposition struct {
	Components []struct {
		ID         string `json:"id"`
		ProfileRef struct {
			Catalog string `json:"catalog"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"profileRef"`
		Overrides []struct {
			ActionID string          `json:"actionID"`
			Field    string          `json:"field"`
			Value    json.RawMessage `json:"value"`
		} `json:"overrides"`
	} `json:"components"`
	MaxTotalBytes int64  `json:"maxTotalBytes"`
	MaxDuration   string `json:"maxDuration"`
}

type CaptureRing struct {
	MaxAge            string `json:"maxAge"`
	MaxBytes          int64  `json:"maxBytes"`
	SegmentBytes      int64  `json:"segmentBytes"`
	MaxSegments       int    `json:"maxSegments"`
	Medium            string `json:"medium"`
	StorageProfileRef string `json:"storageProfileRef"`
}
