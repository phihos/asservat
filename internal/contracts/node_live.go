package contracts

import (
	"encoding/json"
	"io"
)

const NodeLivePath = "/internal/v1/node/live"
const NodeLiveFormat = "node-live/v1"

type NodeLiveRow struct {
	Row   json.RawMessage `json:"row"`
	Nanos int64           `json:"nanos"`
	Clock string          `json:"clock"`
}
type NodeLiveResult struct {
	Manual      *NodeManualLiveObservation `json:"manual,omitempty"`
	Format      string                     `json:"format"`
	Epoch       string                     `json:"epoch"`
	WorkID      string                     `json:"workID"`
	SourceID    string                     `json:"sourceID"`
	Fence       string                     `json:"fence"`
	BootID      string                     `json:"bootID"`
	Clock       string                     `json:"clock"`
	Sample      int64                      `json:"sample"`
	Rows        []NodeLiveRow              `json:"rows"`
	Sequence    uint64                     `json:"sequence"`
	Lost        uint64                     `json:"lost"`
	ClockLost   uint64                     `json:"clockLost,omitempty"`
	Unsupported uint64                     `json:"unsupported,omitempty"`
	SensorLost  uint64                     `json:"sensorLost,omitempty"`
	Dropped     int                        `json:"dropped"`
	Examined    int                        `json:"examined"`
	Bytes       int64                      `json:"bytes"`
}

func DecodeNodeLiveResult(r io.Reader) (NodeLiveResult, error) {
	return nodeDecode[NodeLiveResult](r, 24<<10)
}
