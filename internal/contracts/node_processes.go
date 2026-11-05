package contracts

import (
	"io"
	"time"
)

const NodeProcessesFormat = "asservat-node-processes/v1"
const NodeProcessesPath = "/internal/v1/node/processes"
const NodeProcessesContentType = "application/vnd.asservat.node-processes"

type NodeProcessCapture struct {
	CaptureID         string    `json:"captureID"`
	CollectorEpoch    string    `json:"collectorEpoch"`
	ExpectationDigest string    `json:"expectationDigest"`
	Namespace         string    `json:"namespace"`
	NamespaceUID      string    `json:"namespaceUID"`
	PodName           string    `json:"podName"`
	PodUID            string    `json:"podUID"`
	ControllerUID     string    `json:"controllerUID,omitempty"`
	NodeName          string    `json:"nodeName"`
	NodeUID           string    `json:"nodeUID"`
	BootID            string    `json:"bootID"`
	Mode              string    `json:"mode"`
	NativeLimit       int64     `json:"nativeLimit"`
	NotBefore         time.Time `json:"notBefore"`
	Deadline          time.Time `json:"deadline"`
}

type NodeProcessResult struct {
	Format            string    `json:"format"`
	Epoch             string    `json:"epoch"`
	WorkID            string    `json:"workID"`
	CaptureID         string    `json:"captureID"`
	ExpectationDigest string    `json:"expectationDigest"`
	PodUID            string    `json:"podUID"`
	NodeUID           string    `json:"nodeUID"`
	BootID            string    `json:"bootID"`
	StartedAt         time.Time `json:"startedAt"`
	CompletedAt       time.Time `json:"completedAt"`
	NativeBytes       int64     `json:"nativeBytes"`
	Failure           string    `json:"failure,omitempty"`
}

func DecodeNodeProcessResult(r io.Reader) (NodeProcessResult, error) {
	return nodeDecode[NodeProcessResult](r, NodeCaptureMaxHeader)
}
