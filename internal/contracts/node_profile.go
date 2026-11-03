package contracts

import (
	"io"
	"time"
)

const (
	NodeProfileCaptureFormat      = "asservat-node-profile/v1"
	NodeProfileCapturePath        = "/internal/v1/node/profile"
	NodeProfileCaptureContentType = "application/vnd.asservat.node-profile"
)

type NodeProfileCapture struct {
	CaptureID         string    `json:"captureID"`
	ClusterID         string    `json:"clusterID"`
	ArtifactID        string    `json:"artifactID"`
	AttemptID         string    `json:"attemptID"`
	Namespace         string    `json:"namespace"`
	NamespaceUID      string    `json:"namespaceUID"`
	PodName           string    `json:"podName"`
	PodUID            string    `json:"podUID"`
	ControllerUID     string    `json:"controllerUID,omitempty"`
	NodeName          string    `json:"nodeName"`
	NodeUID           string    `json:"nodeUID"`
	BootID            string    `json:"bootID"`
	CollectorEpoch    string    `json:"collectorEpoch"`
	ExpectationDigest string    `json:"expectationDigest"`
	EndpointDigest    string    `json:"endpointDigest"`
	DefinitionDigest  string    `json:"definitionDigest"`
	SourceRef         string    `json:"sourceRef"`
	Type              string    `json:"type"`
	Mode              string    `json:"mode"`
	DurationMillis    int64     `json:"durationMillis"`
	ForceGC           bool      `json:"forceGC"`
	NativeLimit       int64     `json:"nativeLimit"`
	NotBefore         time.Time `json:"notBefore"`
	Deadline          time.Time `json:"deadline"`
	AddressMode       string    `json:"addressMode"`
	Address           string    `json:"address"`
	Port              uint16    `json:"port"`
	Host              string    `json:"host"`
}

type NodeProfileResult struct {
	Format            string    `json:"format"`
	Epoch             string    `json:"epoch"`
	WorkID            string    `json:"workID"`
	CaptureID         string    `json:"captureID"`
	ExpectationDigest string    `json:"expectationDigest"`
	EndpointDigest    string    `json:"endpointDigest"`
	NativeFormat      string    `json:"nativeFormat"`
	StartedAt         time.Time `json:"startedAt"`
	CompletedAt       time.Time `json:"completedAt"`
	MayHaveStarted    bool      `json:"mayHaveStarted"`
	ResponseComplete  bool      `json:"responseComplete"`
	NativeBytes       int64     `json:"nativeBytes"`
	Failure           string    `json:"failure,omitempty"`
}

func DecodeNodeProfileResult(r io.Reader) (NodeProfileResult, error) {
	return nodeDecode[NodeProfileResult](r, NodeCaptureMaxHeader)
}
