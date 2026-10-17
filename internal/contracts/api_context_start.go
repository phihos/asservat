package contracts

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
)

const (
	APIContextWorkFormat      = "api-context-work/v1"
	APIContextExchangeFormat  = "api-context-exchange/v1"
	APIContextWorkBytes       = 8 << 10
	APIContextSignedWorkBytes = 16 << 10
)

var ErrAPIContextProtocol = errors.New("invalid API context exchange")

type APIContextOwner struct {
	InstallationID string `json:"installationId"`
	ClusterID      string `json:"clusterId"`
	IssuerEpoch    string `json:"issuerEpoch"`
	PodUID         string `json:"podUID"`
	ProcessEpoch   string `json:"processEpoch"`
}
type APIContextConnector struct {
	InstallationID string `json:"installationId"`
	ClusterID      string `json:"clusterId"`
	IssuerEpoch    string `json:"issuerEpoch"`
	PeerID         string `json:"peerId"`
	PodUID         string `json:"podUID"`
	ProcessEpoch   string `json:"processEpoch"`
	LeafDigest     string `json:"leafDigest"`
}
type APIContextExecutor struct {
	NamespaceUID  string `json:"namespaceUID"`
	AccountUID    string `json:"accountUID"`
	PodUID        string `json:"podUID"`
	ProcessEpoch  string `json:"processEpoch"`
	StartupDigest string `json:"startupDigest"`
	ImageDigest   string `json:"imageDigest"`
}
type APIContextChannel struct {
	RootID     string              `json:"rootId"`
	ExchangeID string              `json:"exchangeId"`
	Challenge  string              `json:"challenge"`
	Hub        APIContextOwner     `json:"hub"`
	Connector  APIContextConnector `json:"connector"`
	Executor   APIContextExecutor  `json:"executor"`
}
type APIContextActor struct {
	Issuer   string `json:"issuer"`
	Subject  string `json:"subject"`
	ClientID string `json:"clientId"`
	Kind     string `json:"kind"`
}
type APIContextRevision struct {
	UID        string `json:"uid"`
	Generation int64  `json:"generation"`
	Digest     string `json:"digest"`
}
type APIContextTarget struct {
	ClusterID    string `json:"clusterId"`
	NamespaceUID string `json:"namespaceUID"`
	WorkloadUID  string `json:"workloadUID"`
	PodUID       string `json:"podUID"`
}
type APIContextWork struct {
	Format            string             `json:"format"`
	Purpose           string             `json:"purpose"`
	ExecutionClass    string             `json:"executionClass"`
	ActionID          string             `json:"actionId"`
	NativeBytes       int64              `json:"nativeBytes"`
	Channel           APIContextChannel  `json:"channel"`
	CaptureID         string             `json:"captureId"`
	AttemptID         string             `json:"attemptId"`
	Actor             APIContextActor    `json:"actor"`
	Target            APIContextTarget   `json:"target"`
	ScopeDigest       string             `json:"scopeDigest"`
	ExpectationDigest string             `json:"expectationDigest"`
	IntentDigest      string             `json:"intentDigest"`
	BudgetDigest      string             `json:"budgetDigest"`
	Capability        APIContextRevision `json:"capability"`
	ProjectionDigest  string             `json:"projectionDigest"`
	IssuedAt          string             `json:"issuedAt"`
	NotAfter          string             `json:"notAfter"`
}

func canonicalAPIContext(v any, limit int) ([]byte, error) {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(v) != nil {
		return nil, ErrAPIContextProtocol
	}
	out := jsontext.Value(bytes.TrimSuffix(b.Bytes(), []byte{'\n'}))
	if out.Canonicalize() != nil || len(out) == 0 || len(out) > limit {
		clear(out)
		return nil, ErrAPIContextProtocol
	}
	return out, nil
}
func EncodeAPIContextWork(v APIContextWork) ([]byte, error) {
	return canonicalAPIContext(v, APIContextWorkBytes)
}
func DecodeAPIContextWork(b []byte) (APIContextWork, error) {
	v, e := decodeClosedRPC[APIContextWork](bytes.NewReader(b), APIContextWorkBytes)
	if e != nil {
		return APIContextWork{}, ErrAPIContextProtocol
	}
	return v, nil
}
