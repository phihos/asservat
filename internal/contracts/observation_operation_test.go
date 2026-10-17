package contracts

import (
	"bytes"
	"testing"
)

func TestObservationOperationClosedWireExactIntegers(t *testing.T) {
	w := ConnectorObservationOperationReply{Format: ConnectorObservationOperationFormat, Request: ObservationOperationRequest{Format: OwnerObservationOperationFormat, RootID: "root", ID: "request", Challenge: "challenge", RequestedAt: "2026-10-13T12:00:00Z", NotAfter: "2026-10-13T12:00:05Z"}, Ordinal: 4, BracketID: "bracket", Configuration: APIContextRevision{UID: "source", Generation: 1 << 60, Digest: "digest"}, BackingRevision: (1 << 60) - 1, Final: true}
	body, err := EncodeConnectorObservationOperationReply(w)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"generation":1152921504606846976`)) || !bytes.Contains(body, []byte(`"backingRevision":1152921504606846975`)) {
		t.Fatal("integer identity changed")
	}
	got, err := DecodeConnectorObservationOperationReply(body)
	if err != nil || got != w {
		t.Fatal("wire roundtrip", err)
	}
	again, err := EncodeConnectorObservationOperationReply(got)
	if err != nil || !bytes.Equal(again, body) {
		t.Fatal("decoded exact values changed deterministic bytes", err)
	}
	for name, bad := range map[string][]byte{
		"unknown":   bytes.Replace(body, []byte(`"format":`), []byte(`"extra":1,"format":`), 1),
		"duplicate": bytes.Replace(body, []byte(`"ordinal":4`), []byte(`"ordinal":4,"ordinal":4`), 1),
		"overflow":  bytes.Replace(body, []byte(`1152921504606846975`), []byte(`9223372036854775808`), 1),
		"fraction":  bytes.Replace(body, []byte(`1152921504606846975`), []byte(`1.5`), 1),
		"too-large": bytes.Repeat([]byte(" "), ObservationOperationBytes+1),
		"trailing":  append(bytes.Clone(body), []byte("{}")...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeConnectorObservationOperationReply(bad); err == nil {
				t.Fatal("invalid closed wire accepted")
			}
		})
	}
	if _, err := DecodeConnectorObservationReply(body); err == nil {
		t.Fatal("v1 decoder accepted v2 native phase envelope")
	}
}
