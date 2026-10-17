package contracts

import (
	"bytes"
	"testing"
)

func TestOwnerOperationWireExactClosedV2(t *testing.T) {
	v := OwnerObservationOperationReply{Format: OwnerObservationOperationFormat, Ordinal: 4, Final: true, Configuration: APIContextRevision{Generation: (1 << 60) - 1}}
	raw, err := EncodeOwnerObservationOperationReply(v)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("1152921504606846975")) {
		t.Fatal("integer rounded")
	}
	decoded, err := DecodeOwnerObservationOperationReply(raw)
	if err != nil || decoded != v {
		t.Fatal("codec parity", err)
	}
	again, err := EncodeOwnerObservationOperationReply(decoded)
	if err != nil || !bytes.Equal(raw, again) {
		t.Fatal("non-deterministic bytes")
	}
	for _, b := range [][]byte{append(append([]byte{}, raw...), []byte("{}")...), bytes.Replace(raw, []byte(`"ordinal":4`), []byte(`"ordinal":4,"ordinal":4`), 1), bytes.Replace(raw, []byte(`"ordinal":4`), []byte(`"ordinal":4.5`), 1), bytes.Replace(raw, []byte(`"ordinal":4`), []byte(`"extra":false,"ordinal":4`), 1), bytes.Replace(raw, []byte("1152921504606846975"), []byte("9223372036854775808"), 1)} {
		if _, err := DecodeOwnerObservationOperationReply(b); err == nil {
			t.Fatal("malformed body accepted")
		}
	}
	p := ClusterObservationOperationProbe{Format: ClusterObservationOperationExchangeFormat, Ordinal: 4, Owner: v}
	encoded, err := EncodeClusterObservationOperationProbe(p)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeClusterObservationOperationProbe(encoded)
	if err != nil || restored != p {
		t.Fatal("probe parity", err)
	}
}
